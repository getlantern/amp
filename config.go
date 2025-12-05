package amp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/getlantern/keepcurrent"
	"github.com/goccy/go-yaml"
)

// Config contains the parameters required for sending requests with the amp client
type Config struct {
	BrokerURL string   `yaml:"brokerURL"`
	CacheURL  string   `yaml:"cacheURL"`
	Fronts    []string `yaml:"fronts"`
	PublicKey string   `yaml:"publicKey"`
}

// NewClientWithConfig builds a new amp client with the provided configuration.
// It also supports options for retrieving the latest configuration given a poll
// interval, http client and config url address until context is canceled.
func NewClientWithConfig(ctx context.Context, cfg Config, opts ...Option) (Client, error) {
	cli := &client{
		dial:         (&net.Dialer{}).Dial,
		pollInterval: 12 * time.Hour,
	}
	if err := cli.parseConfig(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	for _, opt := range opts {
		if err := opt(cli); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	cli.keepCurrent(ctx)
	return cli, nil
}

func parseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return rsaPub, nil
}

// Option is a function type used to configure the amp client instance.
type Option func(*client) error

// WithHTTPClient set the HTTP client used during the configuration
// synchronization.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *client) error {
		c.httpClient = httpClient
		return nil
	}
}

// WithPollInterval set the poll interval for fetching new configurations.
// By default it's set as 12h
func WithPollInterval(t time.Duration) Option {
	return func(c *client) error {
		c.pollInterval = t
		return nil
	}
}

// WithConfigURL sets the URL to retrieve the latest configuration
func WithConfigURL(configURL string) Option {
	return func(c *client) error {
		c.configURL = configURL
		return nil
	}
}

// WithDialer sets the network dialer function used for creating connections.
func WithDialer(dial dialFunc) Option {
	return func(c *client) error {
		c.dial = dial
		return nil
	}
}

func processYaml(gzippedYaml []byte) (Config, error) {
	r, gzipErr := gzip.NewReader(bytes.NewReader(gzippedYaml))
	if gzipErr != nil {
		return Config{}, fmt.Errorf("failed to create gzip reader: %w", gzipErr)
	}
	defer r.Close()
	yml, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read gzipped file: %w", err)
	}
	path, err := yaml.PathString("$.amp")
	if err != nil {
		return Config{}, fmt.Errorf("failed to create config path: %w", err)
	}
	var cfg Config
	if err = path.Read(bytes.NewReader(yml), &cfg); err != nil {
		return Config{}, fmt.Errorf("failed to read config: %w", err)
	}

	return cfg, nil
}

func configValidator(data []byte) error {
	if _, err := processYaml(data); err != nil {
		return err
	}
	return nil
}

func (c *client) keepCurrent(ctx context.Context) {
	if c.configURL == "" {
		slog.Debug("No config URL provided -- not updating amp configuration")
		return
	}

	slog.Debug("Updating amp configuration", slog.String("url", c.configURL))
	source := keepcurrent.FromWebWithClient(c.configURL, c.httpClient)
	chDB := make(chan []byte)
	closeChan := sync.OnceFunc(func() {
		close(chDB)
	})
	dest := keepcurrent.ToChannel(chDB)

	runner := keepcurrent.NewWithValidator(
		configValidator,
		source,
		dest,
	)

	go func() {
		for {
			select {
			case <-ctx.Done():
				closeChan()
				return
			case data, ok := <-chDB:
				if !ok {
					return
				}
				slog.Debug("received new amp configuration")
				if err := c.onNewConfig(data); err != nil {
					slog.Error("failed to apply new amp configuration", "error", err)
				}
			}
		}
	}()

	runner.Start(c.pollInterval)
}

func (c *client) parseConfig(cfg Config) error {
	brokerURL, err := url.Parse(cfg.BrokerURL)
	if err != nil {
		return fmt.Errorf("failed to parse broker url: %w", err)
	}

	cacheURL, err := url.Parse(cfg.CacheURL)
	if err != nil {
		return fmt.Errorf("failed to parse cache url: %w", err)
	}

	publicKey, err := parseRSAPublicKeyFromPEM([]byte(cfg.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	c.updateMutex.Lock()
	defer c.updateMutex.Unlock()
	c.brokerURL = brokerURL
	c.cacheURL = cacheURL
	c.serverPublicKey = publicKey
	c.fronts = cfg.Fronts
	return nil
}

func (c *client) onNewConfig(gzippedYML []byte) error {
	cfg, err := processYaml(gzippedYML)
	if err != nil {
		return fmt.Errorf("failed to process amp config: %w", err)
	}

	return c.parseConfig(cfg)
}
