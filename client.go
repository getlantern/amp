// Package amp implements an AMP client for communicating with an AMP broker.
package amp

import (
	"bufio"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

type Client interface {
	Exchange([]byte) (io.ReadCloser, error)
	RoundTripper() (http.RoundTripper, error)
}

type client struct {
	brokerURL       *url.URL
	cacheURL        *url.URL
	fronts          []string
	transport       http.RoundTripper
	dial            dialFunc
	serverPublicKey *rsa.PublicKey

	httpClient    *http.Client
	configURL     string
	pollInterval  time.Duration
	updateMutex   sync.Mutex
	conn          net.Conn
	selectedFront string
}

var errUnexpectedBrokerError = errors.New("unexpected broker error")

// NewClient creates a new AMP client that can communicate with an AMP broker.
// If cacheURL is non-nil, the client will use the AMP cache at that URL.
// If fronts is non-empty, the client will use domain fronting by randomly selecting one of the provided front domains.
// transport is a optional parameter since it's only used by the Exchange method (for AMP cache support but be aware! Exchange func doesn't encrypt your data!).
// The server public key must be provided for the RoundTripper method to work.
// The dialer parameter is optional and can be nil, in which case the default net.Dialer will be used.
func NewClient(brokerURL, cacheURL *url.URL, fronts []string, transport http.RoundTripper, serverPublicKey *rsa.PublicKey, dialer dialFunc) (Client, error) {
	if dialer == nil {
		dialer = (&net.Dialer{}).Dial
	}

	return &client{
		brokerURL:       brokerURL,
		cacheURL:        cacheURL,
		fronts:          fronts,
		transport:       transport,
		dial:            dialer,
		serverPublicKey: serverPublicKey,
	}, nil
}

func establishConn(dialer dialFunc, fronts []string) (net.Conn, string, error) {
	var conn net.Conn
	for _, front := range fronts {
		var err error
		conn, err = dialer("tcp", fmt.Sprintf("%s:443", front))
		if err != nil {
			slog.Warn("failed to dial to front host", slog.String("front", front), slog.Any("error", err))
			continue
		}
		return conn, front, nil
	}
	return nil, "", fmt.Errorf("couldn't establish connection")
}

// Exchange sends an encoded payload to the AMP broker and returns the response.
func (c *client) Exchange(encodedPayload []byte) (io.ReadCloser, error) {
	c.updateMutex.Lock()
	defer c.updateMutex.Unlock()
	// We cannot POST a body through an AMP cache, so instead we GET and
	// encode the client poll request message into the URL.
	reqURL := c.brokerURL.ResolveReference(&url.URL{
		Path: "amp/client/" + amp.EncodePath(encodedPayload),
	})

	if c.cacheURL != nil {
		// Rewrite reqURL to its AMP cache version.
		var err error
		reqURL, err = amp.CacheURL(reqURL, c.cacheURL, "c")
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest("GET", reqURL.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	if len(c.fronts) != 0 {
		// Do domain fronting. Replace the domain in the URL's with a randomly
		// selected front, and store the original domain the HTTP Host header.
		front := c.fronts[rand.Intn(len(c.fronts))]
		slog.Info("Selected front domain", slog.String("front", front))
		req.Host = req.URL.Host
		req.URL.Host = front
	}

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to roundtrip: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// A non-200 status indicates an error:
		// * If the broker returns a page with invalid AMP, then the AMP
		//   cache returns a redirect that would bypass the cache.
		// * If the broker returns a 5xx status, the AMP cache
		//   translates it to a 404.
		// https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/#redirect-%26-error-handling
		slog.Warn("received unexpected status code", slog.Int("status_code", resp.StatusCode))
		return nil, errUnexpectedBrokerError
	}
	if _, err := resp.Location(); err == nil {
		// The Google AMP Cache may return a "silent redirect" with
		// status 200, a Location header set, and a JavaScript redirect
		// in the body. The redirect points directly at the origin
		// server for the request (bypassing the AMP cache). We do not
		// follow redirects nor execute JavaScript, but in any case we
		// cannot extract information from this response and can only
		// treat it as an error.
		slog.Warn("location header set, returning unexpected broker error")
		return nil, errUnexpectedBrokerError
	}

	dec, err := amp.NewArmorDecoder(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create amp decoder: %w", err)
	}

	// The caller should read from the decoder (which reads from the
	// response body), but close the actual response body when done.
	return &struct {
		io.Reader
		io.Closer
	}{
		Reader: dec,
		Closer: resp.Body,
	}, nil
}

type roundTripper struct {
	*client
}

// ClientRequest is a struct that represents an HTTP request so it can
// be encoded into JSON, encrypted with the RSA public key by the client
// and decryptod/decoded by the broker
type ClientRequest struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	URL     string      `json:"url,omitempty"`
	Body    []byte      `json:"body"`
	Headers http.Header `json:"headers"`
}

type AMPRequest struct {
	ClientRequestEncoded string        `json:"p"`
	Key                  string        `json:"k"`
	Nonce                string        `json:"n"`
	ClientRequest        ClientRequest `json:"-"`
	key                  []byte        `json:"-"`
	nonce                []byte        `json:"-"`
	aead                 cipher.AEAD   `json:"-"`
}

type HTTPResponse struct {
	StatusCode    int         `json:"status_code"`
	StatusText    string      `json:"status_text"`
	ContentLength int64       `json:"content_length"`
	Headers       http.Header `json:"headers"`
	Body          []byte      `json:"body"`
}

// BrokerResponse is a struct that represents an HTTP response.
type BrokerResponse struct {
	Response string `json:"response"`
	Nonce    string `json:"nonce"`
}

// RoundTrip implements the http.RoundTripper interface for the AMP client.
// It generate a symmetric key, encrypt the encoded request, encrypt the key
// with the server public key, send it to the AMP broker and decode
// the response back into an HTTP response.
func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clientPayload, err := r.encodeClientRequest(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't encode request: %w", err)
	}
	ampConn, err := NewAMPClientConn(r.conn, r.brokerURL, r.cacheURL, r.selectedFront)
	if err != nil {
		return nil, fmt.Errorf("failed to create AMP client conn: %w", err)
	}

	encryptedConn, err := NewCryptClientConn(ampConn, r.serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypt conn: %w", err)
	}

	_, err = encryptedConn.Write(clientPayload)
	if err != nil {
		return nil, fmt.Errorf("couldn't write to crypt conn: %w", err)
	}

	return http.ReadResponse(bufio.NewReader(encryptedConn), req)
}

func (r *roundTripper) encodeClientRequest(req *http.Request) ([]byte, error) {
	message := ClientRequest{
		Method:  req.Method,
		Headers: req.Header,
		Host:    req.Host,
	}
	if req.URL != nil {
		message.Host = req.URL.Host
		message.URL = req.URL.String()
	}
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("couldn't read request body: %w", err)
		}
		req.Body.Close()
		message.Body = body
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal request: %w", err)
	}

	return payload, nil
}

// RoundTripper returns an http.RoundTripper that can be used to send HTTP requests
func (c *client) RoundTripper() (http.RoundTripper, error) {
	conn, selectedFront, err := establishConn(c.dial, c.fronts)
	if err != nil {
		return nil, err
	}
	return &roundTripper{
		client: &client{
			brokerURL:       c.brokerURL,
			cacheURL:        c.cacheURL,
			fronts:          c.fronts,
			dial:            c.dial,
			serverPublicKey: c.serverPublicKey,
			selectedFront:   selectedFront,
			conn:            conn,
		},
	}, nil
}
