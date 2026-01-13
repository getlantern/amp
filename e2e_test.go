//go:build integration
// +build integration

package amp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	config := Config{
		BrokerURL: "https://amp.iantem.io",
		CacheURL:  "https://cdn.ampproject.org",
		Fronts:    []string{"gmail.com", "youtube.com", "photos.google.com"},
		PublicKey: "",
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	dial := func(network, address string) (net.Conn, error) {
		slog.Debug("dialing", slog.String("network", network), slog.String("address", address))
		return tls.Dial("tcp", fmt.Sprintf("%s:443", address), &tls.Config{
			ServerName: address,
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := NewClientWithOptions(ctx, WithConfig(config), WithDialer(dial))
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://detectportal.firefox.com/success.txt", http.NoBody)
	require.NoError(t, err)

	roundTripper, err := client.RoundTripper()
	assert.NoError(t, err)

	cli := http.DefaultClient
	cli.Timeout = 60 * time.Second
	cli.Transport = roundTripper
	response, err := cli.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	t.Log(response.StatusCode)
	t.Log(string(content))
}
