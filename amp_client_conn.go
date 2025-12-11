package amp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

type ampClientConn struct {
	net.Conn
	brokerURL      *url.URL
	cacheURL       *url.URL
	req            *http.Request
	decoder        io.Reader
	responseCloser io.Closer
	front          string
}

type dialFunc func(network, address string) (net.Conn, error)

// NewAMPClientConn creates a new AMP client connection that implements net.Conn.
// This connection is not encrypted!
func NewAMPClientConn(conn net.Conn, brokerURL, cacheURL *url.URL, front string) (net.Conn, error) {
	return &ampClientConn{
		brokerURL: brokerURL,
		cacheURL:  cacheURL,
		Conn:      conn,
		front:     front,
	}, nil
}

func (c *ampClientConn) Read(b []byte) (n int, err error) {
	if c.Conn == nil {
		return 0, fmt.Errorf("connection not established, cannot read")
	}
	if c.decoder == nil {
		resp, err := http.ReadResponse(bufio.NewReader(c.Conn), c.req)
		if err != nil {
			return 0, fmt.Errorf("amp client conn failed to read HTTP response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			// A non-200 status indicates an error:
			// * If the broker returns a page with invalid AMP, then the AMP
			//   cache returns a redirect that would bypass the cache.
			// * If the broker returns a 5xx status, the AMP cache
			//   translates it to a 404.
			// https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/#redirect-%26-error-handling
			slog.Warn("received unexpected status code", slog.Int("status_code", resp.StatusCode))
			return 0, errUnexpectedBrokerError
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
			return 0, errUnexpectedBrokerError
		}

		dec, err := amp.NewArmorDecoder(resp.Body)
		if err != nil {
			return 0, fmt.Errorf("failed to create amp decoder: %w", err)
		}
		c.decoder = dec
	}

	return c.decoder.Read(b)
}

func (c *ampClientConn) Close() error {
	var err error
	if c.responseCloser != nil {
		err = c.responseCloser.Close()
	}
	if c.Conn != nil {
		err2 := c.Conn.Close()
		if err == nil {
			err = err2
		} else {
			err = errors.Join(err, err2)
		}
	}
	return err
}

func (c *ampClientConn) Write(b []byte) (n int, err error) {
	// We cannot POST a body through an AMP cache, so instead we GET and
	// encode the client poll request message into the URL.
	reqURL := c.brokerURL.ResolveReference(&url.URL{
		Path: "amp/client/" + amp.EncodePath(b),
	})

	if c.cacheURL != nil {
		// Rewrite reqURL to its AMP cache version.
		var err error
		reqURL, err = amp.CacheURL(reqURL, c.cacheURL, "c")
		if err != nil {
			return 0, fmt.Errorf("failed to rewrite request URL to AMP cache URL: %w", err)
		}
	}

	req, err := http.NewRequest("GET", reqURL.String(), http.NoBody)
	if err != nil {
		return 0, fmt.Errorf("failed to create new HTTP request: %w", err)
	}
	c.req = req

	if c.front != "" {
		c.req.Host = req.URL.Host
		c.req.URL.Host = c.front
	}

	if c.Conn == nil {
		return 0, fmt.Errorf("connection not established")
	}

	buffer := bytes.NewBuffer(nil)
	if err := c.req.Write(buffer); err != nil {
		return 0, fmt.Errorf("failed to write request on buffer: %w", err)
	}

	n, err = c.Conn.Write(buffer.Bytes())
	if err != nil {
		return n, fmt.Errorf("failed to write request to connection: %w", err)
	}

	return n, nil
}
