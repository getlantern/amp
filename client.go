// Package amp implements an AMP client for communicating with an AMP broker.
package amp

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

type Client interface {
	Exchange([]byte) ([]byte, error)
	RoundTripper() (http.RoundTripper, error)
}

type client struct {
	brokerURL        *url.URL
	cacheURL         *url.URL
	fronts           []string
	transport        http.RoundTripper
	maxNumberOfBytes int64
	publicKey        *rsa.PublicKey
}

var errUnexpectedBrokerError = errors.New("unexpected broker error")

// NewClient creates a new AMP client that can communicate with an AMP broker.
// If the maxNumberOfBytes is set to 0, it defaults to 100000 bytes.
func NewClient(brokerURL, cacheURL *url.URL, fronts []string, transport http.RoundTripper, maxNumberOfBytes int64, publicKey *rsa.PublicKey) Client {
	//Maximum number of bytes to be read from an HTTP response
	if maxNumberOfBytes == 0 {
		maxNumberOfBytes = 100000
	}
	return &client{
		brokerURL:        brokerURL,
		cacheURL:         cacheURL,
		fronts:           fronts,
		transport:        transport,
		maxNumberOfBytes: maxNumberOfBytes,
		publicKey:        publicKey,
	}
}

// Exchange sends an encoded payload to the AMP broker and returns the response.
func (c *client) Exchange(encodedPayload []byte) ([]byte, error) {
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
		slog.Debug("Selected front domain", slog.String("front", front))
		req.Host = req.URL.Host
		req.URL.Host = front
	}

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// A non-200 status indicates an error:
		// * If the broker returns a page with invalid AMP, then the AMP
		//   cache returns a redirect that would bypass the cache.
		// * If the broker returns a 5xx status, the AMP cache
		//   translates it to a 404.
		// https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/#redirect-%26-error-handling
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
		return nil, errUnexpectedBrokerError
	}

	lr := io.LimitReader(resp.Body, c.maxNumberOfBytes+1)
	dec, err := amp.NewArmorDecoder(lr)
	if err != nil {
		return nil, err
	}
	response, err := io.ReadAll(dec)
	if err != nil {
		return nil, err
	}
	if lr.(*io.LimitedReader).N == 0 {
		// We hit readLimit while decoding AMP armor, that's an error.
		return nil, io.ErrUnexpectedEOF
	}

	return response, err
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

// BrokerResponse is a struct that represents an HTTP response.
type BrokerResponse struct {
	StatusCode    int         `json:"status_code"`
	StatusText    string      `json:"status_text"`
	ContentLength int64       `json:"content_length"`
	Headers       http.Header `json:"headers"`
	Body          []byte      `json:"body"`
}

// RoundTrip implements the http.RoundTripper interface for the AMP client.
// It encodes the HTTP request, encrypts it with the RSA public key,
// sends it to the AMP broker, and decodes the response back into an HTTP response.
func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	payload, err := encodeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt request: %w", err)
	}

	encryptedPayload, err := r.encryptWithRSAPublicKey(payload)
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt request: %w", err)
	}

	response, err := r.Exchange(encryptedPayload)
	if err != nil {
		return nil, err
	}

	return decodeResponse(response)
}

func encodeRequest(req *http.Request) ([]byte, error) {
	var message ClientRequest
	message.Method = req.Method
	message.URL = req.URL.String()
	message.Host = req.Host
	if req.URL != nil {
		message.Host = req.URL.Host
	}
	message.Headers = req.Header
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

func decodeResponse(encodedResponse []byte) (*http.Response, error) {
	var response BrokerResponse
	if err := json.Unmarshal(encodedResponse, &response); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal response: %w", err)
	}

	resp := &http.Response{
		Status:        response.StatusText,
		StatusCode:    response.StatusCode,
		Header:        response.Headers,
		ContentLength: int64(len(response.Body)),
		Body:          io.NopCloser(bytes.NewBuffer(response.Body)),
	}

	return resp, nil
}

func (c *client) encryptWithRSAPublicKey(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), crand.Reader, c.publicKey, data, nil)
}

// RoundTripper returns an http.RoundTripper that can be used to send HTTP requests
func (c *client) RoundTripper() (http.RoundTripper, error) {
	return &roundTripper{c}, nil
}
