package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
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
}

var errUnexpectedBrokerError = errors.New("unexpected broker error")

func NewClient(brokerURL, cacheURL *url.URL, fronts []string, transport http.RoundTripper, maxNumberOfBytes int64) Client {
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
	}
}

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

	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	if len(c.fronts) != 0 {
		// Do domain fronting. Replace the domain in the URL's with a randomly
		// selected front, and store the original domain the HTTP Host header.
		front := c.fronts[rand.Intn(len(c.fronts))]
		log.Println("Front domain:", front)
		req.Host = req.URL.Host
		req.URL.Host = front
	}

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("AMP cache rendezvous response: %s", resp.Status)
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

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// TODO: if theer's a request payload, encode
	response, err := r.Exchange(nil)
	if err != nil {
		return nil, err
	}

	return http.ReadResponse(bufio.NewReader(bytes.NewBuffer(response)), req)
}

func (c *client) RoundTripper() (http.RoundTripper, error) {
	return &roundTripper{c}, nil
}
