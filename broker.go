package amp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

type broker struct {
	requestTimeout time.Duration
	privateKey     *rsa.PrivateKey
	client         *http.Client
}

type Broker interface {
	Handle(http.ResponseWriter, *http.Request)
}

// NewBroker creates a new Broker instance with the specified client timeout,
// private key for decrypting client requests, and an optional HTTP client.
func NewBroker(clientTimeout time.Duration, privateKey *rsa.PrivateKey, client *http.Client) Broker {
	if client == nil {
		client = &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   60 * time.Second,
		}
	}
	return &broker{
		requestTimeout: clientTimeout,
		privateKey:     privateKey,
		client:         client,
	}
}

// Handle processes incoming HTTP requests for the AMP client offers.
func (b broker) Handle(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), b.requestTimeout*time.Second)
	defer cancel()

	// The encoded client poll message immediately follows the /amp/client/
	// path prefix, so this function unfortunately needs to be aware of and
	// remove its own routing prefix.
	path := strings.TrimPrefix(r.URL.Path, "/amp/client/")
	if path == r.URL.Path {
		// The path didn't start with the expected prefix. This probably
		// indicates an internal bug.
		slog.ErrorContext(ctx, "unexpected prefix in request path", slog.String("path", r.URL.Path))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	clientRequest, err := b.getPayload(path)
	if err != nil {
		slog.WarnContext(ctx, "failed to read payload", slog.Any("error", err), slog.String("path", path))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(ctx, clientRequest.Method, clientRequest.URL, bytes.NewReader(clientRequest.Body))
	if err != nil {
		slog.ErrorContext(ctx, "error creating request", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.Header = clientRequest.Headers
	serverResponse, err := b.client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "error making request to server", slog.Any("error", err), slog.String("url", clientRequest.URL))
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	encodedResponse, err := encodeResponse(serverResponse)
	if err != nil {
		slog.ErrorContext(ctx, "error encoding response", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	// Attempt to hint to an AMP cache not to waste resources caching this
	// document. "The Google AMP Cache considers any document fresh for at
	// least 15 seconds."
	// https://developers.google.com/amp/cache/overview#google-amp-cache-updates
	w.Header().Set("Cache-Control", "max-age=15")
	w.WriteHeader(http.StatusOK)

	enc, err := amp.NewArmorEncoder(w)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create armor encoder", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer enc.Close()

	if _, err := enc.Write(encodedResponse); err != nil {
		slog.ErrorContext(ctx, "failed to write encoded response", slog.Any("error", err))
		return
	}
}

func (b *broker) getPayload(path string) (ClientRequest, error) {
	encryptedPayload, err := amp.DecodePath(path)
	if err != nil {
		return ClientRequest{}, fmt.Errorf("failed to decode amp path: %w", err)
	}

	encodedPayload, err := rsa.DecryptPKCS1v15(nil, b.privateKey, encryptedPayload)
	if err != nil {
		return ClientRequest{}, fmt.Errorf("faled to decrypt payload: %w", err)
	}

	var message ClientRequest
	if err := json.Unmarshal(encodedPayload, &message); err != nil {
		return ClientRequest{}, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	return message, nil
}

func encodeResponse(serverResponse *http.Response) ([]byte, error) {
	var response BrokerResponse
	response.StatusCode = serverResponse.StatusCode
	response.StatusText = serverResponse.Status
	response.Headers = serverResponse.Header
	response.ContentLength = serverResponse.ContentLength
	if serverResponse.Body != nil {
		defer serverResponse.Body.Close()

		var err error
		response.Body, err = io.ReadAll(serverResponse.Body)
		if err != nil {
			return nil, fmt.Errorf("could not read response body: %w", err)
		}
	}

	encodedResponse, err := json.Marshal(&response)
	if err != nil {
		return nil, fmt.Errorf("could not marshal response: %w", err)
	}
	return encodedResponse, nil
}
