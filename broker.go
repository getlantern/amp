package amp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/chacha20poly1305"
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

	ampRequest, err := getPayload(path, b.privateKey)
	if err != nil {
		slog.WarnContext(ctx, "failed to read payload", slog.Any("error", err), slog.String("path", path))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	trace.SpanFromContext(ctx).AddEvent("decoded_amp_request", trace.WithAttributes(
		attribute.String("method", ampRequest.ClientRequest.Method),
		attribute.String("url", ampRequest.ClientRequest.URL),
	))
	req, err := http.NewRequestWithContext(ctx, ampRequest.ClientRequest.Method, ampRequest.ClientRequest.URL, bytes.NewReader(ampRequest.ClientRequest.Body))
	if err != nil {
		slog.ErrorContext(ctx, "error creating request", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.Header = ampRequest.ClientRequest.Headers
	serverResponse, err := b.client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "error making request to server", slog.Any("error", err), slog.String("url", ampRequest.ClientRequest.URL))
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	encodedResponse, err := encodeResponse(ampRequest, serverResponse)
	if err != nil {
		slog.ErrorContext(ctx, "error encoding response", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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

	w.Header().Set("Content-Type", "text/html")
	// Attempt to hint to an AMP cache not to waste resources caching this
	// document. "The Google AMP Cache considers any document fresh for at
	// least 15 seconds."
	// https://developers.google.com/amp/cache/overview#google-amp-cache-updates
	w.Header().Set("Cache-Control", "max-age=15")
	w.WriteHeader(http.StatusOK)
}

func getPayload(path string, privateKey *rsa.PrivateKey) (*AMPRequest, error) {
	ampRequestPayload, err := amp.DecodePath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to decode amp path: %w", err)
	}

	var ampRequest AMPRequest
	if err := json.Unmarshal(ampRequestPayload, &ampRequest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(ampRequest.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client key: %w", err)
	}

	ampRequest.nonce, err = base64.StdEncoding.DecodeString(ampRequest.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nonce: %w", err)
	}

	encryptedClientRequest, err := base64.StdEncoding.DecodeString(ampRequest.ClientRequestEncoded)
	if err != nil {
		return nil, err
	}

	ampRequest.key, err = rsa.DecryptOAEP(sha256.New(), nil, privateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	ampRequest.aead, err = chacha20poly1305.New(ampRequest.key)
	if err != nil {
		return nil, fmt.Errorf("could not create AEAD: %w", err)
	}

	jsonClientRequest, err := ampRequest.aead.Open(nil, ampRequest.nonce, encryptedClientRequest, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt client request: %w", err)
	}
	incrementNonce(ampRequest.nonce)

	if err := json.Unmarshal(jsonClientRequest, &ampRequest.ClientRequest); err != nil {
		return nil, err
	}

	return &ampRequest, nil
}

func encodeResponse(request *AMPRequest, serverResponse *http.Response) ([]byte, error) {
	var response HTTPResponse
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

	jsonResponse, err := json.Marshal(&response)
	if err != nil {
		return nil, fmt.Errorf("could not marshal response: %w", err)
	}

	incrementNonce(request.nonce)
	encryptedResponse := request.aead.Seal(nil, request.nonce, jsonResponse, nil)
	brokerResponse := BrokerResponse{
		Response: base64.StdEncoding.EncodeToString(encryptedResponse),
		Nonce:    base64.StdEncoding.EncodeToString(request.nonce),
	}

	encodedBrokerResponse, err := json.Marshal(brokerResponse)
	if err != nil {
		return nil, fmt.Errorf("could not marshal broker response: %w", err)
	}

	return encodedBrokerResponse, nil
}
