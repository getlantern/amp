package amp

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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

	ampRequest, err := b.getPayload(path)
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

	encodedResponse, err := encodeResponse(ampRequest.PublicKey, serverResponse)
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

func (b *broker) getPayload(path string) (AMPRequest, error) {
	ampRequestPayload, err := amp.DecodePath(path)
	if err != nil {
		return AMPRequest{}, fmt.Errorf("failed to decode amp path: %w", err)
	}

	var ampRequest AMPRequest
	if err := json.Unmarshal(ampRequestPayload, &ampRequest); err != nil {
		return AMPRequest{}, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	ampRequest.PublicKey, err = pemToPublicKey(ampRequest.PublicKeyPEM)
	if err != nil {
		return AMPRequest{}, fmt.Errorf("failed to parse client public key: %w", err)
	}

	encryptedClientRequest, err := base64.StdEncoding.DecodeString(ampRequest.ClientRequestEncoded)
	if err != nil {
		return AMPRequest{}, err
	}

	jsonClientRequest, err := rsa.DecryptOAEP(sha256.New(), nil, b.privateKey, encryptedClientRequest, nil)
	if err != nil {
		return AMPRequest{}, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	if err := json.Unmarshal(jsonClientRequest, &ampRequest.ClientRequest); err != nil {
		return AMPRequest{}, err
	}

	return ampRequest, nil
}

func pemToPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func encodeResponse(clientPublicKey *rsa.PublicKey, serverResponse *http.Response) ([]byte, error) {
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

	jsonResponse, err := json.Marshal(&response)
	if err != nil {
		return nil, fmt.Errorf("could not marshal response: %w", err)
	}

	encryptedResponse, err := rsa.EncryptOAEP(sha256.New(), crand.Reader, clientPublicKey, jsonResponse, nil)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt response: %w", err)
	}
	return encryptedResponse, nil
}
