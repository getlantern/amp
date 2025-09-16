package amp

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/crypto/chacha20poly1305"
)

type cryptClientConn struct {
	net.Conn
	key             []byte
	nonce           []byte
	aead            cipher.AEAD
	serverPublicKey *rsa.PublicKey
	response        io.Reader
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// NewCryptClientConn creates a new cryptConn that implements net.Conn. This connection
// is encrypted using a hybrid encryption scheme: a symmetric key is generated
// for encrypting the data with ChaCha20-Poly1305, and this key is then encrypted
// with the server's RSA public key. This connector should be used to wrap the
// ampClientConn to provide encryption.
func NewCryptClientConn(conn net.Conn, serverPublicKey *rsa.PublicKey) (*cryptClientConn, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(crand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &cryptClientConn{
		Conn:            conn,
		key:             key,
		aead:            aead,
		nonce:           nonce,
		serverPublicKey: serverPublicKey,
	}, nil
}

func (c *cryptClientConn) Read(b []byte) (int, error) {
	if c.response == nil {
		var response BrokerResponse
		if err := json.NewDecoder(c.Conn).Decode(&response); err != nil {
			return 0, fmt.Errorf("crypt client conn couldn't unmarshal response: %w", err)
		}

		nonce, err := base64.StdEncoding.DecodeString(response.Nonce)
		if err != nil {
			return 0, fmt.Errorf("couldn't decode nonce: %w", err)
		}

		encryptedHTTPResponse, err := base64.StdEncoding.DecodeString(response.Response)
		if err != nil {
			return 0, fmt.Errorf("couldn't decode response: %w", err)
		}

		decryptedResponse, err := c.aead.Open(nil, nonce, encryptedHTTPResponse, nil)
		if err != nil {
			return 0, fmt.Errorf("couldn't decrypt response: %w", err)
		}

		var httpResponse HTTPResponse
		if err := json.Unmarshal(decryptedResponse, &httpResponse); err != nil {
			return 0, fmt.Errorf("couldn't unmarshal HTTP response: %w", err)
		}

		resp := &http.Response{
			Status:        httpResponse.StatusText,
			StatusCode:    httpResponse.StatusCode,
			Header:        httpResponse.Headers,
			ContentLength: int64(len(httpResponse.Body)),
			Body:          io.NopCloser(bytes.NewBuffer(httpResponse.Body)),
		}

		reader, writer := io.Pipe()
		c.response = reader
		go func() {
			if err := resp.Write(writer); err != nil {
				slog.Error("couldn't write HTTP response to pipe", slog.Any("error", err))
			}
		}()
	}

	return c.response.Read(b)
}

func (c *cryptClientConn) Write(b []byte) (int, error) {
	payloadCipher := c.aead.Seal(nil, c.nonce, b, nil)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), crand.Reader, c.serverPublicKey, c.key, nil)
	if err != nil {
		return 0, fmt.Errorf("couldn't encrypt key: %w", err)
	}

	encodedPayload, err := json.Marshal(AMPRequest{
		ClientRequestEncoded: base64.StdEncoding.EncodeToString(payloadCipher),
		Key:                  base64.StdEncoding.EncodeToString(encryptedKey),
		Nonce:                base64.StdEncoding.EncodeToString(c.nonce),
	})
	if err != nil {
		return 0, fmt.Errorf("couldn't marshal AMP request: %w", err)
	}

	return c.Conn.Write(encodedPayload)
}
