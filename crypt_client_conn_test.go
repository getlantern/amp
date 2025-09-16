package amp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestCryptClientConn_ReadWrite(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &priv.PublicKey

	aeadKey := make([]byte, chacha20poly1305.KeySize)
	_, err = rand.Read(aeadKey)
	require.NoError(t, err)
	aead, err := chacha20poly1305.New(aeadKey)
	require.NoError(t, err)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	tests := []struct {
		name      string
		input     []byte
		expectErr bool
	}{
		{"basic write/read", []byte("hello world"), false},
		{"empty payload", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			conn := &mockConn{writer: buf, reader: buf}

			cc, err := NewCryptClientConn(conn, pub)
			require.NoError(t, err)
			cc.key = aeadKey
			cc.aead = aead
			cc.nonce = nonce

			n, err := cc.Write(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotZero(t, n)
			}

			httpResp := HTTPResponse{
				StatusText: "200 OK",
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/plain"}},
				Body:       tt.input,
			}
			httpRespBytes, _ := json.Marshal(httpResp)
			encResp := cc.aead.Seal(nil, nonce, httpRespBytes, nil)
			brokerResp := BrokerResponse{
				Nonce:    base64.StdEncoding.EncodeToString(nonce),
				Response: base64.StdEncoding.EncodeToString(encResp),
			}
			brokerRespBytes, err := json.Marshal(brokerResp)
			require.NoError(t, err)
			buf.Reset()
			buf.Write(brokerRespBytes)

			readBuf := make([]byte, 4096)
			n, err = cc.Read(readBuf)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotZero(t, n)
			}
		})
	}
}
