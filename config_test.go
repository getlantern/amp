package amp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateRSAPublicKeyPEM(t *testing.T) string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubPEM)
}

func TestParseRSAPublicKeyFromPEM_Table(t *testing.T) {
	validPEM := generateRSAPublicKeyPEM(t)
	invalidPEM := "-----BEGIN PUBLIC KEY-----\ninvalidkeydata\n-----END PUBLIC KEY-----"
	noPEM := "not a pem"

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid PEM", validPEM, false},
		{"invalid PEM", invalidPEM, true},
		{"no PEM block", noPEM, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := parseRSAPublicKeyFromPEM([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, pub)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pub)
			}
		})
	}
}

func TestNewClientWithConfig_InvalidURLs(t *testing.T) {
	validPEM := generateRSAPublicKeyPEM(t)
	ctx := context.Background()
	tests := []struct {
		name      string
		cfg       Config
		expectErr bool
	}{
		{
			"invalid broker url",
			Config{BrokerURL: ":", CacheURL: "http://cache", Fronts: []string{}, PublicKey: validPEM},
			true,
		},
		{
			"invalid cache url",
			Config{BrokerURL: "http://broker", CacheURL: ":", Fronts: []string{}, PublicKey: validPEM},
			true,
		},
		{
			"invalid public key",
			Config{BrokerURL: "http://broker", CacheURL: "http://cache", Fronts: []string{}, PublicKey: "badpem"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClientWithConfig(ctx, tt.cfg)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}
