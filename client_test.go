package amp

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

// mockTransport implements http.RoundTripper for testing.
type mockTransport struct {
	resp *http.Response
	err  error
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.resp, m.err
}

// armorData is valid AMP armor for testing. Replace with actual valid data if needed.
func armorData(t *testing.T, data []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	encoder, err := amp.NewArmorEncoder(buf)
	require.NoError(t, err)
	_, err = encoder.Write(data)
	require.NoError(t, err)
	require.NoError(t, encoder.Close())
	return buf.Bytes()
}

func TestClient_Exchange(t *testing.T) {
	brokerURL, _ := url.Parse("https://broker.example")
	validResponse := `response`
	ampResponse := armorData(t, []byte(validResponse))
	tests := []struct {
		name      string
		transport http.RoundTripper
		payload   []byte
		want      []byte
		wantErr   bool
	}{
		{
			name: "success",
			transport: &mockTransport{
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(ampResponse)),
				},
			},
			payload: []byte("payload"),
			want:    []byte("response"),
			wantErr: false,
		},
		{
			name: "transport error",
			transport: &mockTransport{
				err: errors.New("fail"),
			},
			payload: []byte("payload"),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := &client{
				brokerURL:        brokerURL,
				transport:        tt.transport,
				maxNumberOfBytes: 100000,
			}
			got, err := c.Exchange(tt.payload)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNewClientDefaults(t *testing.T) {
	brokerURL, _ := url.Parse("https://broker.example")
	client := NewClient(brokerURL, nil, nil, http.DefaultTransport, 0, &rsa.PublicKey{}).(*client)
	assert.Equal(t, int64(100000), client.maxNumberOfBytes)
}

// encodeBrokerResponse encodes a BrokerResponse as JSON for the test.
func encodeBrokerResponse(t *testing.T, br BrokerResponse) []byte {
	t.Helper()
	b, err := json.Marshal(br)
	require.NoError(t, err)
	return armorData(t, b)
}

func generateTestKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	// Generate a test RSA public key.
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	require.NoError(t, err)
	return &priv.PublicKey
}

func TestRoundTripper_RoundTrip(t *testing.T) {
	brokerURL, err := url.Parse("https://broker.example")
	require.NoError(t, err)
	successfulResponse := encodeBrokerResponse(t, BrokerResponse{
		StatusCode: http.StatusOK,
		StatusText: http.StatusText(http.StatusOK),
		Headers:    http.Header{"X-Test": []string{"foo"}},
		Body:       []byte("hello"),
	})
	defaultRequest, err := http.NewRequest("GET", "https://broker.example", http.NoBody)
	require.NoError(t, err)
	tests := []struct {
		name      string
		transport http.RoundTripper
		request   *http.Request
		want      []byte
		wantErr   bool
		errMsg    string
	}{
		{
			name: "success",
			transport: &mockTransport{
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(successfulResponse)),
					Header:     make(http.Header),
				},
			},
			request: defaultRequest,
			want:    []byte("hello"),
			wantErr: false,
		},
		{
			name: "transport error",
			transport: &mockTransport{
				err: errors.New("fail"),
			},
			request: defaultRequest,
			want:    nil,
			wantErr: true,
			errMsg:  "fail",
		},
		{
			name: "amp returns EOF when the response doesn't contain the expected AMP armor",
			transport: &mockTransport{
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("not-json")),
					Header:     make(http.Header),
				},
			},
			request: defaultRequest,
			want:    nil,
			wantErr: true,
			errMsg:  "EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(brokerURL, nil, nil, tt.transport, 0, generateTestKey(t))
			rt, err := c.RoundTripper()
			require.NoError(t, err)
			resp, err := rt.RoundTrip(tt.request)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				body, _ := io.ReadAll(resp.Body)
				assert.Equal(t, tt.want, body)
			}
		})
	}
}
