package amp

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

// mockTransport implements http.RoundTripper for testing.
type mockTransport struct {
	f    func()
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
				brokerURL: brokerURL,
				transport: tt.transport,
			}
			got, err := c.Exchange(tt.payload)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				response, err := io.ReadAll(got)
				require.NoError(t, err)
				got.Close()
				assert.Equal(t, tt.want, response)
			}
		})
	}
}

func TestNewClientDefaults(t *testing.T) {
	brokerURL, _ := url.Parse("https://broker.example")
	cli, err := NewClient(brokerURL, nil, nil, http.DefaultTransport, &rsa.PublicKey{}, nil)
	require.NoError(t, err)
	require.NotNil(t, cli)
}

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// Generate a test RSA public key.
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	require.NoError(t, err)
	return priv
}

func TestRoundTripper_RoundTrip(t *testing.T) {
	brokerURL, err := url.Parse("https://broker.example:443")
	require.NoError(t, err)
	defaultRequest, err := http.NewRequest("GET", "https://broker.example", http.NoBody)
	require.NoError(t, err)

	privateKey := generateTestKey(t)
	successfulMessage := "successful response"

	tests := []struct {
		name    string
		request *http.Request
		dial    func(network, address string) (net.Conn, error)
		want    []byte
		wantErr bool
		errMsg  string
	}{
		{
			name: "roundtrip and return a success response",
			dial: func(network, address string) (net.Conn, error) {
				// I need to read tho data written on the writeBuf so I can extract the AES key and nonce
				reader, writer := io.Pipe()
				successfulResponse := new(bytes.Buffer)
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					r, err := http.ReadRequest(bufio.NewReader(reader))
					require.NoError(t, err)
					assert.Equal(t, "GET", r.Method)

					path := strings.TrimPrefix(r.URL.Path, "/amp/client/")
					ampRequest, err := getPayload(path, privateKey)
					require.NoError(t, err)
					req, err := http.NewRequest(ampRequest.ClientRequest.Method, ampRequest.ClientRequest.URL, bytes.NewReader(ampRequest.ClientRequest.Body))
					require.NoError(t, err)

					encodedProxiedResponse, err := encodeResponse(ampRequest, &http.Response{
						Request:    req,
						Proto:      "HTTP/1.1",
						Status:     "OK",
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(successfulMessage)),
					})
					require.NoError(t, err)

					armoredResponse := new(bytes.Buffer)
					encoder, err := amp.NewArmorEncoder(armoredResponse)
					require.NoError(t, err)
					_, err = encoder.Write(encodedProxiedResponse)
					require.NoError(t, err)
					require.NoError(t, encoder.Close())

					responseHeaders := make(http.Header)
					responseHeaders.Set("Content-Type", "text/html")
					responseHeaders.Set("Cache-Control", "max-age=15")

					httpResponse := &http.Response{
						Proto:      "HTTP/1.1",
						Status:     "OK",
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(armoredResponse),
						Header:     responseHeaders,
					}
					require.NoError(t, httpResponse.Write(successfulResponse))
				}()
				return &mockConn{
					reader: successfulResponse,
					writer: writer,
					wg:     &wg,
				}, nil
			},
			request: defaultRequest,
			want:    []byte(successfulMessage),
			wantErr: false,
		},
		{
			name: "amp returns EOF when the response doesn't contain the expected AMP armor",
			dial: func(network, address string) (net.Conn, error) {
				httpResponse := &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte("invalid response"))),
				}
				responseBuf := new(bytes.Buffer)
				httpResponse.Write(responseBuf)

				return &mockConn{
					reader: responseBuf,
					writer: new(bytes.Buffer),
				}, nil
			},
			request: defaultRequest,
			want:    nil,
			wantErr: true,
			errMsg:  "EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(brokerURL, nil, nil, http.DefaultTransport, &privateKey.PublicKey, tt.dial)
			require.NoError(t, err)
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
