package amp

import (
	"bytes"
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
	t.Logf("AMP Response: %s", ampResponse)
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
	client := NewClient(brokerURL, nil, nil, http.DefaultTransport, 0).(*client)
	assert.Equal(t, int64(100000), client.maxNumberOfBytes)
}
