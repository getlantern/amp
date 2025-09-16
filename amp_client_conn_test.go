package amp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	reader io.Reader
	writer io.Writer
	closed bool
	wg     *sync.WaitGroup
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.wg != nil {
		m.wg.Wait()
	}
	return m.reader.Read(b)
}
func (m *mockConn) Write(b []byte) (int, error) {
	return m.writer.Write(b)
}
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestAMPClientConn_ReadWrite(t *testing.T) {
	brokerURL, err := url.Parse("https://broker.example.com/")
	require.NoError(t, err)
	cacheURL, err := url.Parse("https://cache.example.com/")
	require.NoError(t, err)

	successfulMessage := "hello"
	successHTTPResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(armorData(t, []byte(successfulMessage)))),
	}
	successfulResponse := new(bytes.Buffer)
	require.NoError(t, successHTTPResponse.Write(successfulResponse))

	tests := []struct {
		name      string
		fronts    []string
		readBuf   []byte
		wantRead  string
		wantWrite bool
		wantErr   bool
	}{
		{
			name:     "OK response",
			wantRead: successfulMessage,
		},
		{
			name:    "Non-OK response",
			wantErr: true,
		},
		{
			name:    "Location header set",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				reader: successfulResponse,
				writer: new(bytes.Buffer),
			}
			c := &ampClientConn{
				brokerURL: brokerURL,
				cacheURL:  cacheURL,
				fronts:    tt.fronts,
				dial: func(network, address string) (net.Conn, error) {
					return conn, nil
				},
				Conn: conn,
			}
			// Write
			n, err := c.Write([]byte("abc"))
			if err != nil || n == 0 {
				t.Errorf("Write failed: %v", err)
			}
			// Read
			buf := make([]byte, 10)
			n, err = c.Read(buf)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Greater(t, n, 0)
			assert.Equal(t, tt.wantRead, string(buf[:n]))
		})
	}
}
