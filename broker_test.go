package amp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func TestBroker_Handle_Integration(t *testing.T) {
	priv, pub := newTestKeyPair(t)
	broker := NewBroker(1, priv, nil)

	// Start test HTTP server for the broker to forward requests to
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("X-Backend", "yes")
			w.WriteHeader(200)
			w.Write([]byte("backend response"))
		case "/fail":
			w.WriteHeader(418)
			w.Write([]byte("teapot"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer backend.Close()

	// Broker HTTP server
	brokerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		broker.Handle(w, r)
	}))
	defer brokerSrv.Close()

	brokerURL, err := url.Parse(brokerSrv.URL)
	require.NoError(t, err)

	client := NewClient(brokerURL, nil, nil, http.DefaultTransport, 100000, pub)

	type testCase struct {
		name            string
		method          string
		path            string
		headers         http.Header
		body            []byte
		expectStatus    int
		expectBody      string
		expectHeader    string
		expectHeaderVal string
	}

	tests := []testCase{
		{
			name:            "success",
			method:          "GET",
			path:            backend.URL + "/ok",
			expectStatus:    200,
			expectBody:      "backend response",
			expectHeader:    "X-Backend",
			expectHeaderVal: "yes",
		},
		{
			name:         "backend error",
			method:       "GET",
			path:         backend.URL + "/fail",
			expectStatus: 418,
			expectBody:   "teapot",
		},
		{
			name:         "not found",
			method:       "GET",
			path:         backend.URL + "/notfound",
			expectStatus: 404,
		},
		{
			name:         "post with body",
			method:       "POST",
			path:         backend.URL + "/ok",
			body:         []byte("hello"),
			expectStatus: 200,
			expectBody:   "backend response",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			require.NoError(t, err)
			req.Header = tc.headers

			rt, err := client.RoundTripper()
			require.NoError(t, err)
			resp, err := rt.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.expectStatus, resp.StatusCode)
			if tc.expectBody != "" {
				body, _ := io.ReadAll(resp.Body)
				assert.Equal(t, tc.expectBody, string(body))
			}
			if tc.expectHeader != "" {
				assert.Equal(t, tc.expectHeaderVal, resp.Header.Get(tc.expectHeader))
			}
		})
	}
}

func TestBroker_Handle_InvalidPath(t *testing.T) {
	priv, _ := newTestKeyPair(t)
	broker := NewBroker(1, priv, nil)
	req := httptest.NewRequest("GET", "/amp/invalidprefix/foobar", nil)
	w := httptest.NewRecorder()
	broker.Handle(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
