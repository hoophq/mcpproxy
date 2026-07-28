package backend

// Tests for the legacy HTTP+SSE backend against an in-process fake server
// speaking the 2024-11-05 transport: a GET stream that emits an endpoint
// event, and POST /messages answered over that stream.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// fakeSSEServer implements the legacy transport for tests.
type fakeSSEServer struct {
	t *testing.T

	mu      sync.Mutex
	stream  chan string // SSE frames pushed to the connected client
	posts   [][]byte    // bodies received on the message endpoint
	authHdr string      // last Authorization seen
	// echoInBody makes POST answer with JSON in the body instead of the
	// stream, a tolerated off-spec server shape.
	echoInBody bool
	// relativeEndpoint emits the endpoint event as a relative URL.
	relativeEndpoint bool

	srv *httptest.Server
}

func newFakeSSE(t *testing.T) *fakeSSEServer {
	t.Helper()
	f := &fakeSSEServer{t: t, stream: make(chan string, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", f.handleStream)
	mux.HandleFunc("/messages", f.handleMessage)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSSEServer) handleStream(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authHdr = r.Header.Get("Authorization")
	f.mu.Unlock()

	fl := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	ep := f.srv.URL + "/messages"
	if f.relativeEndpoint {
		ep = "/messages"
	}
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", ep)
	fl.Flush()
	for {
		select {
		case frame, ok := <-f.stream:
			if !ok {
				return
			}
			fmt.Fprint(w, frame)
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (f *fakeSSEServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(body)
	f.mu.Lock()
	f.posts = append(f.posts, body)
	echo := f.echoInBody
	f.mu.Unlock()

	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &msg)
	if len(msg.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, msg.ID)
	if echo {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, resp)
		return
	}
	// Spec shape: 202 on POST, response over the stream.
	w.WriteHeader(http.StatusAccepted)
	f.stream <- fmt.Sprintf("event: message\ndata: %s\n\n", resp)
}

func startSSE(t *testing.T, f *fakeSSEServer, mut func(*SSEBackend)) *SSEBackend {
	t.Helper()
	b := NewSSE("test", config.Backend{Transport: "sse", URL: f.srv.URL + "/sse"}, nil)
	if mut != nil {
		mut(b)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func recvOne(t *testing.T, b *SSEBackend) []byte {
	t.Helper()
	select {
	case msg, ok := <-b.Recv():
		if !ok {
			t.Fatalf("recv closed while waiting for a message (err=%v)", b.Err())
		}
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
		return nil
	}
}

func TestSSERoundTrip(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	b := startSSE(t, f, nil)

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := recvOne(t, b)
	if !strings.Contains(string(got), `"ok":true`) {
		t.Fatalf("unexpected response: %s", got)
	}
}

func TestSSERelativeEndpointResolved(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	f.relativeEndpoint = true
	b := startSSE(t, f, nil)

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":7,"method":"ping"}`)); err != nil {
		t.Fatalf("Send with relative endpoint: %v", err)
	}
	recvOne(t, b)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) != 1 {
		t.Fatalf("expected 1 post, got %d", len(f.posts))
	}
}

func TestSSENotificationNoResponse(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	b := startSSE(t, f, nil)

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
		t.Fatalf("Send notification: %v", err)
	}
	select {
	case msg := <-b.Recv():
		t.Fatalf("unexpected message for a notification: %s", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSSEBodyEchoTolerated(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	f.echoInBody = true
	b := startSSE(t, f, nil)

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := recvOne(t, b)
	if !strings.Contains(string(got), `"id":2`) {
		t.Fatalf("body-echoed response not delivered: %s", got)
	}
}

func TestSSETokenSourceAppliedToStreamAndPosts(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	b := startSSE(t, f, func(b *SSEBackend) {
		b.TokenSource = func(context.Context) (string, error) { return "tok-123", nil }
	})

	f.mu.Lock()
	hdr := f.authHdr
	f.mu.Unlock()
	if hdr != "Bearer tok-123" {
		t.Fatalf("stream GET missing bearer: %q", hdr)
	}
	_ = b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":3,"method":"ping"}`))
	recvOne(t, b)
}

func TestSSEServerStreamCloseTerminatesBackend(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	b := startSSE(t, f, nil)

	close(f.stream) // server ends the event stream
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not terminate after stream close")
	}
	if b.Err() == nil {
		t.Fatal("expected a termination error after server-side close")
	}
	if err := b.Send(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("Send after termination should fail")
	}
}

func TestSSECleanCloseNoError(t *testing.T) {
	t.Parallel()
	f := newFakeSSE(t)
	b := startSSE(t, f, nil)

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after Close")
	}
	if err := b.Err(); err != nil {
		t.Fatalf("clean Close must not report an error, got: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close must be idempotent: %v", err)
	}
}

func TestSSEWrongContentTypeRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	b := NewSSE("test", config.Backend{Transport: "sse", URL: srv.URL}, nil)
	err := b.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "streamable-http") {
		t.Fatalf("expected content-type rejection hinting at streamable-http, got: %v", err)
	}
}

func TestSSEUnauthorizedSurfacesChallenge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	b := NewSSE("test", config.Backend{Transport: "sse", URL: srv.URL}, nil)
	err := b.Start(context.Background())
	var ue *ErrUnauthorized
	if !errors.As(err, &ue) {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}
	if !strings.Contains(ue.Challenge, "resource_metadata") {
		t.Fatalf("challenge not preserved: %q", ue.Challenge)
	}
}
