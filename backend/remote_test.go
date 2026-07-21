package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/internal/testmcp"
	"github.com/hoophq/mcpproxy/mcp"
)

func startRemote(t *testing.T, h http.Handler) (*RemoteBackend, *httptest.Server) {
	t.Helper()
	hs := httptest.NewServer(h)
	t.Cleanup(hs.Close)
	b := NewRemote("remote", config.Backend{
		Transport: TransportStreamableHTTP,
		URL:       hs.URL,
	}, nil)
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, hs
}

// TestRemoteRoundTripJSON and its SSE twin assert the same observable
// contract — one response message on Recv — across both legal
// streamable-HTTP response framings.
func TestRemoteRoundTripJSON(t *testing.T) {
	srv := testmcp.New()
	b, _ := startRemote(t, srv.HTTPHandler())
	assertRemoteRoundTrip(t, b)
}

func TestRemoteRoundTripSSE(t *testing.T) {
	srv := testmcp.New()
	srv.SSEResponses(true)
	b, _ := startRemote(t, srv.HTTPHandler())
	assertRemoteRoundTrip(t, b)
}

func assertRemoteRoundTrip(t *testing.T, b *RemoteBackend) {
	t.Helper()
	ctx := context.Background()
	if err := b.Send(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)); err != nil {
		t.Fatalf("Send initialize: %v", err)
	}
	got := recvMessage(t, b.Recv(), 5*time.Second)
	var res mcp.InitializeResult
	if err := json.Unmarshal(got.Result, &res); err != nil {
		t.Fatalf("decoding initialize result: %v", err)
	}
	if res.ProtocolVersion != testmcp.ProtocolVersion {
		t.Errorf("protocolVersion = %q", res.ProtocolVersion)
	}

	if err := b.Send(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"k":"v"}}}`)); err != nil {
		t.Fatalf("Send echo: %v", err)
	}
	got = recvMessage(t, b.Recv(), 5*time.Second)
	if got.ID.Key() != "2" {
		t.Errorf("id = %s, want 2", got.ID)
	}
	if !strings.Contains(string(got.Result), `k\":\"v`) {
		t.Errorf("echo result = %s", got.Result)
	}
}

// TestRemoteSSEMultipleEvents proves one POST can yield several messages:
// the server streams a progress notification before the actual response.
func TestRemoteSSEMultipleEvents(t *testing.T) {
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// A comment line, an event name and a multi-line data field all
		// have to be handled per the SSE spec.
		fmt.Fprint(w, ": keepalive\n\n")
		fmt.Fprint(w, "event: message\nid: 1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\n")
		fmt.Fprint(w, "data: \"result\":{\"ok\":true}}\n\n")
		w.(http.Flusher).Flush()
	}))

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	first := recvMessage(t, b.Recv(), 5*time.Second)
	if first.Method != mcp.MethodProgress {
		t.Errorf("first message = %+v, want a progress notification", first)
	}
	second := recvMessage(t, b.Recv(), 5*time.Second)
	if second.ID.Key() != "1" || string(second.Result) != `{"ok":true}` {
		t.Errorf("second message = %+v, want the reassembled multi-line response", second)
	}
}

// TestRemoteSSEFinalEventWithoutBlankLine: a server that closes the stream
// right after the last data line still delivered a complete event.
func TestRemoteSSEFinalEventWithoutBlankLine(t *testing.T) {
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n")
	}))
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":7,"method":"ping"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := recvMessage(t, b.Recv(), 5*time.Second); got.ID.Key() != "7" {
		t.Errorf("id = %s, want 7", got.ID)
	}
}

// TestRemoteSessionHeader: the id the server assigns on the first response
// must be echoed on every later request, and never overwritten.
func TestRemoteSessionHeader(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get(mcpSessionHeader))
		n := len(seen)
		mu.Unlock()
		// A server that renames the session mid-stream must not make us
		// forget the original.
		w.Header().Set(mcpSessionHeader, fmt.Sprintf("sess-%d", n))
		w.WriteHeader(http.StatusAccepted)
	}))

	ctx := context.Background()
	for i := range 3 {
		if err := b.Send(ctx, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if got := b.SessionID(); got != "sess-1" {
		t.Errorf("SessionID = %q, want sess-1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"", "sess-1", "sess-1"}
	for i, w := range want {
		if seen[i] != w {
			t.Errorf("request %d sent %s=%q, want %q", i, mcpSessionHeader, seen[i], w)
		}
	}
}

func TestRemoteNoPayloadStatuses(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case msg := <-b.Recv():
				t.Fatalf("got %s on Recv, want nothing for a %d", msg, status)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// TestRemoteUnauthorized: a 401 must arrive as a typed error carrying the
// challenge, because that header is what drives OAuth discovery.
func TestRemoteUnauthorized(t *testing.T) {
	const challenge = `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", challenge)
		http.Error(w, "nope", http.StatusUnauthorized)
	}))

	err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	var unauth *ErrUnauthorized
	if !errors.As(err, &unauth) {
		t.Fatalf("Send = %v, want an *ErrUnauthorized", err)
	}
	if unauth.Challenge != challenge {
		t.Errorf("Challenge = %q, want %q", unauth.Challenge, challenge)
	}
	if unauth.Backend != "remote" {
		t.Errorf("Backend = %q", unauth.Backend)
	}
	if !strings.Contains(unauth.Error(), "resource_metadata") {
		t.Errorf("Error() = %q, want the challenge included", unauth.Error())
	}
}

func TestRemoteHTTPErrorStatus(t *testing.T) {
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err == nil {
		t.Fatal("Send = nil, want an error for a 502")
	}
	var unauth *ErrUnauthorized
	if errors.As(err, &unauth) {
		t.Fatal("a 502 must not be reported as ErrUnauthorized")
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want the status and body excerpt", err)
	}
}

// TestRemoteTokenSource: static headers apply, and TokenSource wins on
// Authorization — that precedence is what lets OAuth override a stale static
// credential without rewriting the config.
func TestRemoteTokenSource(t *testing.T) {
	type capture struct{ auth, custom, contentType, accept string }
	got := make(chan capture, 1)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- capture{
			auth:        r.Header.Get("Authorization"),
			custom:      r.Header.Get("X-Custom"),
			contentType: r.Header.Get("Content-Type"),
			accept:      r.Header.Get("Accept"),
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer hs.Close()

	b := NewRemote("remote", config.Backend{
		Transport: TransportStreamableHTTP,
		URL:       hs.URL,
		Headers:   map[string]string{"X-Custom": "yes", "Authorization": "Bearer static"},
	}, nil)
	var calls int
	b.TokenSource = func(context.Context) (string, error) {
		calls++
		return fmt.Sprintf("dynamic-%d", calls), nil
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Close()

	for i := 1; i <= 2; i++ {
		if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"n"}`)); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		c := <-got
		if want := fmt.Sprintf("Bearer dynamic-%d", i); c.auth != want {
			t.Errorf("Authorization = %q, want %q (TokenSource overrides the static header)", c.auth, want)
		}
		if c.custom != "yes" {
			t.Errorf("X-Custom = %q, want the static header preserved", c.custom)
		}
		if c.contentType != "application/json" {
			t.Errorf("Content-Type = %q", c.contentType)
		}
		if !strings.Contains(c.accept, "text/event-stream") {
			t.Errorf("Accept = %q, want SSE advertised", c.accept)
		}
	}
}

func TestRemoteTokenSourceFailureAborts(t *testing.T) {
	var hits int
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer hs.Close()

	b := NewRemote("remote", config.Backend{Transport: TransportStreamableHTTP, URL: hs.URL}, nil)
	sentinel := errors.New("no token today")
	b.TokenSource = func(context.Context) (string, error) { return "", sentinel }
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Close()

	err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"n"}`))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send = %v, want the token source error wrapped", err)
	}
	if hits != 0 {
		t.Errorf("server saw %d requests, want 0 — an unauthenticated request must not go out", hits)
	}
}

// TestRemoteEmptyTokenLeavesStaticHeader: a passthrough source with no token
// for this caller must not clobber a configured static credential.
func TestRemoteEmptyTokenLeavesStaticHeader(t *testing.T) {
	got := make(chan string, 1)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer hs.Close()

	b := NewRemote("remote", config.Backend{
		Transport: TransportStreamableHTTP,
		URL:       hs.URL,
		Headers:   map[string]string{"Authorization": "Bearer static"},
	}, nil)
	b.TokenSource = func(context.Context) (string, error) { return "", nil }
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Close()
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"n"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if v := <-got; v != "Bearer static" {
		t.Errorf("Authorization = %q, want the static header untouched", v)
	}
}

func TestRemoteLifecycle(t *testing.T) {
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	if b.Name() != "remote" {
		t.Errorf("Name = %q", b.Name())
	}
	select {
	case <-b.Done():
		t.Fatal("Done closed before Close")
	default:
	}
	if err := b.Start(context.Background()); err == nil {
		t.Error("second Start should fail")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-b.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close after Close")
	}
	if _, ok := <-b.Recv(); ok {
		t.Error("Recv not closed after Close")
	}
	if err := b.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
	if err := b.Send(context.Background(), []byte(`{}`)); !errors.Is(err, ErrClosed) {
		t.Errorf("Send after Close = %v, want ErrClosed", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

// TestRemoteCloseDuringSSE: Close must not deadlock or panic while a stream
// is mid-flight, and must not close Recv from under the reader.
func TestRemoteCloseDuringSSE(t *testing.T) {
	release := make(chan struct{})
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		fl.Flush()
		// Flood past the Recv buffer so the SSE reader is parked on a
		// send when Close arrives.
		for i := range recvBuffer * 2 {
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"n%d\"}\n\n", i)
			fl.Flush()
		}
		<-release
	}))
	defer close(release)

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","method":"n"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	recvMessage(t, b.Recv(), 5*time.Second) // stream is live

	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close deadlocked against an in-flight SSE stream")
	}
	// Draining after Close must terminate rather than block forever.
	for range b.Recv() {
	}
}

func TestRemoteStartRequiresURL(t *testing.T) {
	b := NewRemote("remote", config.Backend{Transport: TransportStreamableHTTP}, nil)
	if err := b.Start(context.Background()); err == nil {
		t.Fatal("Start with no url should fail")
	}
}

func TestRemoteRejectsUnexpectedContentType(t *testing.T) {
	b, _ := startRemote(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>login</html>")
	}))
	err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err == nil || !strings.Contains(err.Error(), "content-type") {
		t.Fatalf("Send = %v, want a content-type error", err)
	}
}

func TestMediaType(t *testing.T) {
	tests := map[string]string{
		"application/json":                 "application/json",
		"application/json; charset=utf-8":  "application/json",
		"Text/Event-Stream ;charset=utf-8": "text/event-stream",
		"":                                 "",
		"  text/event-stream  ":            "text/event-stream",
	}
	for in, want := range tests {
		if got := mediaType(in); got != want {
			t.Errorf("mediaType(%q) = %q, want %q", in, got, want)
		}
	}
}
