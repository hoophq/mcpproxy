package gateway_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/auth/outbound"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
)

// sseUpstream speaks the legacy HTTP+SSE transport for one session and
// records the Authorization of the stream and of every message POST.
type sseUpstream struct {
	mu     sync.Mutex
	stream []string
	posts  []string
	frames chan string
}

func (u *sseUpstream) auth() (stream, posts []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.stream...), append([]string(nil), u.posts...)
}

func (u *sseUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	if r.Method == http.MethodGet {
		u.stream = append(u.stream, r.Header.Get("Authorization"))
	} else {
		u.posts = append(u.posts, r.Header.Get("Authorization"))
	}
	u.mu.Unlock()

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: endpoint\ndata: /messages\n\n")
		w.(http.Flusher).Flush()
		for {
			select {
			case f := <-u.frames:
				fmt.Fprint(w, f)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
	body, _ := io.ReadAll(r.Body)
	env, err := jsonrpc.Parse(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	if !env.IsRequest() {
		return
	}
	res := `{}`
	switch env.Method {
	case "initialize":
		res = `{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"up","version":"0"}}`
	case "tools/list":
		res = `{"tools":[{"name":"ask","inputSchema":{"type":"object"}}]}`
	case "tools/call":
		res = `{"content":[{"type":"text","text":"done"}]}`
	}
	u.frames <- fmt.Sprintf("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n\n", env.ID, res)
}

// An SSE backend opens its stream with the credential of the caller that
// opened the session and keeps it; each message POST carries the credential
// of its own request, a rotated one included.
func TestSSEStreamUsesSessionOpenerCredential(t *testing.T) {
	t.Parallel()
	u := &sseUpstream{frames: make(chan string, 16)}
	up := httptest.NewServer(u)
	defer up.Close()
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "sse", URL: up.URL + "/sse"}, outbound.NewPassthrough()),
		},
		Pipeline:       checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		Resolver:       passthroughResolver,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()

	c := &tclient{t: t, url: front.URL, header: http.Header{outbound.UpstreamAuthHeader: {"Bearer tok-opener"}}}
	c.initialize()
	c.header.Set(outbound.UpstreamAuthHeader, "Bearer tok-rotated")
	if m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ask","arguments":{}}}`); m["result"] == nil {
		t.Fatalf("tools/call: %v", m)
	}

	stream, posts := u.auth()
	if len(stream) != 1 || stream[0] != "Bearer tok-opener" {
		t.Errorf("stream opened with %q, want once with the session opener's credential", stream)
	}
	if len(posts) == 0 || posts[0] != "Bearer tok-opener" || posts[len(posts)-1] != "Bearer tok-rotated" {
		t.Errorf("message POSTs carried %q, want each request's own credential", posts)
	}
}
