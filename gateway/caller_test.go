package gateway_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

// passthroughResolver moves the caller's upstream credential onto the
// request context, as mcpproxyd and hoop do.
func passthroughResolver(r *http.Request) (inspect.Identity, error) {
	if v := r.Header.Get(outbound.UpstreamAuthHeader); v != "" {
		*r = *r.WithContext(outbound.WithClientToken(r.Context(), outbound.TrimBearer(v)))
	}
	return inspect.Identity{Subject: "alice"}, nil
}

// samplingUpstream is a streamable-HTTP server that answers tools/call with
// a sampling request before the result. It reports the Authorization of
// every reply it receives.
func samplingUpstream(replies chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env, err := jsonrpc.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Mcp-Session-Id", "up-1")
		var res string
		switch {
		case env.IsResponse():
			replies <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusAccepted)
			return
		case env.IsNotification():
			w.WriteHeader(http.StatusAccepted)
			return
		case env.Method == "initialize":
			res = `{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"up","version":"0"}}`
		case env.Method == "tools/list":
			res = `{"tools":[{"name":"ask","inputSchema":{"type":"object"}}]}`
		case env.Method == "tools/call":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, `data: {"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}`+"\n\n")
			fmt.Fprintf(w, `data: {"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done"}]}}`+"\n\n", env.ID)
			return
		default:
			res = `{}`
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, env.ID, res)
	}
}

// The gateway's own reply to a server request reaches the upstream with the
// credential of the session's latest request, through a passthrough
// TokenSource that reads only the context.
func TestServerRequestReplyCarriesSessionCaller(t *testing.T) {
	t.Parallel()
	replies := make(chan string, 4)
	up := httptest.NewServer(samplingUpstream(replies))
	defer up.Close()
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: up.URL}, outbound.NewPassthrough()),
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

	c := &tclient{t: t, url: front.URL, header: http.Header{outbound.UpstreamAuthHeader: {"Bearer tok-1"}}}
	c.initialize()
	c.header.Set(outbound.UpstreamAuthHeader, "Bearer tok-2")
	if m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ask","arguments":{}}}`); m["result"] == nil {
		t.Fatalf("tools/call: %v", m)
	}

	select {
	case got := <-replies:
		if got != "Bearer tok-2" {
			t.Fatalf("reply to the sampling request carried %q, want the session's latest credential", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the denied sampling request got no reply upstream")
	}
}

// ctxBE records the passthrough credential on the context of every reply the
// gateway sends toward the server.
type ctxBE struct {
	*fakeBE
	tokens chan string
}

func (b *ctxBE) Send(ctx context.Context, msg []byte) error {
	if env, err := jsonrpc.Parse(msg); err == nil && env.IsResponse() {
		tok, _ := outbound.ClientTokenFrom(ctx)
		b.tokens <- tok
	}
	return b.fakeBE.Send(ctx, msg)
}

// A server request the full S2C queue drops is answered with the session's
// caller on the context too.
func TestDroppedServerRequestReplyCarriesSessionCaller(t *testing.T) {
	t.Parallel()
	be := &ctxBE{fakeBE: newFakeBE("main"), tokens: make(chan string, 16)}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{"main": func(context.Context) (backend.Backend, error) { return be, nil }},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		Resolver: passthroughResolver,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()

	c := &tclient{t: t, url: front.URL, header: http.Header{outbound.UpstreamAuthHeader: {"Bearer tok-1"}}}
	c.initialize()
	for i := 1; i <= 66; i++ {
		be.recv <- []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":"s%d","method":"ping"}`, i))
	}
	select {
	case got := <-be.tokens:
		if got != "tok-1" {
			t.Fatalf("drop reply context carried %q, want tok-1", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no drop reply")
	}
}
