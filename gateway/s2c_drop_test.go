package gateway_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
)

// fakeBE answers client requests with a minimal result and records every
// response the gateway sends back toward the server.
type fakeBE struct {
	name string
	recv chan []byte
	done chan struct{}
	sent chan []byte
	once sync.Once
}

func newFakeBE(name string) *fakeBE {
	return &fakeBE{name: name, recv: make(chan []byte, 8192), done: make(chan struct{}), sent: make(chan []byte, 8192)}
}
func (b *fakeBE) Name() string                { return b.name }
func (b *fakeBE) Start(context.Context) error { return nil }
func (b *fakeBE) Recv() <-chan []byte         { return b.recv }
func (b *fakeBE) Done() <-chan struct{}       { return b.done }
func (b *fakeBE) Err() error                  { return nil }
func (b *fakeBE) Close() error                { b.once.Do(func() { close(b.done) }); return nil }
func (b *fakeBE) Send(_ context.Context, msg []byte) error {
	env, err := jsonrpc.Parse(msg)
	if err != nil {
		return err
	}
	if env.IsResponse() {
		b.sent <- msg
		return nil
	}
	if env.IsNotification() {
		return nil
	}
	var res *jsonrpc.Message
	switch env.Method {
	case "initialize":
		res, _ = jsonrpc.NewResult(env.ID, map[string]any{"protocolVersion": "2025-06-18", "serverInfo": map[string]any{"name": b.name, "version": "0"}, "capabilities": map[string]any{}})
	case "tools/list":
		res, _ = jsonrpc.NewResult(env.ID, map[string]any{"tools": []any{map[string]any{"name": "echo", "description": "d", "inputSchema": map[string]any{"type": "object"}}}})
	default:
		res, _ = jsonrpc.NewResult(env.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}})
	}
	raw, _ := res.Marshal()
	select {
	case b.recv <- raw:
	case <-b.done:
	}
	return nil
}

type s2cSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *s2cSink) Emit(_ context.Context, ev audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *s2cSink) queueFull() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, ev := range s.events {
		if ev.Type == audit.EventError && strings.Contains(ev.Reason, "queue full") {
			n++
		}
	}
	return n
}

func newFakeGateway(t *testing.T, sink audit.Sink, names ...string) (map[string]*fakeBE, *httptest.Server) {
	t.Helper()
	bes := map[string]*fakeBE{}
	factories := map[string]backend.Factory{}
	for _, n := range names {
		be := newFakeBE(n)
		bes[n] = be
		factories[n] = func(context.Context) (backend.Backend, error) { return be, nil }
	}
	gw, err := gateway.New(gateway.Options{
		Backends:       factories,
		Pipeline:       checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		Sink:           sink,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { front.Close(); gw.Close() })
	return bes, front
}

func notif(i int) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"chatter %d"}}`, i))
}

// readSSE opens the GET stream for d and returns the data payloads it saw.
func readSSE(url, sid string, d time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"/mcp", nil)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			out = append(out, strings.TrimPrefix(sc.Text(), "data: "))
		}
	}
	return out, nil
}

// The oldest server requests a full queue drops are answered with -32603, in
// any order, so the server stops waiting; the session audits the first drop
// once.
func TestDroppedServerRequestGetsErrorReply(t *testing.T) {
	sink := &s2cSink{}
	bes, front := newFakeGateway(t, sink, "main")
	c := &tclient{t: t, url: front.URL}
	c.initialize()
	be := bes["main"]
	for i := 1; i <= 70; i++ {
		be.recv <- []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":"s%d","method":"ping"}`, i))
	}
	var got []string
	deadline := time.After(2 * time.Second)
	for len(got) < 6 {
		select {
		case raw := <-be.sent:
			env, err := jsonrpc.Parse(raw)
			if err != nil || env.Error == nil || env.Error.Code != jsonrpc.CodeInternalError {
				t.Fatalf("reply to the server is not a -32603 error: %s", raw)
			}
			got = append(got, string(raw))
		case <-deadline:
			t.Fatalf("got %d error replies in 2s, want 6: %v", len(got), got)
		}
	}
	all := strings.Join(got, "\n")
	for i := 1; i <= 6; i++ {
		if !strings.Contains(all, fmt.Sprintf(`"id":"s%d"`, i)) {
			t.Fatalf("no reply answers s%d: %v", i, got)
		}
	}
	select {
	case raw := <-be.sent:
		t.Fatalf("unexpected 7th reply: %s", raw)
	case <-time.After(300 * time.Millisecond):
	}
	if n := sink.queueFull(); n != 1 {
		t.Fatalf("queue-full audit events = %d, want 1 per session", n)
	}
}

// After a burst with no stream open, a GET stream opened later holds the
// newest 64 messages: the queue drops its oldest.
func TestGETStreamHoldsNewest64AfterBurst(t *testing.T) {
	bes, front := newFakeGateway(t, audit.Discard, "main")
	c := &tclient{t: t, url: front.URL}
	c.initialize()
	be := bes["main"]
	for i := 1; i <= 100; i++ {
		be.recv <- notif(i)
	}
	time.Sleep(300 * time.Millisecond)
	ev, err := readSSE(front.URL, c.sid, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 64 || !strings.Contains(ev[0], "chatter 37") || !strings.Contains(ev[63], "chatter 100") {
		first, last := "", ""
		if len(ev) > 0 {
			first, last = ev[0], ev[len(ev)-1]
		}
		t.Fatalf("GET stream: %d events, first=%s last=%s; want 64, chatter 37..100", len(ev), first, last)
	}
}

// slowReplyServer is a streamable-http backend whose tools/call answers on
// an SSE body with `pings` server requests, then the result. It takes
// replyDelay to accept each response the gateway POSTs back.
func slowReplyServer(replyDelay time.Duration, pings int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(body, &m)
		w.Header().Set("Mcp-Session-Id", "slow")
		id, hasID := m["id"]
		if _, hasMethod := m["method"]; !hasMethod {
			time.Sleep(replyDelay)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if !hasID {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var method string
		_ = json.Unmarshal(m["method"], &method)
		jsonReply := func(s string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, s)
		}
		switch method {
		case "initialize":
			jsonReply(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"slow","version":"0"},"capabilities":{}}}`, id))
		case "tools/list":
			jsonReply(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"pings","description":"d","inputSchema":{"type":"object"}}]}}`, id))
		case "tools/call":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fl := w.(http.Flusher)
			for i := 1; i <= pings; i++ {
				fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"s%d\",\"method\":\"ping\"}\n\n", i)
				fl.Flush()
			}
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}}\n\n", id)
			fl.Flush()
		default:
			jsonReply(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, id))
		}
	}))
}

// A backend slow to accept the error replies for dropped requests must not
// delay the tool result: the replies go out off the pump. 70 pings over a
// 64 queue drop 6, at one second each if they were in line.
func TestDropReplyDoesNotDelayTheResult(t *testing.T) {
	hs := slowReplyServer(time.Second, 70)
	defer hs.Close()
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
		},
		Pipeline:       checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		RequestTimeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()
	c := &tclient{t: t, url: front.URL}
	c.initialize()
	start := time.Now()
	m, code := c.post(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pings","arguments":{}}}`)
	d := time.Since(start)
	if code != 200 || m["result"] == nil {
		t.Fatalf("tools/call: %d %v", code, m)
	}
	if d > 2*time.Second {
		t.Fatalf("the result waited %v on the drop replies", d.Round(time.Millisecond))
	}
}
