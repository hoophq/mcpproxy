package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
	"github.com/hoophq/mcpproxy/session"
)

// backendConn pairs a backend with per-request waiters keyed by JSON-RPC id.
type backendConn struct {
	name string
	b    backend.Backend

	mu      sync.Mutex
	waiters map[string]chan []byte // id key → response delivery
}

func (bc *backendConn) addWaiter(key string) chan []byte {
	ch := make(chan []byte, 1)
	bc.mu.Lock()
	bc.waiters[key] = ch
	bc.mu.Unlock()
	return ch
}

func (bc *backendConn) dropWaiter(key string) {
	bc.mu.Lock()
	delete(bc.waiters, key)
	bc.mu.Unlock()
}

func (bc *backendConn) resolveWaiter(key string) (chan []byte, bool) {
	bc.mu.Lock()
	ch, ok := bc.waiters[key]
	if ok {
		delete(bc.waiters, key)
	}
	bc.mu.Unlock()
	return ch, ok
}

// conn is one live MCP session: state, backends, and the S2C stream.
type conn struct {
	g        *Gateway
	state    *session.State
	backends map[string]*backendConn

	// s2c carries server-initiated messages (requests, notifications)
	// toward the client's SSE stream.
	s2c chan []byte

	mu       sync.Mutex
	last     time.Time
	initRes  []byte // cached initialize result (aggregated)
	done     chan struct{}
	shutOnce sync.Once
}

func (c *conn) touch() {
	c.mu.Lock()
	c.last = time.Now()
	c.mu.Unlock()
}

func (c *conn) lastSeen() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// shutdown terminates the session; reason may be nil (normal teardown).
func (c *conn) shutdown(reason error) {
	c.shutOnce.Do(func() {
		close(c.done)
		for _, bc := range c.backends {
			_ = bc.b.Close()
		}
		ev := audit.Event{
			Time: time.Now(), Type: audit.EventSessionEnd,
			Session: c.state.ID(), User: c.state.Identity().Subject,
		}
		if reason != nil {
			ev.Type = audit.EventSessionKilled
			ev.Reason = reason.Error()
		}
		c.g.sink.Emit(context.Background(), ev)
	})
}

// pump drains one backend's recv stream. It hands responses to their waiter
// and pushes server-initiated traffic through the S2C pipeline to the SSE
// stream.
func (c *conn) pump(bc *backendConn) {
	for {
		select {
		case raw, ok := <-bc.b.Recv():
			if !ok {
				select {
				case <-c.done:
				default:
					c.g.log.Warn("backend terminated", "sid", c.state.ID(), "backend", bc.name, "err", bc.b.Err())
					c.g.dropSession(c.state.ID())
				}
				return
			}
			c.dispatchFromBackend(bc, raw)
		case <-c.done:
			return
		}
	}
}

func (c *conn) dispatchFromBackend(bc *backendConn, raw []byte) {
	env, err := jsonrpc.Parse(raw)
	if err != nil {
		c.g.log.Warn("unparseable message from backend", "backend", bc.name, "err", err)
		return
	}
	if env.IsResponse() {
		if ch, ok := bc.resolveWaiter(env.ID.Key()); ok {
			ch <- raw
			return
		}
		// Unsolicited response: drop with audit.
		c.g.sink.Emit(context.Background(), audit.Event{
			Time: time.Now(), Type: audit.EventError, Session: c.state.ID(),
			Backend: bc.name, Reason: "unsolicited response from backend",
		})
		return
	}
	// Server-initiated request or notification → S2C pipeline → SSE.
	out, ok := c.inspectS2C(bc, env)
	if !ok {
		return // denied; error already sent back to backend if request
	}
	select {
	case c.s2c <- out:
	case <-c.done:
	}
}

// inspectS2C runs the pipeline on a server-initiated message. Returns the
// (possibly mutated) serialized message and whether to forward it.
func (c *conn) inspectS2C(bc *backendConn, env *jsonrpc.Message) ([]byte, bool) {
	ctx := context.Background()
	m := &inspect.Msg{Dir: inspect.S2C, Backend: bc.name, Env: env}
	dec := c.runPipeline(ctx, m)
	switch dec.Verdict {
	case inspect.Allow:
		out, err := env.Marshal()
		if err != nil {
			return nil, false
		}
		return out, true
	case inspect.Deny:
		// Answer the server's request with an error so it stops waiting.
		if env.IsRequest() && dec.Reply != nil {
			if rb, err := dec.Reply.Marshal(); err == nil {
				_ = bc.b.Send(ctx, rb)
			}
		}
		return nil, false
	case inspect.Kill:
		c.g.dropSession(c.state.ID())
		c.shutdown(fmt.Errorf("%s", dec.Reason))
		return nil, false
	default: // Hold unsupported for S2C
		return nil, false
	}
}

func (c *conn) runPipeline(ctx context.Context, m *inspect.Msg) inspect.Decision {
	start := time.Now()
	dec := inspect.AllowAll
	for _, chk := range c.g.opts.Pipeline {
		dec = chk.Inspect(ctx, c.state, m)
		if dec.Verdict != inspect.Allow {
			dec.Rule = coalesce(dec.Rule, chk.Name())
			break
		}
	}
	if obs := c.g.opts.Observer; obs != nil {
		tool := ""
		method := ""
		if m.Env != nil {
			method = m.Env.Method
			if method == mcp.MethodToolsCall {
				tool = inspect.RawTool(m.Env.Params)
			} else if m.CorrelatedTool != "" {
				tool = m.CorrelatedTool
			}
		}
		obs.ObserveMessage(m.Dir, m.Backend, method, tool, verdictName(dec.Verdict), time.Since(start))
	}
	return dec
}

func verdictName(v inspect.Verdict) string {
	switch v {
	case inspect.Allow:
		return "allow"
	case inspect.Deny:
		return "deny"
	case inspect.Hold:
		return "hold"
	default:
		return "kill"
	}
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// routeTool resolves an aggregated tool name "backend_tool" to (backendConn,
// bare tool name). A single-backend gateway routes everything to that backend
// unprefixed.
func (c *conn) routeTool(name string) (*backendConn, string, error) {
	if !c.g.aggregated() {
		for _, bc := range c.backends {
			return bc, name, nil
		}
	}
	for bname, bc := range c.backends {
		p := bname + "_"
		if strings.HasPrefix(name, p) {
			return bc, strings.TrimPrefix(name, p), nil
		}
	}
	return nil, "", fmt.Errorf("unknown tool %q", name)
}

// anyBackend returns the sole backend (single-backend mode) or the first in
// deterministic-enough order for methods that need one target.
func (c *conn) anyBackend() *backendConn {
	for _, bc := range c.backends {
		return bc
	}
	return nil
}

// roundTrip sends env to bc and awaits the matching response.
func (c *conn) roundTrip(ctx context.Context, bc *backendConn, env *jsonrpc.Message) (*jsonrpc.Message, error) {
	raw, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	if env.ID.IsZero() { // notification: no response
		return nil, bc.b.Send(ctx, raw)
	}
	ch := bc.addWaiter(env.ID.Key())
	defer bc.dropWaiter(env.ID.Key())
	if err := bc.b.Send(ctx, raw); err != nil {
		return nil, err
	}
	select {
	case respRaw := <-ch:
		return jsonrpc.Parse(respRaw)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-bc.b.Done():
		return nil, fmt.Errorf("backend %s terminated: %w", bc.name, coalesceErr(bc.b.Err()))
	case <-c.done:
		return nil, fmt.Errorf("session closed")
	}
}

func coalesceErr(err error) error {
	if err == nil {
		return fmt.Errorf("closed")
	}
	return err
}

// fanoutInitialize sends initialize to every backend, records server info,
// and returns a merged result (first backend's payload, gateway-branded in
// aggregation mode).
func (c *conn) fanoutInitialize(ctx context.Context, env *jsonrpc.Message) (*jsonrpc.Message, error) {
	var p mcp.InitializeParams
	_ = json.Unmarshal(env.Params, &p)
	c.state.ClientInfo = p.ClientInfo

	var first *jsonrpc.Message
	for name, bc := range c.backends {
		resp, err := c.roundTrip(ctx, bc, env)
		if err != nil {
			return nil, fmt.Errorf("initialize %s: %w", name, err)
		}
		if resp.Error != nil {
			return resp, nil
		}
		var res mcp.InitializeResult
		if err := json.Unmarshal(resp.Result, &res); err == nil {
			c.state.ServerInfo[name] = res.ServerInfo
		}
		if first == nil {
			first = resp
		}
		// Deliver the initialized notification later via notifyAll.
	}
	if c.g.aggregated() && first != nil {
		var res mcp.InitializeResult
		if err := json.Unmarshal(first.Result, &res); err == nil {
			res.ServerInfo = mcp.Implementation{Name: "mcpproxy-gateway", Version: "0.1.0"}
			if b, err := json.Marshal(res); err == nil {
				first.Result = b
			}
		}
	}
	c.g.sink.Emit(ctx, audit.Event{
		Time: time.Now(), Type: audit.EventInitialize, Session: c.state.ID(),
		User: c.state.Identity().Subject,
		Fields: map[string]any{
			"client": p.ClientInfo.Name, "client_version": p.ClientInfo.Version,
		},
	})
	return first, nil
}

// notifyAll forwards a notification to every backend.
func (c *conn) notifyAll(ctx context.Context, env *jsonrpc.Message) error {
	raw, err := env.Marshal()
	if err != nil {
		return err
	}
	for _, bc := range c.backends {
		if err := bc.b.Send(ctx, raw); err != nil {
			return err
		}
	}
	return nil
}

// fanoutToolsList queries every backend and merges the tool lists, prefixing
// names in aggregation mode. Reusing env.ID across backends is safe because
// waiters are per-backend.
func (c *conn) fanoutToolsList(ctx context.Context, env *jsonrpc.Message) (*jsonrpc.Message, error) {
	merged := mcp.ToolsListResult{Tools: []json.RawMessage{}}
	for name, bc := range c.backends {
		resp, err := c.roundTrip(ctx, bc, env)
		if err != nil {
			return nil, fmt.Errorf("tools/list %s: %w", name, err)
		}
		if resp.Error != nil {
			return resp, nil
		}
		var res mcp.ToolsListResult
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			return nil, fmt.Errorf("tools/list %s: bad result: %w", name, err)
		}
		for _, rawTool := range res.Tools {
			out := rawTool
			if c.g.aggregated() {
				out = prefixToolName(rawTool, name+"_")
			}
			merged.Tools = append(merged.Tools, out)
		}
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	return &jsonrpc.Message{JSONRPC: "2.0", ID: env.ID, Result: b}, nil
}

// prefixToolName rewrites the "name" field of a raw tool entry.
func prefixToolName(raw json.RawMessage, prefix string) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	var name string
	if err := json.Unmarshal(m["name"], &name); err != nil {
		return raw
	}
	nb, _ := json.Marshal(prefix + name)
	m["name"] = nb
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}
