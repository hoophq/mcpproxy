package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	replies chan struct{}          // drop replies in flight, see dropS2C
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
	// toward the client's SSE stream. See enqueueS2C.
	s2c     chan s2cMsg
	s2cMu   sync.Mutex // serializes evict and insert across backend pumps
	dropped atomic.Int64

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
	c.enqueueS2C(bc, out)
}

// s2cQueue is how many server-initiated messages wait for the client's GET
// stream before the oldest is dropped.
const s2cQueue = 64

// dropReplyTimeout bounds the error reply sent to a server whose request
// was dropped, so a remote backend slow to accept it cannot hold anything
// up. A stdio backend's Send ignores the deadline and waits on the child's
// stdin; Close ends that wait. Session DELETE and Close wait for replies
// still in flight, at most this long.
const dropReplyTimeout = 5 * time.Second

// dropReplyLimit caps the replies in flight per backend, so one that floods
// server requests and never accepts replies cannot pile up goroutines or
// hold the slots of another backend.
const dropReplyLimit = 8

type s2cMsg struct {
	raw []byte
	bc  *backendConn
}

// enqueueS2C hands a server-initiated message to the client's GET stream and
// never blocks the pump: a full queue drops its oldest message, so a session
// with no stream open still receives its responses.
func (c *conn) enqueueS2C(bc *backendConn, raw []byte) {
	for _, d := range c.offerS2C(s2cMsg{raw: raw, bc: bc}) {
		c.dropS2C(d)
	}
}

// offerS2C puts msg on the queue and evicts the oldest message when it is
// full, under one lock so concurrent pumps keep the drop-oldest order. It
// never blocks. It returns what it dropped.
func (c *conn) offerS2C(msg s2cMsg) []s2cMsg {
	c.s2cMu.Lock()
	defer c.s2cMu.Unlock()
	select {
	case c.s2c <- msg:
		return nil
	case <-c.done:
		return nil
	default:
	}
	var dropped []s2cMsg
	select {
	case old := <-c.s2c:
		dropped = append(dropped, old)
	default:
	}
	select {
	case c.s2c <- msg:
	default:
		dropped = append(dropped, msg)
	}
	return dropped
}

// dropS2C answers a dropped server request with an error, so the server stops
// waiting, and audits the first drop of the session. The reply goes out off
// the pump, with a deadline: the pump must never wait on a backend.
func (c *conn) dropS2C(m s2cMsg) {
	ctx := context.Background()
	if env, err := jsonrpc.Parse(m.raw); err == nil && env.IsRequest() {
		reply := jsonrpc.NewError(env.ID, jsonrpc.CodeInternalError, "client has no stream open for server requests")
		if rb, err := reply.Marshal(); err == nil {
			select {
			case m.bc.replies <- struct{}{}:
				go func() {
					defer func() { <-m.bc.replies }()
					ctx, cancel := context.WithTimeout(context.Background(), dropReplyTimeout)
					defer cancel()
					_ = m.bc.b.Send(ctx, rb)
				}()
			default:
				c.g.log.Debug("drop reply skipped, limit reached", "sid", c.state.ID(), "backend", m.bc.name)
			}
		}
	}
	if c.dropped.Add(1) == 1 {
		c.g.sink.Emit(ctx, audit.Event{
			Time: time.Now(), Type: audit.EventError, Session: c.state.ID(),
			Backend: m.bc.name, Reason: "server-to-client queue full with no stream draining it; dropping the oldest messages",
		})
	}
	c.g.log.Debug("dropped server-to-client message", "sid", c.state.ID(), "backend", m.bc.name)
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
// sorted-name order for methods that need one target. Sorted rather than
// arbitrary so that under aggregation the same method always lands on the
// same backend, making both routing and audit reproducible.
func (c *conn) anyBackend() *backendConn {
	names := c.backendNames()
	if len(names) == 0 {
		return nil
	}
	return c.backends[names[0]]
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
	for _, name := range c.backendNames() {
		bc := c.backends[name]
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
			if first == nil {
				c.state.SetProtocolVersion(res.ProtocolVersion)
			}
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
	merged := map[string]json.RawMessage{}
	tools := []json.RawMessage{}
	// Iterate backends in a stable order: the spec asks for a deterministic
	// tools/list so clients can cache the catalog and keep upstream prompt
	// caches stable. Go randomizes map iteration, so ranging c.backends
	// directly reshuffles the merged list on every call.
	for _, name := range c.backendNames() {
		resp, err := c.roundTrip(ctx, c.backends[name], env)
		if err != nil {
			return nil, fmt.Errorf("tools/list %s: %w", name, err)
		}
		if resp.Error != nil {
			return resp, nil
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(resp.Result, &fields); err != nil {
			return nil, fmt.Errorf("tools/list %s: bad result: %w", name, err)
		}
		var res []json.RawMessage
		if raw, ok := fields["tools"]; ok {
			if err := json.Unmarshal(raw, &res); err != nil {
				return nil, fmt.Errorf("tools/list %s: bad tools array: %w", name, err)
			}
		}
		for _, rawTool := range res {
			out := rawTool
			if c.g.aggregated() {
				out = prefixToolName(rawTool, name+"_")
			}
			tools = append(tools, out)
		}
		mergeListFields(merged, fields)
	}
	toolsRaw, err := json.Marshal(tools)
	if err != nil {
		return nil, err
	}
	merged["tools"] = toolsRaw
	b, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	return &jsonrpc.Message{JSONRPC: "2.0", ID: env.ID, Result: b}, nil
}

// backendNames returns backend names in sorted order, so every fan-out and
// every merged catalog is byte-stable across calls.
func (c *conn) backendNames() []string {
	names := make([]string, 0, len(c.backends))
	for name := range c.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// mergeListFields folds one backend's result envelope into the merged one,
// preserving fields the gateway does not model so a newer revision survives
// the merge. Only "tools" is rebuilt by the caller.
//
// Cache hints need real arithmetic rather than last-writer-wins: the merged
// catalog is only as fresh as its stalest contributor, so ttlMs takes the
// minimum, and it is only as shareable as its most restrictive contributor,
// so any "private" scope makes the whole result private. Dropping these (the
// previous behavior, which rebuilt a typed result) silently discarded a
// backend's caching policy; taking a maximum would let one permissive backend
// license a shared cache to serve another's private catalog.
func mergeListFields(dst, src map[string]json.RawMessage) {
	for k, v := range src {
		switch k {
		case "tools", "nextCursor":
			// Rebuilt by the caller; a per-backend cursor is meaningless
			// once several catalogs are concatenated.
		case "ttlMs":
			var incoming, existing float64
			if json.Unmarshal(v, &incoming) != nil {
				continue
			}
			if cur, ok := dst[k]; !ok || json.Unmarshal(cur, &existing) != nil || incoming < existing {
				dst[k] = v
			}
		case "cacheScope":
			var scope string
			if json.Unmarshal(v, &scope) != nil {
				continue
			}
			if _, ok := dst[k]; !ok || scope != "public" {
				dst[k] = v
			}
		default:
			if _, ok := dst[k]; !ok {
				dst[k] = v
			}
		}
	}
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
