// Package gateway is the MCP gateway core. It terminates streamable-HTTP on
// the front, runs every message through the inspection pipeline, then routes
// to one or more backends (aggregating with tool prefixes when several).
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/session"
)

// IdentityResolver authenticates an HTTP request (inbound auth). It returns
// the caller identity or an error that terminates the request. The gateway
// stays auth-agnostic: the daemon (or hoop) supplies the resolver.
type IdentityResolver func(r *http.Request) (inspect.Identity, error)

// Options assemble a Gateway.
type Options struct {
	// Backends: name → factory. Names are tool prefixes in aggregation.
	Backends map[string]backend.Factory
	// Pipeline is the ordered check chain applied to every message.
	Pipeline []inspect.Check
	// Resolver authenticates requests. nil = anonymous.
	Resolver IdentityResolver
	// Sink receives audit events. nil = discard.
	Sink audit.Sink
	// SessionIdleTimeout reaps sessions with no traffic. 0 = 30m.
	SessionIdleTimeout time.Duration
	// RequestTimeout bounds one round-trip to a backend. 0 = 5m, since
	// slow tool calls are normal. Approvals hold longer via ctx.
	RequestTimeout time.Duration
	// Held is the approval parking lot; nil disables Hold verdicts
	// (they become Deny).
	Held HeldStore
	// Observer receives per-message timing/decision telemetry. Optional.
	Observer Observer
	Logger   *slog.Logger
}

// Observer is the telemetry seam: one call per gateway-processed message.
type Observer interface {
	ObserveMessage(dir inspect.Direction, backendName, method, tool, decision string, dur time.Duration)
}

// HeldStore parks messages awaiting human approval.
type HeldStore interface {
	// Hold parks a call and returns a resolution channel. The channel
	// yields true (approved) or false (rejected) exactly once.
	Hold(ctx context.Context, h HeldCall) (id string, resolved <-chan bool, err error)
}

// HeldCall describes one parked tool call.
type HeldCall struct {
	Session string
	User    string
	Backend string
	Tool    string
	Args    []byte
	Rule    string
}

// Gateway is the shared front for all sessions.
type Gateway struct {
	opts   Options
	log    *slog.Logger
	sink   audit.Sink
	mu     sync.Mutex
	sess   map[string]*conn
	closed bool
}

// New builds a Gateway.
func New(opts Options) (*Gateway, error) {
	if len(opts.Backends) == 0 {
		return nil, fmt.Errorf("gateway requires at least one backend")
	}
	if opts.Sink == nil {
		opts.Sink = audit.Discard
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.SessionIdleTimeout == 0 {
		opts.SessionIdleTimeout = 30 * time.Minute
	}
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 5 * time.Minute
	}
	g := &Gateway{
		opts: opts,
		log:  opts.Logger,
		sink: opts.Sink,
		sess: map[string]*conn{},
	}
	go g.reaper()
	return g, nil
}

// aggregated reports whether tool-prefix aggregation is active.
func (g *Gateway) aggregated() bool { return len(g.opts.Backends) > 1 }

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (g *Gateway) getSession(id string) *conn {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sess[id]
}

func (g *Gateway) putSession(c *conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sess[c.state.ID()] = c
}

// dropSession removes a session and shuts it down. A non-nil reason ends it
// as killed, so the audit trail says why.
func (g *Gateway) dropSession(id string, reason error) {
	g.mu.Lock()
	c := g.sess[id]
	delete(g.sess, id)
	g.mu.Unlock()
	if c != nil {
		c.shutdown(reason)
	}
}

// Close terminates all sessions.
func (g *Gateway) Close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	conns := make([]*conn, 0, len(g.sess))
	for _, c := range g.sess {
		conns = append(conns, c)
	}
	g.sess = map[string]*conn{}
	g.mu.Unlock()
	for _, c := range conns {
		c.shutdown(nil)
	}
}

func (g *Gateway) reaper() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return
		}
		var stale []*conn
		for id, c := range g.sess {
			if time.Since(c.lastSeen()) > g.opts.SessionIdleTimeout {
				stale = append(stale, c)
				delete(g.sess, id)
			}
		}
		g.mu.Unlock()
		for _, c := range stale {
			g.log.Info("reaping idle session", "sid", c.state.ID())
			c.shutdown(nil)
		}
	}
}

// startSession spawns backends and pumps for a new session.
func (g *Gateway) startSession(ctx context.Context, identity inspect.Identity) (*conn, error) {
	st := session.New(newSessionID(), identity)
	c := &conn{
		g:        g,
		state:    st,
		backends: map[string]*backendConn{},
		s2c:      make(chan s2cMsg, s2cQueue),
		done:     make(chan struct{}),
	}
	c.touch()
	// Backends live as long as the session, not the initialize request.
	// ctx here is the POST's request context and cancels the moment the
	// handler writes the response, which would kill stdio children
	// mid-session. conn.shutdown tears the session down instead.
	bctx := context.WithoutCancel(ctx)
	for name, factory := range g.opts.Backends {
		b, err := factory(bctx)
		if err != nil {
			c.shutdown(nil)
			return nil, fmt.Errorf("backend %s: %w", name, err)
		}
		if err := b.Start(bctx); err != nil {
			c.shutdown(nil)
			return nil, fmt.Errorf("starting backend %s: %w", name, err)
		}
		bc := &backendConn{name: name, b: b, waiters: map[string]chan []byte{}, replies: make(chan struct{}, dropReplyLimit)}
		c.backends[name] = bc
		go c.pump(bc)
	}
	g.putSession(c)
	g.sink.Emit(ctx, audit.Event{
		Time: time.Now(), Type: audit.EventSessionStart,
		Session: st.ID(), User: identity.Subject,
	})
	return c, nil
}
