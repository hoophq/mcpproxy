// Package session holds per-MCP-session protocol state: request/response
// correlation, the observed tool catalog with fingerprints, identity, and
// arbitrary per-check state.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// Pending describes an in-flight request awaiting its response.
type Pending struct {
	Method  string
	Tool    string // tools/call only
	Backend string
}

// State is the concrete session implementation of inspect.Session.
type State struct {
	id       string
	identity inspect.Identity

	mu       sync.Mutex
	pending  map[string]Pending           // jsonrpc.ID.Key() → request info
	tools    map[string]map[string]string // backend → tool name → fingerprint
	counters map[string]*int64
	meta     map[string]any

	ClientInfo mcp.Implementation
	ServerInfo map[string]mcp.Implementation // per backend
}

// New creates session state.
func New(id string, identity inspect.Identity) *State {
	return &State{
		id:         id,
		identity:   identity,
		pending:    map[string]Pending{},
		tools:      map[string]map[string]string{},
		counters:   map[string]*int64{},
		meta:       map[string]any{},
		ServerInfo: map[string]mcp.Implementation{},
	}
}

// ID implements inspect.Session.
func (s *State) ID() string { return s.id }

// Identity implements inspect.Session.
func (s *State) Identity() inspect.Identity { return s.identity }

// TrackRequest records an outgoing C2S request for response correlation.
func (s *State) TrackRequest(id jsonrpc.ID, backend, method, tool string) {
	if id.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[id.Key()] = Pending{Method: method, Tool: tool, Backend: backend}
}

// ResolveResponse pops correlation info for a response id. ok is false for
// unsolicited responses.
func (s *State) ResolveResponse(id jsonrpc.ID) (Pending, bool) {
	if id.IsZero() {
		return Pending{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id.Key()]
	if ok {
		delete(s.pending, id.Key())
	}
	return p, ok
}

// DropPending removes a tracked request (used when the gateway itself
// answers it, e.g. a denied call).
func (s *State) DropPending(id jsonrpc.ID) {
	if id.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id.Key())
}

// Fingerprint hashes the security-relevant identity of a tool: name,
// description, and input schema. Any change to these mid-session is a
// rug-pull signal.
func Fingerprint(t mcp.Tool) string {
	h := sha256.New()
	h.Write([]byte(t.Name))
	h.Write([]byte{0})
	h.Write([]byte(t.Description))
	h.Write([]byte{0})
	h.Write(compactJSON(t.InputSchema))
	return hex.EncodeToString(h.Sum(nil))
}

func compactJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// ObserveTool records a tool from a tools/list response. It returns the
// previous fingerprint and whether the tool was seen before. A changed
// fingerprint on a known tool is a rug pull.
func (s *State) ObserveTool(backend string, t mcp.Tool) (prev string, known bool) {
	fp := Fingerprint(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.tools[backend]
	if m == nil {
		m = map[string]string{}
		s.tools[backend] = m
	}
	prev, known = m[t.Name]
	m[t.Name] = fp
	return prev, known
}

// InvalidateTools clears the catalog for a backend (on
// notifications/tools/list_changed) so the next tools/list re-fingerprints.
// It keeps the existing fingerprints so rug-pull detection still compares
// against the pre-change catalog.
func (s *State) InvalidateTools(backend string) {
	// Retain: comparison happens in ObserveTool against existing entries.
	// There is nothing to clear. ToolKnown must keep answering true for
	// tools the client already saw, and fingerprints must persist for
	// comparison.
	_ = backend
}

// ToolKnown implements inspect.Session.
func (s *State) ToolKnown(backend, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tools[backend][name]
	return ok
}

// Counter implements inspect.Session.
func (s *State) Counter(name string) *int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.counters[name]
	if !ok {
		c = new(int64)
		s.counters[name] = c
	}
	return c
}

// Meta implements inspect.Session.
func (s *State) Meta(key string, mk func() any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.meta[key]
	if !ok {
		v = mk()
		s.meta[key] = v
	}
	return v
}
