package checks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
	"github.com/hoophq/mcpproxy/session"
)

// Rug-pull responses.
const (
	OnRugPullKill  = "kill"
	OnRugPullAlert = "alert"
)

// RugPull detects a server silently mutating a tool the client already
// approved of. An MCP server can re-answer tools/list at any time; if the
// description or input schema of an already-seen tool changes mid-session,
// the client's model is now reasoning about a tool it never saw. That is the
// rug pull, and the default response is to kill the session.
type RugPull struct {
	onChange string
	sink     audit.Sink
}

// NewRugPull builds the rug-pull check. An unrecognised or empty
// on_rug_pull setting resolves to "kill".
func NewRugPull(pol config.Policy, sink audit.Sink) *RugPull {
	mode := pol.OnRugPull
	if mode != OnRugPullAlert {
		mode = OnRugPullKill
	}
	return &RugPull{onChange: mode, sink: sink}
}

// Name implements inspect.Check.
func (r *RugPull) Name() string { return NameRugPull }

// Inspect implements inspect.Check.
func (r *RugPull) Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if m == nil || m.Env == nil {
		return inspect.AllowAll
	}
	if m.Env.Method == mcp.MethodToolsListChanged && m.Env.IsNotification() {
		return r.listChanged(ctx, s, m)
	}
	res, ok := toolsListResult(m)
	if !ok {
		return inspect.AllowAll
	}
	cat, ok := s.(catalog)
	if !ok {
		return inspect.AllowAll
	}
	for _, raw := range res.Tools {
		var t mcp.Tool
		if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
			continue
		}
		prev, known := cat.ObserveTool(m.Backend, t)
		if !known || prev == session.Fingerprint(t) {
			continue
		}
		reason := fmt.Sprintf("tool %q changed definition mid-session (rug pull)", t.Name)
		if r.onChange == OnRugPullAlert {
			emit(ctx, r.sink, s, audit.Event{
				Type: audit.EventToolsChanged, Backend: m.Backend, Tool: t.Name,
				Rule: NameRugPull, Reason: reason,
				Fields: map[string]any{"prev_fingerprint": prev, "fingerprint": session.Fingerprint(t)},
			})
			continue
		}
		emit(ctx, r.sink, s, audit.Event{
			Type: audit.EventToolsChanged, Backend: m.Backend, Tool: t.Name,
			Rule: NameRugPull, Reason: reason,
			Fields: map[string]any{"prev_fingerprint": prev, "fingerprint": session.Fingerprint(t), "action": OnRugPullKill},
		})
		return inspect.Decision{Verdict: inspect.Kill, Rule: NameRugPull, Reason: reason}
	}
	// Only after a clean pass is the catalog authoritative enough for the
	// policy check to refuse unadvertised tools.
	markCatalogListed(s)
	return inspect.AllowAll
}

// listChanged handles notifications/tools/list_changed. The catalog is
// invalidated so the next tools/list re-fingerprints, but retained
// fingerprints still feed rug-pull comparison: a server cannot escape
// detection by announcing the change first.
func (r *RugPull) listChanged(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if cat, ok := s.(catalog); ok {
		cat.InvalidateTools(m.Backend)
	}
	emit(ctx, r.sink, s, audit.Event{
		Type: audit.EventToolsChanged, Backend: m.Backend, Rule: NameRugPull,
		Reason: "server announced tools/list_changed",
	})
	return inspect.AllowAll
}
