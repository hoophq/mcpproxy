package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
)

// AuditTap is the terminal check: it records what actually survived the
// pipeline and always allows. Sitting last means the audit trail reflects
// post-override, post-redaction reality rather than what the client sent.
//
// Tool arguments are recorded as a SHA-256 digest plus a byte count, never
// verbatim — arguments routinely carry credentials and customer data, and an
// audit log is a lower-trust store than the session it describes. The digest
// still proves two calls were identical and lets a reviewer match a recorded
// payload against the log.
type AuditTap struct {
	sink audit.Sink
}

// NewAuditTap builds the terminal audit check.
func NewAuditTap(sink audit.Sink) *AuditTap { return &AuditTap{sink: sink} }

// Name implements inspect.Check.
func (a *AuditTap) Name() string { return NameAuditTap }

// Inspect implements inspect.Check.
func (a *AuditTap) Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if a.sink == nil || m == nil || m.Env == nil {
		return inspect.AllowAll
	}
	if exposed, ok := isToolCall(m); ok {
		a.toolCall(ctx, s, m, exposed)
		return inspect.AllowAll
	}
	if res, ok := toolsListResult(m); ok {
		a.toolsListed(ctx, s, m, res)
	}
	// initialize is audited by the gateway itself (it owns the fan-out and
	// the merged server info); duplicating it here would double-count.
	return inspect.AllowAll
}

func (a *AuditTap) toolCall(ctx context.Context, s inspect.Session, m *inspect.Msg, exposed string) {
	var p mcp.ToolsCallParams
	_ = json.Unmarshal(m.Env.Params, &p)
	fields := map[string]any{
		"args_bytes":  len(p.Arguments),
		"args_sha256": digest(p.Arguments),
	}
	real := RealToolName(s, exposed)
	if real != exposed {
		fields["exposed_tool"] = exposed
	}
	emit(ctx, a.sink, s, audit.Event{
		Type: audit.EventToolCall, Backend: m.Backend, Tool: real, Fields: fields,
	})
}

func (a *AuditTap) toolsListed(ctx context.Context, s inspect.Session, m *inspect.Msg, res *mcp.ToolsListResult) {
	names := make([]string, 0, len(res.Tools))
	for _, raw := range res.Tools {
		if n := rawName(raw); n != "" {
			names = append(names, n)
		}
	}
	emit(ctx, a.sink, s, audit.Event{
		Type: audit.EventToolsListed, Backend: m.Backend,
		Fields: map[string]any{"count": len(res.Tools), "names": names},
	})
}

// digest hashes tool arguments. Absent arguments hash to the empty string so
// a reviewer can tell "no arguments" from "arguments withheld".
func digest(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
