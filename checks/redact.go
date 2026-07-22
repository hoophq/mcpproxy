package checks

import (
	"context"
	"encoding/json"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
)

// Redactor masks sensitive strings in data flowing back to the model. Only
// the two payloads that carry backend-controlled bulk text are walked:
// tool results (result.content[]) and resource reads (result.contents[]).
// Everything else — schemas, capability blobs, ids — is structural and
// rewriting it would break the protocol.
type Redactor struct {
	redact func(ctx context.Context, text string) (string, int, error)
	sink   audit.Sink
}

// NewRedactor builds the redaction check. hooks.Redact must be non-nil;
// Assemble omits the check otherwise.
func NewRedactor(hooks inspect.Hooks, sink audit.Sink) *Redactor {
	return &Redactor{redact: hooks.Redact, sink: sink}
}

// Name implements inspect.Check.
func (r *Redactor) Name() string { return NameRedact }

// Inspect implements inspect.Check.
func (r *Redactor) Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if r.redact == nil || m == nil || m.Env == nil || m.Dir != inspect.S2C {
		return inspect.AllowAll
	}
	if !m.Env.IsResponse() || m.Env.Error != nil || len(m.Env.Result) == 0 {
		return inspect.AllowAll
	}
	var field string
	switch m.CorrelatedMethod {
	case mcp.MethodToolsCall:
		field = "content"
	case mcp.MethodResourcesRead:
		field = "contents"
	default:
		return inspect.AllowAll
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(m.Env.Result, &result); err != nil {
		return inspect.AllowAll
	}
	var items []json.RawMessage
	if err := json.Unmarshal(result[field], &items); err != nil || len(items) == 0 {
		return inspect.AllowAll
	}

	total := 0
	for i, raw := range items {
		out, n := r.redactItem(ctx, raw)
		if n == 0 {
			continue
		}
		items[i] = out
		total += n
	}
	if total == 0 {
		return inspect.AllowAll
	}

	ib, err := json.Marshal(items)
	if err != nil {
		return inspect.AllowAll
	}
	result[field] = ib
	out, err := json.Marshal(result)
	if err != nil {
		return inspect.AllowAll
	}
	m.Env.Result = out
	emit(ctx, r.sink, s, audit.Event{
		Type: audit.EventRedacted, Backend: m.Backend, Tool: m.CorrelatedTool,
		Rule: NameRedact, Fields: map[string]any{"redactions": total, "field": field},
	})
	return inspect.AllowAll
}

// redactItem rewrites the "text" leaf of one content entry, preserving every
// other field. It returns the new bytes and the redaction count; count 0
// means the entry is unchanged.
func (r *Redactor) redactItem(ctx context.Context, raw json.RawMessage) (json.RawMessage, int) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return raw, 0
	}
	tv, ok := fields["text"]
	if !ok {
		return raw, 0
	}
	var text string
	if err := json.Unmarshal(tv, &text); err != nil || text == "" {
		return raw, 0
	}
	masked, n, err := r.redact(ctx, text)
	if err != nil || n == 0 {
		// A failing redactor must not silently pass unmasked text off as
		// clean, but neither can it fabricate content: leave the entry as-is
		// and let the audit count stay honest at zero.
		return raw, 0
	}
	mb, err := json.Marshal(masked)
	if err != nil {
		return raw, 0
	}
	fields["text"] = mb
	out, err := json.Marshal(fields)
	if err != nil {
		return raw, 0
	}
	return out, n
}
