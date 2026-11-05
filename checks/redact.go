package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// redactReason is what the client reads when a result is withheld. The hook
// error goes to the audit event only, because it can quote the text.
const redactReason = "result withheld: redaction failed"

// Redactor masks sensitive strings in tools/call and resources/read results:
// content[].text, content[].resource.text, contents[].text and every string
// of structuredContent. Other fields are structural, and rewriting them would
// break the protocol. A Redact hook error denies the result, so unmasked text
// never reaches the client.
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
	if m.CorrelatedMethod != mcp.MethodToolsCall && m.CorrelatedMethod != mcp.MethodResourcesRead {
		return inspect.AllowAll
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(m.Env.Result, &result); err != nil {
		return inspect.AllowAll
	}

	w := &walker{ctx: ctx, redact: r.redact}
	total := 0
	var masked []string
	for _, field := range []string{"content", "contents", "structuredContent"} {
		raw, ok := result[field]
		if !ok {
			continue
		}
		var out json.RawMessage
		var n int
		var err error
		if field == "structuredContent" {
			out, n, err = w.value(raw)
		} else {
			out, n, err = w.array(raw, w.item)
		}
		if err != nil {
			return r.deny(ctx, s, m, err)
		}
		if n > 0 {
			result[field] = out
			total += n
			masked = append(masked, field)
		}
	}
	if total == 0 {
		return inspect.AllowAll
	}

	out, err := json.Marshal(result)
	if err != nil {
		return r.deny(ctx, s, m, err)
	}
	m.Env.Result = out
	emit(ctx, r.sink, s, audit.Event{
		Type: audit.EventRedacted, Backend: m.Backend, Tool: m.CorrelatedTool,
		Rule: NameRedact, Fields: map[string]any{"redactions": total, "field": strings.Join(masked, ",")},
	})
	return inspect.AllowAll
}

func (r *Redactor) deny(ctx context.Context, s inspect.Session, m *inspect.Msg, err error) inspect.Decision {
	emit(ctx, r.sink, s, audit.Event{
		Type: audit.EventToolDenied, Backend: m.Backend, Tool: m.CorrelatedTool,
		Rule: NameRedact, Reason: redactReason + ": " + err.Error(),
	})
	return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameRedact, redactReason)
}

// walker runs the Redact hook over the strings of one result. Each method
// returns the new bytes and the redaction count; count 0 means the input is
// unchanged. A value of an unexpected shape carries no text leaf and is left
// as it is.
type walker struct {
	ctx    context.Context
	redact func(ctx context.Context, text string) (string, int, error)
}

// item masks the text leaf of one content entry and the text of its nested
// resource.
func (w *walker) item(raw json.RawMessage) (json.RawMessage, int, error) {
	return w.object(raw, func(fields map[string]json.RawMessage) (int, error) {
		n, err := w.leaf(fields, "text")
		if err != nil {
			return 0, err
		}
		res, ok := fields["resource"]
		if !ok {
			return n, nil
		}
		out, rn, err := w.object(res, func(rf map[string]json.RawMessage) (int, error) {
			return w.leaf(rf, "text")
		})
		if err != nil {
			return 0, err
		}
		if rn > 0 {
			fields["resource"] = out
		}
		return n + rn, nil
	})
}

// value masks every string in a JSON value, at any depth. Object keys are
// structure.
func (w *walker) value(raw json.RawMessage) (json.RawMessage, int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, 0, nil
	}
	switch trimmed[0] {
	case '"':
		return w.str(raw)
	case '[':
		return w.array(raw, w.value)
	case '{':
		return w.object(raw, func(fields map[string]json.RawMessage) (int, error) {
			total := 0
			for k, v := range fields {
				n, err := w.set(fields, k, v, w.value)
				if err != nil {
					return 0, err
				}
				total += n
			}
			return total, nil
		})
	}
	return raw, 0, nil
}

// array applies fn to each element of a JSON array.
func (w *walker) array(raw json.RawMessage, fn func(json.RawMessage) (json.RawMessage, int, error)) (json.RawMessage, int, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return raw, 0, nil
	}
	total := 0
	for i, v := range elems {
		out, n, err := fn(v)
		if err != nil {
			return nil, 0, err
		}
		if n > 0 {
			elems[i] = out
			total += n
		}
	}
	if total == 0 {
		return raw, 0, nil
	}
	out, err := json.Marshal(elems)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// object decodes a JSON object, lets fn rewrite its fields, and encodes it
// again when fn masked something.
func (w *walker) object(raw json.RawMessage, fn func(map[string]json.RawMessage) (int, error)) (json.RawMessage, int, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return raw, 0, nil
	}
	n, err := fn(fields)
	if err != nil {
		return nil, 0, err
	}
	if n == 0 {
		return raw, 0, nil
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}

// leaf masks fields[key] when it is a string.
func (w *walker) leaf(fields map[string]json.RawMessage, key string) (int, error) {
	v, ok := fields[key]
	if !ok {
		return 0, nil
	}
	return w.set(fields, key, v, w.str)
}

// set stores fn(v) under key when fn masked something.
func (w *walker) set(fields map[string]json.RawMessage, key string, v json.RawMessage, fn func(json.RawMessage) (json.RawMessage, int, error)) (int, error) {
	out, n, err := fn(v)
	if err != nil || n == 0 {
		return 0, err
	}
	fields[key] = out
	return n, nil
}

// str runs the hook over one JSON string.
func (w *walker) str(raw json.RawMessage) (json.RawMessage, int, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil || text == "" {
		return raw, 0, nil
	}
	masked, n, err := w.redact(w.ctx, text)
	if err != nil {
		return nil, 0, err
	}
	if n <= 0 {
		return raw, 0, nil
	}
	out, err := json.Marshal(masked)
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}
