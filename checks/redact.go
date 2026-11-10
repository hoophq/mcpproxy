package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// maxRedactDepth caps the nesting of structuredContent. A deeper value is
// denied, as on a hook error.
const maxRedactDepth = 128

// The reasons a result is withheld. A Redact hook error can quote the text,
// so errRedactHook replaces it: the hook's own error never reaches an event,
// a log line or the client.
var (
	errRedactHook     = errors.New("redaction failed")
	errRedactDepth    = fmt.Errorf("structuredContent nests deeper than %d levels", maxRedactDepth)
	errRedactCanceled = errors.New("redaction canceled")
	errRedactKeys     = errors.New("a result key repeats or differs in case")
	errRedactShape    = errors.New("a result field has an unexpected type")
)

// Redactor masks sensitive strings in tools/call, resources/read and
// tasks/result results: content[].text, content[].resource.text,
// contents[].text and every string value of structuredContent. Object keys
// and other fields are structural, and rewriting them would break the
// protocol. A client that matches keys without case could read a value the
// redactor did not, so a repeated key, or one that only folds to a key read
// here, denies the result. So do a field read here of an unexpected type and
// a Redact hook error: unmasked text never reaches the client.
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
	switch m.CorrelatedMethod {
	case mcp.MethodToolsCall, mcp.MethodResourcesRead, mcp.MethodTasksResult:
	default:
		return inspect.AllowAll
	}

	if _, ok := m.Env.FoldedField(); ok {
		return r.deny(ctx, s, m, errRedactKeys)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(m.Env.Result, &result); err != nil {
		return r.deny(ctx, s, m, errRedactShape)
	}
	if mcp.ExactKeys(m.Env.Result, result, "content", "contents", "structuredContent") != nil {
		return r.deny(ctx, s, m, errRedactKeys)
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
			out, n, err = w.values(raw)
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

	out, err := encode(result)
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

// deny withholds the result. The reason is one of the fixed errRedact* texts.
func (r *Redactor) deny(ctx context.Context, s inspect.Session, m *inspect.Msg, err error) inspect.Decision {
	cause := errRedactHook
	for _, known := range []error{errRedactDepth, errRedactCanceled, errRedactKeys, errRedactShape} {
		if errors.Is(err, known) {
			cause = known
		}
	}
	reason := "result withheld: " + cause.Error()
	emit(ctx, r.sink, s, audit.Event{
		Type: audit.EventToolDenied, Backend: m.Backend, Tool: m.CorrelatedTool,
		Rule: NameRedact, Reason: reason,
	})
	return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameRedact, reason)
}

// walker runs the Redact hook over the strings of one result. Each method
// returns the new bytes and the redaction count; count 0 means the input is
// unchanged. A null value is left as it is; a value of another unexpected type
// fails with errRedactShape.
type walker struct {
	ctx    context.Context
	redact func(ctx context.Context, text string) (string, int, error)
}

// item masks the text leaf of one content entry and the text of its nested
// resource.
func (w *walker) item(raw json.RawMessage) (json.RawMessage, int, error) {
	return w.object(raw, []string{"text", "resource"}, func(fields map[string]json.RawMessage) (int, error) {
		n, err := w.leaf(fields, "text")
		if err != nil {
			return 0, err
		}
		res, ok := fields["resource"]
		if !ok {
			return n, nil
		}
		out, rn, err := w.object(res, []string{"text"}, func(rf map[string]json.RawMessage) (int, error) {
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

// values masks every string value of a JSON value in one pass over its bytes.
// Object keys, numbers and unmasked strings are copied byte for byte.
func (w *walker) values(raw json.RawMessage) (json.RawMessage, int, error) {
	var out, stack []byte
	key := false
	last, total := 0, 0
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '{', '[':
			if len(stack) == maxRedactDepth {
				return nil, 0, errRedactDepth
			}
			stack = append(stack, c)
			key = c == '{'
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case ',':
			key = len(stack) > 0 && stack[len(stack)-1] == '{'
		case ':':
			key = false
		case '"':
			end := stringEnd(raw, i)
			if !key {
				masked, n, err := w.str(raw[i:end])
				if err != nil {
					return nil, 0, err
				}
				if n > 0 {
					out = append(append(out, raw[last:i]...), masked...)
					last = end
					total += n
				}
			}
			i = end - 1
		}
	}
	if total == 0 {
		return raw, 0, nil
	}
	return append(out, raw[last:]...), total, nil
}

// stringEnd returns the index just past the JSON string that opens at raw[i].
func stringEnd(raw []byte, i int) int {
	for j := i + 1; j < len(raw); j++ {
		switch raw[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(raw)
}

// array applies fn to each element of a JSON array.
func (w *walker) array(raw json.RawMessage, fn func(json.RawMessage) (json.RawMessage, int, error)) (json.RawMessage, int, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, 0, errRedactShape
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
	out, err := encode(elems)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// object decodes a JSON object, lets fn rewrite its fields, and encodes it
// again when fn masked something. keys are the fields fn reads.
func (w *walker) object(raw json.RawMessage, keys []string, fn func(map[string]json.RawMessage) (int, error)) (json.RawMessage, int, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, 0, errRedactShape
	}
	if fields == nil {
		return raw, 0, nil
	}
	if mcp.ExactKeys(raw, fields, keys...) != nil {
		return nil, 0, errRedactKeys
	}
	n, err := fn(fields)
	if err != nil {
		return nil, 0, err
	}
	if n == 0 {
		return raw, 0, nil
	}
	out, err := encode(fields)
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
	out, n, err := w.str(v)
	if err != nil || n == 0 {
		return 0, err
	}
	fields[key] = out
	return n, nil
}

// str runs the hook over one JSON string.
func (w *walker) str(raw json.RawMessage) (json.RawMessage, int, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, 0, errRedactShape
	}
	if text == "" {
		return raw, 0, nil
	}
	if w.ctx.Err() != nil {
		return nil, 0, errRedactCanceled
	}
	masked, n, err := w.redact(w.ctx, text)
	if err != nil {
		return nil, 0, errRedactHook
	}
	if w.ctx.Err() != nil {
		return nil, 0, errRedactCanceled
	}
	if n <= 0 {
		return raw, 0, nil
	}
	out, err := encode(masked)
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}

// encode marshals v without HTML escaping, so keys and strings already on the
// wire keep their bytes.
func encode(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
