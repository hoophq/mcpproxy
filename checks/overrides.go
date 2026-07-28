package checks

import (
	"context"
	"encoding/json"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
)

// Overrides rewrites the tool catalog the client sees: a tool can be renamed
// (to disambiguate across backends, or to steer model selection) and its
// description replaced (descriptions are prompt input, so operators need to
// own them).
//
// The rewrite is presentation-only. The check records every rename on the
// session, so it can rewrite calls arriving under the exposed name back to
// the real name before they reach the backend, and so the checks that ran
// earlier evaluate the real name via RealToolName.
type Overrides struct {
	byTool map[string]config.ToolOverride
}

// NewOverrides builds the catalog-override check.
func NewOverrides(pol config.Policy) *Overrides {
	return &Overrides{byTool: pol.Overrides}
}

// Name implements inspect.Check.
func (o *Overrides) Name() string { return NameOverrides }

// Inspect implements inspect.Check.
func (o *Overrides) Inspect(_ context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if len(o.byTool) == 0 || m == nil || m.Env == nil {
		return inspect.AllowAll
	}
	if exposed, ok := isToolCall(m); ok {
		o.unrename(s, m, exposed)
		return inspect.AllowAll
	}
	res, ok := toolsListResult(m)
	if !ok {
		return inspect.AllowAll
	}
	o.rewriteCatalog(s, m, res)
	return inspect.AllowAll
}

// rewriteCatalog applies renames and description replacements to the raw
// tool entries, preserving every field the gateway does not model.
func (o *Overrides) rewriteCatalog(s inspect.Session, m *inspect.Msg, res *mcp.ToolsListResult) {
	changed := false
	for i, raw := range res.Tools {
		real := rawName(raw)
		ov, ok := o.byTool[real]
		if !ok || (ov.Name == "" && ov.Description == "") {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			continue
		}
		if ov.Name != "" && ov.Name != real {
			nb, err := json.Marshal(ov.Name)
			if err != nil {
				continue
			}
			fields["name"] = nb
			rememberRename(s, ov.Name, real)
		}
		if ov.Description != "" {
			db, err := json.Marshal(ov.Description)
			if err != nil {
				continue
			}
			fields["description"] = db
		}
		out, err := json.Marshal(fields)
		if err != nil {
			continue
		}
		res.Tools[i] = out
		changed = true
	}
	if !changed {
		return
	}
	// Re-marshal in place so downstream checks and the client both see the
	// rewritten catalog.
	if b, err := json.Marshal(res); err == nil {
		m.Env.Result = b
	}
}

// unrename rewrites params.name from the exposed alias back to the real tool
// name so routing and the backend see what they expect.
func (o *Overrides) unrename(s inspect.Session, m *inspect.Msg, exposed string) {
	real := RealToolName(s, exposed)
	if real == exposed {
		return
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(m.Env.Params, &params); err != nil {
		return
	}
	nb, err := json.Marshal(real)
	if err != nil {
		return
	}
	params["name"] = nb
	if b, err := json.Marshal(params); err == nil {
		m.Env.Params = b
	}
}
