// Package optimizer trims a tools/list response down to the tools that matter
// for the session's stated purpose.
//
// Context windows are finite and MCP servers are generous: a handful of
// aggregated backends advertises two hundred tools, most of them noise for any
// given task. Ranking tools against a purpose string and keeping the top K
// shrinks the prompt. It also shrinks the attack surface, since a tool absent
// from the catalog is a tool the model cannot be steered into calling.
//
// The default scorer is lexical: no network, no model, and deterministic under
// test. Swap in an embedding-backed Scorer when semantic recall matters more
// than determinism; the Check does not care which it got.
package optimizer

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
)

// Scorer ranks a tool's relevance to a purpose. Higher is more relevant.
// Scores are compared only against each other, so any monotonic scale works.
// Implementations must be safe for concurrent use.
//
// The lexical default stays simple. An embedding implementation would cache
// purpose and tool vectors and return cosine similarity here; nothing else in
// this package changes.
type Scorer interface {
	Score(purpose, toolName, toolDesc string) float64
}

// Optimizer is an inspect.Check that filters S2C tools/list results.
type Optimizer struct {
	topK    int
	purpose string
	sink    audit.Sink
	scorer  Scorer
}

// New builds the filter. A nil scorer selects the built-in lexical scorer; a
// nil sink discards audit events. TopK <= 0 or an empty purpose makes the
// check a pass-through, so a caller can install it in every pipeline.
func New(cfg config.Optimizer, sink audit.Sink, scorer Scorer) *Optimizer {
	if scorer == nil {
		scorer = Lexical{}
	}
	if sink == nil {
		sink = audit.Discard
	}
	return &Optimizer{
		topK:    cfg.TopK,
		purpose: cfg.Purpose,
		sink:    sink,
		scorer:  scorer,
	}
}

// Name implements inspect.Check.
func (o *Optimizer) Name() string { return "optimizer" }

// Enabled reports whether the check will filter anything.
func (o *Optimizer) Enabled() bool { return o.topK > 0 && strings.TrimSpace(o.purpose) != "" }

// Inspect implements inspect.Check. It rewrites tools/list results in place
// and returns Allow every time: relevance is a hint, not a policy verdict, so
// a scoring mistake cannot break a session.
func (o *Optimizer) Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if !o.Enabled() || m.Dir != inspect.S2C || m.Env == nil {
		return inspect.AllowAll
	}
	// Only tools/list responses carry a catalog. Correlation is the gateway's
	// job; an uncorrelated response is not ours to touch.
	if m.CorrelatedMethod != mcp.MethodToolsList || m.Env.Result == nil {
		return inspect.AllowAll
	}

	var res mcp.ToolsListResult
	if err := json.Unmarshal(m.Env.Result, &res); err != nil {
		// Malformed or non-standard payload: pass it through untouched
		// rather than corrupt a response we do not understand.
		return inspect.AllowAll
	}
	total := len(res.Tools)
	if total <= o.topK {
		return inspect.AllowAll
	}

	kept, dropped := o.rank(res.Tools)
	if len(dropped) == 0 {
		return inspect.AllowAll
	}
	res.Tools = kept

	// Re-marshal only on success. A failure here leaves m.Env.Result as it
	// was, so the client still gets the full catalog.
	raw, err := json.Marshal(res)
	if err != nil {
		return inspect.AllowAll
	}
	m.Env.Result = raw

	o.sink.Emit(ctx, audit.Event{
		Time:    time.Now(),
		Type:    audit.EventToolsListed,
		Session: s.ID(),
		User:    s.Identity().Subject,
		Backend: m.Backend,
		Rule:    o.Name(),
		Reason:  "tools filtered by session purpose",
		Fields: map[string]any{
			"purpose":       o.purpose,
			"top_k":         o.topK,
			"tools_total":   total,
			"tools_kept":    len(kept),
			"tools_dropped": len(dropped),
			"dropped":       dropped,
		},
	})
	return inspect.AllowAll
}

// rank scores every entry and returns the top-K raw entries in their
// original catalog order, plus the names of the entries removed.
//
// Preserving catalog order matters: clients and users read tools/list output,
// and reshuffling it on every call would churn that view for no gain.
func (o *Optimizer) rank(tools []json.RawMessage) (kept []json.RawMessage, dropped []string) {
	names := make([]string, len(tools))
	scores := make([]float64, len(tools))
	order := make([]int, len(tools))
	for i, raw := range tools {
		var t mcp.Tool
		// An entry we cannot parse scores as an empty tool, so it sinks to
		// the bottom instead of getting a free pass into the kept set.
		_ = json.Unmarshal(raw, &t)
		names[i] = t.Name
		scores[i] = o.scorer.Score(o.purpose, t.Name, t.Description)
		order[i] = i
	}

	// Score desc, catalog index asc. Ties fall back to the server's own
	// ordering, which keeps the output stable across calls.
	slices.SortFunc(order, func(a, b int) int {
		if c := cmp.Compare(scores[b], scores[a]); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})

	keep := make([]bool, len(tools))
	for _, i := range order[:o.topK] {
		keep[i] = true
	}

	kept = make([]json.RawMessage, 0, o.topK)
	for i, raw := range tools {
		if keep[i] {
			kept = append(kept, raw)
		} else {
			dropped = append(dropped, names[i])
		}
	}
	return kept, dropped
}

// Lexical is the built-in Scorer: for each purpose token it takes the best
// match found anywhere in the tool's name or description, weighting name
// matches above description matches and exact matches above prefix matches.
//
// Best match per token beats raw term frequency. A description repeating
// "issue" eleven times is chatty, and no more relevant than one that says it
// once. Taking the max per purpose token turns the score into a coverage
// measure: how much of the purpose the tool addresses.
//
// Matching is lexical, with no embeddings and no model call. It ranks
// "list_issues" above "get_weather" for the purpose "github issues", which is
// the bar for a default that must stay off the network.
type Lexical struct{}

// Score implements Scorer. The result is in [0, nameExact], normalized by
// purpose length so verbose and terse purposes stay comparable.
func (Lexical) Score(purpose, toolName, toolDesc string) float64 {
	pTokens := tokenize(purpose)
	if len(pTokens) == 0 {
		return 0
	}
	nameTokens := tokenize(toolName)
	descTokens := tokenize(toolDesc)
	if len(nameTokens) == 0 && len(descTokens) == 0 {
		return 0
	}

	var total float64
	for _, p := range pTokens {
		best := bestMatch(p, nameTokens, nameExact, namePrefix)
		if best < nameExact {
			if d := bestMatch(p, descTokens, descExact, descPrefix); d > best {
				best = d
			}
		}
		total += best
	}
	return total / float64(len(pTokens))
}

// bestMatch scores one purpose token against one token list, returning exact
// for an equal (post-stem) token and prefix for a prefix relationship.
func bestMatch(p string, tokens []string, exact, prefix float64) float64 {
	ps := stem(p)
	var best float64
	for _, t := range tokens {
		ts := stem(t)
		switch {
		case ps == ts:
			return exact
		// Prefix in either direction covers the morphology the stemmer
		// misses: "repo"/"repository", "comment"/"commenting". Bounded by
		// minPrefix so "id" does not match half the catalog.
		case len(ps) >= minPrefix && (strings.HasPrefix(ts, ps) || strings.HasPrefix(ps, ts)):
			if prefix > best {
				best = prefix
			}
		}
	}
	return best
}

// stem folds the two plural forms that appear in tool names, so
// "issue"/"issues" and "repository"/"repositories" unify. A real stemmer buys
// nothing here: tool names are short English nouns and verbs in these forms.
func stem(t string) string {
	switch {
	case len(t) > 4 && strings.HasSuffix(t, "ies"):
		return t[:len(t)-3] + "y"
	case len(t) > 3 && strings.HasSuffix(t, "s") && !strings.HasSuffix(t, "ss"):
		return t[:len(t)-1]
	}
	return t
}

const (
	// Name matches dominate description matches. Somebody curated the tool
	// name; descriptions ramble and mention adjacent concepts in passing.
	nameExact  = 1.0
	namePrefix = 0.6
	descExact  = 0.35
	descPrefix = 0.2
	// minPrefix keeps short tokens ("id", "to", "get") from matching half
	// the catalog through the prefix rule.
	minPrefix = 4
)

// tokenize lowercases and splits on anything that is not a letter or digit,
// which covers snake_case, kebab-case, and dotted namespaces. camelCase
// boundaries are split too, so "listIssues" yields "list", "issues".
func tokenize(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	prev := rune(0)
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			// Boundary only after a lowercase/digit, so "HTTPServer" yields
			// "httpserver" rather than nine one-letter tokens.
			if unicode.IsLower(prev) || unicode.IsDigit(prev) {
				flush()
			}
			cur.WriteRune(unicode.ToLower(r))
		case unicode.IsLower(r) || unicode.IsDigit(r):
			cur.WriteRune(r)
		default:
			flush()
		}
		prev = r
	}
	flush()
	return out
}
