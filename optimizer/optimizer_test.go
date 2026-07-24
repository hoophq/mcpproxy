package optimizer

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

var _ inspect.Check = (*Optimizer)(nil)

// fakeSession is the minimum inspect.Session the optimizer touches.
type fakeSession struct{ id string }

func (f fakeSession) ID() string { return f.id }
func (f fakeSession) Identity() inspect.Identity {
	return inspect.Identity{Subject: "ana@example.com"}
}
func (fakeSession) ToolKnown(string, string) bool { return true }
func (fakeSession) Counter(string) *int64         { var n int64; return &n }
func (fakeSession) Meta(string, func() any) any   { return nil }

// recordSink captures emitted events.
type recordSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordSink) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordSink) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

// catalog is the test corpus: four GitHub-ish tools and four unrelated ones.
var catalog = []mcp.Tool{
	{Name: "get_weather", Description: "Current weather conditions for a city."},
	{Name: "list_issues", Description: "List issues in a GitHub repository."},
	{Name: "send_email", Description: "Send an email message to a recipient."},
	{Name: "create_issue", Description: "Open a new GitHub issue with a title and body."},
	{Name: "weather_forecast", Description: "Ten-day forecast for a location."},
	{Name: "comment_on_issue", Description: "Add a comment to an existing GitHub issue."},
	{Name: "convert_currency", Description: "Convert an amount between currencies."},
	{Name: "search_flights", Description: "Find flights between two airports."},
}

// toolsListResponse builds an S2C tools/list response message.
func toolsListResponse(t *testing.T, tools []mcp.Tool) *jsonrpc.Message {
	t.Helper()
	raws := make([]json.RawMessage, len(tools))
	for i, tool := range tools {
		b, err := json.Marshal(tool)
		if err != nil {
			t.Fatalf("marshal tool: %v", err)
		}
		raws[i] = b
	}
	result, err := json.Marshal(mcp.ToolsListResult{Tools: raws, NextCursor: "next-page"})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return &jsonrpc.Message{JSONRPC: "2.0", ID: jsonrpc.ID{Raw: json.RawMessage("1")}, Result: result}
}

func listMsg(t *testing.T, tools []mcp.Tool) *inspect.Msg {
	t.Helper()
	return &inspect.Msg{
		Dir:              inspect.S2C,
		Backend:          "github",
		Env:              toolsListResponse(t, tools),
		CorrelatedMethod: mcp.MethodToolsList,
	}
}

// toolNames decodes the (possibly filtered) result back into names.
func toolNames(t *testing.T, m *inspect.Msg) []string {
	t.Helper()
	var res mcp.ToolsListResult
	if err := json.Unmarshal(m.Env.Result, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	out := make([]string, len(res.Tools))
	for i, raw := range res.Tools {
		var tool mcp.Tool
		if err := json.Unmarshal(raw, &tool); err != nil {
			t.Fatalf("unmarshal tool: %v", err)
		}
		out[i] = tool.Name
	}
	return out
}

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestKeepsTopKRelevant(t *testing.T) {
	sink := &recordSink{}
	o := New(config.Optimizer{TopK: 3, Purpose: "github issues"}, sink, nil)

	m := listMsg(t, catalog)
	if dec := o.Inspect(context.Background(), fakeSession{id: "s1"}, m); dec.Verdict != inspect.Allow {
		t.Fatalf("verdict = %v, want Allow (relevance is a hint, never a policy verdict)", dec.Verdict)
	}

	names := toolNames(t, m)
	if len(names) != 3 {
		t.Fatalf("kept %d tools (%v), want 3", len(names), names)
	}
	for _, want := range []string{"list_issues", "create_issue", "comment_on_issue"} {
		if !contains(names, want) {
			t.Errorf("issue tool %q was dropped; kept %v", want, names)
		}
	}
	for _, unwanted := range []string{"get_weather", "weather_forecast", "search_flights", "convert_currency"} {
		if contains(names, unwanted) {
			t.Errorf("irrelevant tool %q survived; kept %v", unwanted, names)
		}
	}
}

// The kept tools must stay in the server's original catalog order.
func TestPreservesCatalogOrder(t *testing.T) {
	o := New(config.Optimizer{TopK: 3, Purpose: "github issues"}, nil, nil)
	m := listMsg(t, catalog)
	o.Inspect(context.Background(), fakeSession{id: "s1"}, m)

	got := toolNames(t, m)
	want := []string{"list_issues", "create_issue", "comment_on_issue"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// Filtering must not corrupt the envelope: sibling result fields survive and
// the message still marshals to parseable JSON-RPC.
func TestEnvelopeStaysValid(t *testing.T) {
	o := New(config.Optimizer{TopK: 2, Purpose: "github issues"}, nil, nil)
	m := listMsg(t, catalog)
	o.Inspect(context.Background(), fakeSession{id: "s1"}, m)

	raw, err := m.Env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reparsed, err := jsonrpc.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reparsed.IsResponse() {
		t.Error("filtered message is no longer a response")
	}
	if reparsed.ID.Key() != "1" {
		t.Errorf("id = %q, want 1", reparsed.ID.Key())
	}

	var res mcp.ToolsListResult
	if err := json.Unmarshal(reparsed.Result, &res); err != nil {
		t.Fatalf("result is not a tools/list payload: %v", err)
	}
	if len(res.Tools) != 2 {
		t.Errorf("tools = %d, want 2", len(res.Tools))
	}
	if res.NextCursor != "next-page" {
		t.Errorf("nextCursor = %q, want next-page (sibling fields must survive)", res.NextCursor)
	}
	// Surviving entries must be byte-identical to what the server sent:
	// unknown fields on a tool are not ours to drop.
	var tool struct {
		Name        string          `json:"name"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if err := json.Unmarshal(res.Tools[0], &tool); err != nil {
		t.Fatalf("tool entry: %v", err)
	}
	if tool.Name == "" {
		t.Error("tool entry lost its name")
	}
}

func TestPassThrough(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Optimizer
		msg  func(*testing.T) *inspect.Msg
	}{
		{"topk zero", config.Optimizer{TopK: 0, Purpose: "github issues"},
			func(t *testing.T) *inspect.Msg { return listMsg(t, catalog) }},
		{"topk negative", config.Optimizer{TopK: -1, Purpose: "github issues"},
			func(t *testing.T) *inspect.Msg { return listMsg(t, catalog) }},
		{"empty purpose", config.Optimizer{TopK: 2},
			func(t *testing.T) *inspect.Msg { return listMsg(t, catalog) }},
		{"blank purpose", config.Optimizer{TopK: 2, Purpose: "   "},
			func(t *testing.T) *inspect.Msg { return listMsg(t, catalog) }},
		{"topk exceeds catalog", config.Optimizer{TopK: 99, Purpose: "github issues"},
			func(t *testing.T) *inspect.Msg { return listMsg(t, catalog) }},
		{"c2s direction", config.Optimizer{TopK: 2, Purpose: "github issues"},
			func(t *testing.T) *inspect.Msg {
				m := listMsg(t, catalog)
				m.Dir = inspect.C2S
				return m
			}},
		{"not a tools/list response", config.Optimizer{TopK: 2, Purpose: "github issues"},
			func(t *testing.T) *inspect.Msg {
				m := listMsg(t, catalog)
				m.CorrelatedMethod = mcp.MethodToolsCall
				return m
			}},
		{"uncorrelated response", config.Optimizer{TopK: 2, Purpose: "github issues"},
			func(t *testing.T) *inspect.Msg {
				m := listMsg(t, catalog)
				m.CorrelatedMethod = ""
				return m
			}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordSink{}
			o := New(tc.cfg, sink, nil)
			m := tc.msg(t)
			before := append([]byte(nil), m.Env.Result...)

			if dec := o.Inspect(context.Background(), fakeSession{id: "s1"}, m); dec.Verdict != inspect.Allow {
				t.Fatalf("verdict = %v, want Allow", dec.Verdict)
			}
			if string(m.Env.Result) != string(before) {
				t.Errorf("result mutated in pass-through mode:\n got %s\nwant %s", m.Env.Result, before)
			}
			if n := len(sink.all()); n != 0 {
				t.Errorf("emitted %d events in pass-through mode, want 0", n)
			}
		})
	}
}

// A payload we cannot parse must pass through untouched rather than be
// replaced by something we guessed at.
func TestMalformedResultPassesThrough(t *testing.T) {
	o := New(config.Optimizer{TopK: 1, Purpose: "github issues"}, nil, nil)
	m := &inspect.Msg{
		Dir:              inspect.S2C,
		Env:              &jsonrpc.Message{JSONRPC: "2.0", Result: json.RawMessage(`"not an object"`)},
		CorrelatedMethod: mcp.MethodToolsList,
	}
	if dec := o.Inspect(context.Background(), fakeSession{id: "s1"}, m); dec.Verdict != inspect.Allow {
		t.Fatalf("verdict = %v, want Allow", dec.Verdict)
	}
	if string(m.Env.Result) != `"not an object"` {
		t.Errorf("result = %s, want untouched", m.Env.Result)
	}
}

func TestNilEnvelopeIsSafe(t *testing.T) {
	o := New(config.Optimizer{TopK: 1, Purpose: "github issues"}, nil, nil)
	m := &inspect.Msg{Dir: inspect.S2C, CorrelatedMethod: mcp.MethodToolsList}
	if dec := o.Inspect(context.Background(), fakeSession{id: "s1"}, m); dec.Verdict != inspect.Allow {
		t.Fatalf("verdict = %v, want Allow", dec.Verdict)
	}
}

func TestAuditEvent(t *testing.T) {
	sink := &recordSink{}
	o := New(config.Optimizer{TopK: 3, Purpose: "github issues"}, sink, nil)
	o.Inspect(context.Background(), fakeSession{id: "sess-42"}, listMsg(t, catalog))

	events := sink.all()
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Type != audit.EventToolsListed {
		t.Errorf("type = %s, want %s", ev.Type, audit.EventToolsListed)
	}
	if ev.Session != "sess-42" {
		t.Errorf("session = %q, want sess-42", ev.Session)
	}
	if ev.User != "ana@example.com" {
		t.Errorf("user = %q", ev.User)
	}
	if ev.Backend != "github" {
		t.Errorf("backend = %q, want github", ev.Backend)
	}
	if ev.Rule != "optimizer" {
		t.Errorf("rule = %q, want optimizer", ev.Rule)
	}
	if ev.Fields["tools_total"] != len(catalog) {
		t.Errorf("tools_total = %v, want %d", ev.Fields["tools_total"], len(catalog))
	}
	if ev.Fields["tools_kept"] != 3 {
		t.Errorf("tools_kept = %v, want 3", ev.Fields["tools_kept"])
	}
	if ev.Fields["tools_dropped"] != len(catalog)-3 {
		t.Errorf("tools_dropped = %v, want %d", ev.Fields["tools_dropped"], len(catalog)-3)
	}
	dropped, ok := ev.Fields["dropped"].([]string)
	if !ok || len(dropped) != len(catalog)-3 {
		t.Fatalf("dropped = %v, want %d names", ev.Fields["dropped"], len(catalog)-3)
	}
	if !contains(dropped, "get_weather") {
		t.Errorf("dropped list %v missing get_weather", dropped)
	}

	// The event must survive JSON encoding: it goes to the WAL as JSONL.
	if _, err := json.Marshal(ev); err != nil {
		t.Errorf("audit event is not JSON-encodable: %v", err)
	}
}

// A custom Scorer must fully control ranking; that is the seam an embedding
// provider plugs into.
func TestCustomScorer(t *testing.T) {
	// Reverse the lexical intuition: rank weather above everything.
	o := New(config.Optimizer{TopK: 2, Purpose: "github issues"}, nil,
		scorerFunc(func(_, name, _ string) float64 {
			if strings.Contains(name, "weather") {
				return 100
			}
			return 0
		}))

	m := listMsg(t, catalog)
	o.Inspect(context.Background(), fakeSession{id: "s1"}, m)

	names := toolNames(t, m)
	want := []string{"get_weather", "weather_forecast"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("kept %v, want %v — custom scorer was not consulted", names, want)
	}
}

type scorerFunc func(purpose, name, desc string) float64

func (f scorerFunc) Score(purpose, name, desc string) float64 { return f(purpose, name, desc) }

// Ties must break on catalog order, not on map iteration.
func TestDeterministicTieBreak(t *testing.T) {
	o := New(config.Optimizer{TopK: 2, Purpose: "github issues"}, nil,
		scorerFunc(func(string, string, string) float64 { return 1 }))

	var first []string
	for range 20 {
		m := listMsg(t, catalog)
		o.Inspect(context.Background(), fakeSession{id: "s1"}, m)
		got := toolNames(t, m)
		if first == nil {
			first = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("non-deterministic selection: %v then %v", first, got)
		}
	}
	want := []string{catalog[0].Name, catalog[1].Name}
	if strings.Join(first, ",") != strings.Join(want, ",") {
		t.Errorf("all-equal scores kept %v, want the first two %v", first, want)
	}
}

func TestLexicalScorer(t *testing.T) {
	s := Lexical{}
	tests := []struct {
		name           string
		purpose        string
		hiName, hiDesc string
		loName, loDesc string
	}{
		{"issue beats weather", "github issues",
			"list_issues", "List issues in a GitHub repository.",
			"get_weather", "Current weather conditions."},
		{"name outweighs description", "issues",
			"issues_search", "Search.",
			"search", "Find issues maybe."},
		{"camelCase tokenizes", "list issues",
			"listIssues", "",
			"deleteBranch", ""},
		{"substring morphology", "repository",
			"repositories_list", "",
			"weather_now", ""},
		{"dotted namespace", "github issues",
			"github.issues.list", "",
			"weather.now", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hi := s.Score(tc.purpose, tc.hiName, tc.hiDesc)
			lo := s.Score(tc.purpose, tc.loName, tc.loDesc)
			if hi <= lo {
				t.Errorf("score(%s)=%v not greater than score(%s)=%v", tc.hiName, hi, tc.loName, lo)
			}
		})
	}

	if got := s.Score("", "list_issues", "issues"); got != 0 {
		t.Errorf("empty purpose scored %v, want 0", got)
	}
	if got := s.Score("github issues", "", ""); got != 0 {
		t.Errorf("empty tool scored %v, want 0", got)
	}
	// Short purpose tokens must not fire the substring bonus, or "id" would
	// match half the catalog.
	if got := s.Score("id", "validate_identity", ""); got != 0 {
		t.Errorf("short token %q matched via substring (score %v), want 0", "id", got)
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"list_issues", []string{"list", "issues"}},
		{"listIssues", []string{"list", "issues"}},
		{"github.issues.list", []string{"github", "issues", "list"}},
		{"kebab-case-name", []string{"kebab", "case", "name"}},
		{"HTTPServer", []string{"httpserver"}},
		{"get2Things", []string{"get2", "things"}},
		{"", nil},
		{"   ", nil},
	}
	for _, tc := range tests {
		got := tokenize(tc.in)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("tokenize(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestEnabled(t *testing.T) {
	tests := []struct {
		cfg  config.Optimizer
		want bool
	}{
		{config.Optimizer{TopK: 5, Purpose: "x"}, true},
		{config.Optimizer{TopK: 0, Purpose: "x"}, false},
		{config.Optimizer{TopK: 5}, false},
		{config.Optimizer{TopK: 5, Purpose: " \t "}, false},
	}
	for _, tc := range tests {
		if got := New(tc.cfg, nil, nil).Enabled(); got != tc.want {
			t.Errorf("Enabled(%+v) = %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

// A nil sink must be tolerated: the optimizer is useful without auditing.
func TestNilSinkAndScorer(t *testing.T) {
	o := New(config.Optimizer{TopK: 2, Purpose: "github issues"}, nil, nil)
	m := listMsg(t, catalog)
	if dec := o.Inspect(context.Background(), fakeSession{id: "s1"}, m); dec.Verdict != inspect.Allow {
		t.Fatalf("verdict = %v, want Allow", dec.Verdict)
	}
	if n := len(toolNames(t, m)); n != 2 {
		t.Errorf("kept %d, want 2", n)
	}
}
