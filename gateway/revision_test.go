package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// req builds a POST carrying body, with each header pair applied in order.
func req(t *testing.T, body string, headers ...string) (*jsonrpc.Message, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	env, err := jsonrpc.Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return env, httptest.NewRecorder(), r
}

func TestClassifyLegacyWithoutModernSignal(t *testing.T) {
	// The overwhelmingly common case: a 2025-era client sends neither the
	// version header nor _meta. It must reach the session path untouched.
	env, _, r := req(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	rev, errMsg := classify(r, env)
	if rev != mcp.RevisionLegacy || errMsg != nil {
		t.Fatalf("got rev=%v err=%v, want legacy/nil", rev, errMsg)
	}
}

func TestClassifyInitializeIsAlwaysLegacy(t *testing.T) {
	// A forged Modern _meta on an initialize must not route to a path that
	// assumes there is no handshake.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	env, _, r := req(t, body, mcp.HeaderProtocolVersion, mcp.VersionModern)
	rev, errMsg := classify(r, env)
	if rev != mcp.RevisionLegacy || errMsg != nil {
		t.Fatalf("got rev=%v err=%v, want legacy/nil", rev, errMsg)
	}
}

func TestClassifyModernFromMetaAndHeader(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	env, _, r := req(t, body,
		mcp.HeaderProtocolVersion, mcp.VersionModern,
		mcp.HeaderMethod, "tools/list")
	rev, errMsg := classify(r, env)
	if rev != mcp.RevisionModern || errMsg != nil {
		t.Fatalf("got rev=%v err=%v, want modern/nil", rev, errMsg)
	}
}

func TestClassifyHeaderBodyDisagreementRejected(t *testing.T) {
	// A load balancer routing on the header and a server executing on the
	// body would disagree about this request; it must not be served.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	env, _, r := req(t, body, mcp.HeaderProtocolVersion, "2025-11-25")
	_, errMsg := classify(r, env)
	if errMsg == nil || errMsg.Error.Code != mcp.CodeHeaderMismatch {
		t.Fatalf("got %v, want -32020 header mismatch", errMsg)
	}
}

func TestClassifyModernMissingVersionHeader(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	env, _, r := req(t, body)
	_, errMsg := classify(r, env)
	if errMsg == nil || errMsg.Error.Code != mcp.CodeHeaderMismatch {
		t.Fatalf("got %v, want -32020 for missing version header", errMsg)
	}
}

func TestClassifyMethodHeaderMustMatchBody(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	env, _, r := req(t, body,
		mcp.HeaderProtocolVersion, mcp.VersionModern,
		mcp.HeaderMethod, "tools/call")
	_, errMsg := classify(r, env)
	if errMsg == nil || errMsg.Error.Code != mcp.CodeHeaderMismatch {
		t.Fatalf("got %v, want -32020 for method header mismatch", errMsg)
	}
}

func TestClassifyNameHeaderRequiredForToolsCall(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`

	// Missing entirely.
	env, _, r := req(t, body,
		mcp.HeaderProtocolVersion, mcp.VersionModern,
		mcp.HeaderMethod, "tools/call")
	if _, errMsg := classify(r, env); errMsg == nil || errMsg.Error.Code != mcp.CodeHeaderMismatch {
		t.Fatalf("got %v, want -32020 for missing Mcp-Name", errMsg)
	}

	// Present but naming a different tool: the routing-vs-execution split
	// this validation exists to catch.
	env, _, r = req(t, body,
		mcp.HeaderProtocolVersion, mcp.VersionModern,
		mcp.HeaderMethod, "tools/call",
		mcp.HeaderName, "rm_rf")
	if _, errMsg := classify(r, env); errMsg == nil || errMsg.Error.Code != mcp.CodeHeaderMismatch {
		t.Fatalf("got %v, want -32020 for mismatched Mcp-Name", errMsg)
	}

	// Matching.
	env, _, r = req(t, body,
		mcp.HeaderProtocolVersion, mcp.VersionModern,
		mcp.HeaderMethod, "tools/call",
		mcp.HeaderName, "echo")
	if rev, errMsg := classify(r, env); rev != mcp.RevisionModern || errMsg != nil {
		t.Fatalf("got rev=%v err=%v, want modern/nil", rev, errMsg)
	}
}

func TestClassifyBase64SentinelName(t *testing.T) {
	// A tool name outside printable ASCII travels base64-wrapped; the
	// gateway must decode before comparing or it would reject valid traffic.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"héllo","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	env, _, r := req(t, body,
		mcp.HeaderProtocolVersion, mcp.VersionModern,
		mcp.HeaderMethod, "tools/call",
		mcp.HeaderName, "=?base64?aMOpbGxv?=")
	if rev, errMsg := classify(r, env); rev != mcp.RevisionModern || errMsg != nil {
		t.Fatalf("got rev=%v err=%v, want modern/nil", rev, errMsg)
	}
}

func TestClassifyUnknownVersionNamesSupported(t *testing.T) {
	// A client asserting a revision the gateway does not serve gets the
	// list it does serve, so a dual-era client can retry instead of failing.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`
	env, _, r := req(t, body, mcp.HeaderProtocolVersion, "2099-01-01")
	_, errMsg := classify(r, env)
	if errMsg == nil || errMsg.Error.Code != mcp.CodeUnsupportedProtocolVersion {
		t.Fatalf("got %v, want -32022", errMsg)
	}
	var data struct {
		Supported []string `json:"supported"`
		Requested string   `json:"requested"`
	}
	if err := json.Unmarshal(errMsg.Error.Data, &data); err != nil {
		t.Fatalf("error data: %v", err)
	}
	if len(data.Supported) != 1 || data.Supported[0] != mcp.VersionLegacy {
		t.Errorf("supported = %v, want [%s]", data.Supported, mcp.VersionLegacy)
	}
	if data.Requested != "2099-01-01" {
		t.Errorf("requested = %q, want 2099-01-01", data.Requested)
	}
}

func TestRefuseModernNamesBlockers(t *testing.T) {
	// The refusal must be actionable: an operator reading the response needs
	// to know which controls are keeping the gateway on the Legacy path.
	g := &Gateway{log: discardLogger()}
	env, w, _ := req(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	g.refuseModern(w, env)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var got jsonrpc.Message
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if got.Error == nil || got.Error.Code != mcp.CodeUnsupportedProtocolVersion {
		t.Fatalf("error = %v, want -32022", got.Error)
	}
	var data struct {
		Supported []string `json:"supported"`
		Reasons   []string `json:"reasons"`
	}
	if err := json.Unmarshal(got.Error.Data, &data); err != nil {
		t.Fatalf("error data: %v", err)
	}
	if len(data.Reasons) == 0 {
		t.Error("refusal names no blockers; an operator cannot act on it")
	}
	if len(data.Supported) != 1 || data.Supported[0] != mcp.VersionLegacy {
		t.Errorf("supported = %v, want [%s]", data.Supported, mcp.VersionLegacy)
	}
}

func TestRefuseModernNotificationHasNoBody(t *testing.T) {
	g := &Gateway{log: discardLogger()}
	env, w, _ := req(t, `{"jsonrpc":"2.0","method":"notifications/progress"}`)
	g.refuseModern(w, env)
	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty for a notification", w.Body.String())
	}
}
