package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// classify decides which protocol era a request belongs to, and validates the
// mirrored HTTP headers when it is Modern.
//
// The body is authoritative: params._meta carries the revision, and the
// MCP-Protocol-Version header must agree with it. An `initialize` request is
// Legacy no matter what it claims, so a forged Modern _meta cannot steer a
// handshake onto a path that assumes there is no handshake.
//
// A returned message is a ready-to-send JSON-RPC error; the caller writes it
// with HTTP 400.
func classify(r *http.Request, env *jsonrpc.Message) (mcp.Revision, *jsonrpc.Message) {
	if env.Method == mcp.MethodInitialize {
		return mcp.RevisionLegacy, nil
	}

	meta := mcp.ParseMeta(env.Params)
	header := r.Header.Get(mcp.HeaderProtocolVersion)

	// MCP-Protocol-Version is not a Modern invention. Since 2025-06-18 the
	// spec requires a Legacy client to echo the version it negotiated at
	// `initialize` on every subsequent HTTP request, so the header alone
	// says nothing about the era — only _meta does. Reading the header as a
	// Modern signal rejected the very clients that follow the spec most
	// closely: claude-code negotiates 2025-11-25, echoes it as required, and
	// its next message (notifications/initialized) came back
	// "-32022 unsupported protocol version" naming 2025-11-25 as both the
	// requested and the only supported version.
	//
	// So the era is decided by _meta, and the header is only cross-checked
	// against it.
	if !meta.HasModernSignal() {
		if header != "" && header != mcp.VersionLegacy && header != mcp.VersionModern {
			// A Legacy-shaped request echoing a version this gateway does
			// not speak. Still worth refusing, but for the right reason.
			return mcp.RevisionLegacy, unsupportedVersion(env.ID, header)
		}
		return mcp.RevisionLegacy, nil
	}

	// _meta claims a revision. From here a disagreement with the mirrored
	// header is an error rather than a silent downgrade: a client that
	// mirrors its version into a header and then contradicts it in the body
	// is exactly the split-brain the spec's header validation exists to
	// catch.
	if header != "" && header != meta.ProtocolVersion {
		return mcp.RevisionLegacy, headerMismatch(env.ID,
			fmt.Sprintf("%s header %q does not match _meta protocolVersion %q",
				mcp.HeaderProtocolVersion, header, meta.ProtocolVersion))
	}

	if meta.ProtocolVersion != mcp.VersionModern {
		// A version the gateway does not serve. Naming what it does serve is
		// what lets a dual-era client retry instead of failing outright.
		return mcp.RevisionLegacy, unsupportedVersion(env.ID, meta.ProtocolVersion)
	}

	if msg := validateModernHeaders(r, env); msg != nil {
		return mcp.RevisionModern, msg
	}
	return mcp.RevisionModern, nil
}

// validateModernHeaders enforces the mirrored-header contract. Intermediaries
// route and rate-limit on these headers without parsing the body, so a header
// that disagrees with the body is a request two components would treat
// differently. Rejecting is the only safe answer.
func validateModernHeaders(r *http.Request, env *jsonrpc.Message) *jsonrpc.Message {
	if r.Header.Get(mcp.HeaderProtocolVersion) == "" {
		return headerMismatch(env.ID, "missing required "+mcp.HeaderProtocolVersion+" header")
	}

	// Notifications carry no id and the spec leaves their header rules
	// undefined; only requests are validated.
	if !env.IsRequest() {
		return nil
	}

	switch got := r.Header.Get(mcp.HeaderMethod); got {
	case "":
		return headerMismatch(env.ID, "missing required "+mcp.HeaderMethod+" header")
	case env.Method:
	default:
		return headerMismatch(env.ID, fmt.Sprintf("%s header %q does not match body method %q",
			mcp.HeaderMethod, got, env.Method))
	}

	want, required := mcp.NameForMethod(env.Method, env.Params)
	if !required {
		return nil
	}
	raw := r.Header.Get(mcp.HeaderName)
	if raw == "" {
		return headerMismatch(env.ID, fmt.Sprintf("%s header is required for %s",
			mcp.HeaderName, env.Method))
	}
	got, ok := mcp.DecodeHeaderName(raw)
	if !ok {
		return headerMismatch(env.ID, mcp.HeaderName+" header is not valid base64 sentinel encoding")
	}
	if got != want {
		return headerMismatch(env.ID, fmt.Sprintf("%s header %q does not match body value %q",
			mcp.HeaderName, got, want))
	}
	return nil
}

func headerMismatch(id jsonrpc.ID, reason string) *jsonrpc.Message {
	return jsonrpc.NewError(id, mcp.CodeHeaderMismatch, reason)
}

// unsupportedVersion refuses a revision and names the ones the gateway serves,
// so a dual-era client can retry rather than give up.
func unsupportedVersion(id jsonrpc.ID, requested string) *jsonrpc.Message {
	msg := jsonrpc.NewError(id, mcp.CodeUnsupportedProtocolVersion, "unsupported protocol version")
	data, err := json.Marshal(struct {
		Supported []string `json:"supported"`
		Requested string   `json:"requested,omitempty"`
	}{
		Supported: []string{mcp.VersionLegacy},
		Requested: requested,
	})
	if err == nil {
		msg.Error.Data = data
	}
	return msg
}

// statelessBlockers names the gateway features that cannot be served without a
// session, and are therefore why a Modern client is steered to Legacy.
//
// Every entry is a security control whose correctness depends on comparing
// across requests:
//
//   - Rug-pull detection diffs a tool's fingerprint against the catalog the
//     client saw earlier. With no session there is no "earlier".
//   - Per-session call budgets and rate windows count against a session.
//   - The override rename map is populated by tools/list and consulted by
//     tools/call, so that an alias cannot launder a denied call.
//
// Serving Modern today would not degrade these gracefully. It would give each
// request an empty state, and every one of them would silently pass: the
// catalog-listed flag would never be set, so unadvertised-tool enforcement
// would not fire; the rename map would be empty, so an alias would reach the
// backend unmapped; the call counter would reset to zero on every request.
// The gateway would keep answering and stop enforcing.
//
// Refusing loudly is the honest answer until that state is re-keyed to
// identity. Delete an entry when its control no longer needs a session; when
// the list is empty, the Modern path can be served.
func (g *Gateway) statelessBlockers() []string {
	return []string{
		"rug-pull detection requires a per-session tool catalog",
		"call budgets and rate limits are counted per session",
		"tool-override renames are learned from a session's tools/list",
	}
}

// refuseModern answers a Modern request the gateway cannot serve statelessly.
//
// The refusal is deliberate and conformant, not a fallback: it names the
// revision the gateway does serve, so a dual-era client retries on Legacy and
// gets full policy enforcement. Answering the request statelessly instead
// would silently disable the controls listed in statelessBlockers.
func (g *Gateway) refuseModern(w http.ResponseWriter, env *jsonrpc.Message) {
	blockers := g.statelessBlockers()
	g.log.Warn("refused MCP 2026-07-28 request; gateway serves "+mcp.VersionLegacy,
		"method", env.Method, "blockers", blockers)

	// A notification expects no body, only a status.
	if !env.IsRequest() {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	msg := unsupportedVersion(env.ID, mcp.VersionModern)
	if data, err := json.Marshal(struct {
		Supported []string `json:"supported"`
		Requested string   `json:"requested"`
		Reasons   []string `json:"reasons"`
	}{
		Supported: []string{mcp.VersionLegacy},
		Requested: mcp.VersionModern,
		Reasons:   blockers,
	}); err == nil {
		msg.Error.Data = data
	}
	writeJSON(w, http.StatusBadRequest, msg)
}
