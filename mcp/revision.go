package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Protocol revisions the gateway distinguishes.
//
// Legacy is every revision through 2025-11-25: a session opens with an
// initialize handshake and later messages carry Mcp-Session-Id. Modern is
// 2026-07-28: no handshake, no session, every request self-describing via
// _meta and mirrored HTTP headers.
//
// Only Modern needs its own name. Older revisions differ from each other in
// ways the gateway does not inspect, so they collapse into Legacy.
type Revision int

const (
	// RevisionLegacy is the session-based era (2025-11-25 and earlier).
	RevisionLegacy Revision = iota
	// RevisionModern is 2026-07-28: stateless, per-request metadata.
	RevisionModern
)

func (r Revision) String() string {
	if r == RevisionModern {
		return "modern"
	}
	return "legacy"
}

// Wire values for the revisions above.
const (
	// VersionModern is the stateless revision this gateway recognizes.
	VersionModern = "2026-07-28"
	// VersionLegacy is the newest session-based revision, and the one the
	// gateway offers a Modern client that it cannot serve statelessly.
	VersionLegacy = "2025-11-25"
)

// Methods introduced by 2026-07-28.
const (
	// MethodServerDiscover replaces initialize as the capability probe.
	MethodServerDiscover = "server/discover"
	// MethodSubscriptionsListen replaces the GET SSE endpoint.
	MethodSubscriptionsListen = "subscriptions/listen"
)

// HTTP headers the Modern revision mirrors from the request body.
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
)

// Reserved _meta keys carrying per-request protocol metadata.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// Error codes the specification reserves for protocol-level failures. The
// -32020..-32099 band belongs to the spec; the gateway's own codes live in
// the implementation-defined -32000..-32019 band (see jsonrpc).
const (
	// CodeHeaderMismatch reports a mirrored header that is missing or
	// disagrees with the request body.
	CodeHeaderMismatch = -32020
	// CodeUnsupportedProtocolVersion reports a revision the server does not
	// serve; its data names the revisions it does.
	CodeUnsupportedProtocolVersion = -32022
)

// resultTypeInputRequired marks a Multi Round-Trip Request interim result:
// the server needs sampling, elicitation, or roots from the client before it
// can finish. Under 2026-07-28 these no longer arrive as server-initiated
// requests, so a gateway that inspects only requests never sees them.
const resultTypeInputRequired = "input_required"

// requestsRequiringName lists the methods whose Mcp-Name header is mandatory.
// The spec ties the header to params.name (tools, prompts) or params.uri
// (resources).
var requestsRequiringName = map[string]bool{
	MethodToolsCall:     true,
	MethodResourcesRead: true,
	MethodPromptsGet:    true,
}

// Meta is the subset of a request's _meta the gateway reads.
type Meta struct {
	ProtocolVersion string
	ClientInfo      Implementation
	// HasCapabilities distinguishes an absent clientCapabilities object
	// from an empty one. The spec requires the field; absence is an error,
	// while "{}" is a client that declares nothing.
	HasCapabilities bool
}

// ParseMeta extracts the reserved keys from a request's params._meta. A
// message with no params, no _meta, or no reserved keys yields the zero Meta,
// which Classify reads as Legacy.
func ParseMeta(params json.RawMessage) Meta {
	if len(params) == 0 {
		return Meta{}
	}
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil || p.Meta == nil {
		return Meta{}
	}
	var m Meta
	if raw, ok := p.Meta[MetaProtocolVersion]; ok {
		_ = json.Unmarshal(raw, &m.ProtocolVersion)
	}
	if raw, ok := p.Meta[MetaClientInfo]; ok {
		_ = json.Unmarshal(raw, &m.ClientInfo)
	}
	_, m.HasCapabilities = p.Meta[MetaClientCapabilities]
	return m
}

// IsModern reports whether the metadata claims the stateless revision.
func (m Meta) IsModern() bool { return m.ProtocolVersion == VersionModern }

// HasModernSignal reports whether anything in the metadata claims a revision
// at all. A request carrying io.modelcontextprotocol/protocolVersion is
// asserting an era even when the value is one the gateway does not serve;
// that distinction is what separates "unsupported version" from "legacy
// client that simply omitted the field".
func (m Meta) HasModernSignal() bool { return m.ProtocolVersion != "" }

// ResultRequiresInput reports whether a response body is an MRTR interim
// result asking the client for sampling, elicitation, or roots.
//
// This is the shape that replaced server-initiated requests in 2026-07-28.
// A gate that switches on a message's method never fires for it: the message
// is a *response*, so its method is empty and the request it answers is an
// ordinary tools/call.
func ResultRequiresInput(result json.RawMessage) bool {
	if len(result) == 0 {
		return false
	}
	var r struct {
		ResultType string `json:"resultType"`
	}
	if json.Unmarshal(result, &r) != nil {
		return false
	}
	return r.ResultType == resultTypeInputRequired
}

// InputRequestMethods lists the distinct server-to-client request methods an
// MRTR interim result asks the client to satisfy, in encounter order with
// duplicates removed. Keys of the inputRequests map are server-assigned and
// carry no meaning, so the gate matches on each entry's method.
//
// A result whose inputRequests is absent or malformed yields nil: such a
// result asks for nothing the gateway needs to police.
func InputRequestMethods(result json.RawMessage) []string {
	var r struct {
		InputRequests map[string]struct {
			Method string `json:"method"`
		} `json:"inputRequests"`
	}
	if json.Unmarshal(result, &r) != nil || len(r.InputRequests) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(r.InputRequests))
	out := make([]string, 0, len(r.InputRequests))
	for _, req := range r.InputRequests {
		if req.Method == "" || seen[req.Method] {
			continue
		}
		seen[req.Method] = true
		out = append(out, req.Method)
	}
	return out
}

// NameForMethod returns the value the Mcp-Name header must carry for this
// request, and whether the method requires the header at all.
func NameForMethod(method string, params json.RawMessage) (string, bool) {
	if !requestsRequiringName[method] {
		return "", false
	}
	var p struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &p)
	}
	if method == MethodResourcesRead {
		return p.URI, true
	}
	return p.Name, true
}

// sentinelPrefix and sentinelSuffix wrap a base64 header value that could not
// be represented as plain ASCII. Both markers are literal and lowercase; this
// is not RFC 2047, which carries a charset and an encoding letter.
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// DecodeHeaderName unwraps the base64 sentinel a client uses when a tool name
// or resource URI cannot travel as a plain ASCII header value. A value
// without the markers passes through unchanged; a malformed payload reports
// false so the caller can reject the request rather than compare garbage.
func DecodeHeaderName(v string) (string, bool) {
	if !strings.HasPrefix(v, sentinelPrefix) || !strings.HasSuffix(v, sentinelSuffix) {
		return v, true
	}
	payload := v[len(sentinelPrefix) : len(v)-len(sentinelSuffix)]
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}
