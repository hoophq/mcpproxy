package inbound

import (
	"encoding/json"
	"net/http"
	"strings"
)

// WellKnownPath is the RFC 9728 protected-resource metadata path.
const WellKnownPath = "/.well-known/oauth-protected-resource"

// protectedResourceMetadata is the RFC 9728 document. It carries the two
// required fields and nothing else: MCP clients use them to find the
// authorization server, and advertising scopes the gateway does not enforce
// would be a lie.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// WellKnownHandler serves RFC 9728 protected-resource metadata, pointing MCP
// clients at the authorization server that fronts this gateway.
//
// Unauthenticated MCP clients self-configure from it. A client hits /mcp,
// gets 401 with WWW-Authenticate, fetches this document, discovers
// authServerURL, and runs the OAuth flow against it with no manual setup.
//
// The daemon registers this under the *prefix*
// /.well-known/oauth-protected-resource, because RFC 9728 §3.1 lets clients
// append the resource path (a client talking to https://gw/mcp may request
// /.well-known/oauth-protected-resource/mcp). All such subpaths describe the
// same resource, so they get the same document.
//
// The endpoint takes no credential by design: requiring a token to learn how
// to get a token is a deadlock.
func WellKnownHandler(issuer, authServerURL string) http.Handler {
	body, err := json.Marshal(protectedResourceMetadata{
		Resource:             issuer,
		AuthorizationServers: []string{authServerURL},
	})
	if err != nil {
		// Both fields are plain strings, so encoding cannot fail. This
		// package does not panic, so fall back to an empty object rather
		// than serving a truncated document.
		body = []byte(`{}`)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isWellKnownPath(r.URL.Path) {
			// A JSON 404 keeps OAuth discovery clients on their error path;
			// an HTML error page from a fallthrough handler breaks their
			// response parsing.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The metadata holds still for the process lifetime; let clients
		// cache it instead of re-fetching before every token refresh.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}

// isWellKnownPath reports whether p is the metadata path or a resource-suffixed
// variant of it.
func isWellKnownPath(p string) bool {
	return p == WellKnownPath || strings.HasPrefix(p, WellKnownPath+"/")
}
