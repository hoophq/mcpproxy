package inbound

import (
	"net/http"

	"github.com/hoophq/mcpproxy/inspect"
)

// AnonymousSubject is the subject every request gets in anonymous mode. The
// gateway uses the same literal when no resolver is configured at all, so
// audit records look identical whichever path produced them.
const AnonymousSubject = "anonymous"

// Anonymous accepts every request without inspecting credentials. It exists so
// that "no auth" is an explicit, auditable configuration rather than a nil
// resolver, and so local development has a mode that never 401s.
func Anonymous() Resolver {
	id := inspect.Identity{Subject: AnonymousSubject}
	return func(*http.Request) (inspect.Identity, error) { return id, nil }
}
