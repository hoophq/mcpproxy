package inbound

import (
	"fmt"
	"net/http"
	"os/user"

	"github.com/hoophq/mcpproxy/inspect"
)

// Local attributes every request to the OS user running the daemon.
//
// Single-user desktop deployments use this: the gateway listens on loopback
// and the operator's own MCP client is the sole caller, so there is no
// credential to check, yet audit records should carry a real name instead of
// "anonymous". Binding this mode to a non-loopback address is a configuration
// error; the resolver cannot detect that and does not try.
//
// Local looks the user up once at construction. The user cannot change for
// the life of the process, and a per-request user.Current() would add a
// syscall to the hot path for nothing.
func Local() (Resolver, error) {
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("inbound local: resolving current OS user: %w", err)
	}
	subject := u.Username
	if subject == "" {
		// Some containerized environments return a passwd entry with no name;
		// the numeric uid still names a stable principal.
		subject = u.Uid
	}
	id := inspect.Identity{
		Subject: subject,
		Claims: map[string]any{
			"uid":  u.Uid,
			"gid":  u.Gid,
			"name": u.Name,
		},
	}
	return func(*http.Request) (inspect.Identity, error) { return id, nil }, nil
}
