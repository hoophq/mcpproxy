// Package inbound implements the gateway's inbound authentication: turning an
// incoming HTTP request into an inspect.Identity.
//
// Each mode is an independent constructor returning a Resolver; New dispatches
// on config.Inbound.Mode so the daemon does not have to switch on strings.
// Resolvers are called on every request from many goroutines and must be
// safe for concurrent use.
//
// Portions adapted from ToolHive (github.com/stacklok/toolhive), Apache-2.0.
package inbound

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
)

// Resolver authenticates an HTTP request and yields the caller identity. It is
// an alias (not a defined type) so a Resolver is directly assignable to
// gateway.IdentityResolver without importing the gateway package here.
type Resolver = func(r *http.Request) (inspect.Identity, error)

// ErrUnauthenticated is the root of every credential-rejection error returned
// by a Resolver. The gateway turns any resolver error into a 401, but callers
// that need to distinguish "bad credential" from "auth backend broken" can use
// errors.Is against this.
var ErrUnauthenticated = errors.New("unauthenticated")

// New builds the Resolver selected by cfg.Mode. An empty mode means anonymous,
// matching config.Validate, which accepts "" as a synonym.
//
// Construction never performs network I/O: modes that need a remote authority
// (oidc) resolve it lazily on first use so an unreachable IdP at startup
// degrades to failing requests instead of a daemon that refuses to boot.
func New(cfg config.Inbound) (Resolver, error) {
	switch cfg.Mode {
	case "", "anonymous":
		return Anonymous(), nil
	case "local":
		return Local()
	case "static":
		return Static(cfg.Token)
	case "oidc":
		return OIDC(OIDCOptions{
			Issuer:   cfg.Issuer,
			Audience: cfg.Audience,
			Scopes:   cfg.Scopes,
		})
	case "github":
		return GitHub(GitHubOptions{AllowedOrgs: cfg.GitHubAllowedOrgs}), nil
	case "awssts":
		return AWSSTS(AWSSTSOptions{RoleMappings: cfg.AWSRoleMappings})
	default:
		return nil, fmt.Errorf("inbound: unknown mode %q", cfg.Mode)
	}
}

// bearerToken extracts the credential from an RFC 6750 Authorization header.
// The scheme comparison is case-insensitive because RFC 7235 defines auth
// schemes as case-insensitive tokens and real clients send "bearer".
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", fmt.Errorf("%w: missing Authorization header", ErrUnauthenticated)
	}
	const scheme = "bearer "
	if len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", fmt.Errorf("%w: Authorization header is not a Bearer credential", ErrUnauthenticated)
	}
	tok := strings.TrimSpace(h[len(scheme):])
	if tok == "" {
		return "", fmt.Errorf("%w: empty Bearer token", ErrUnauthenticated)
	}
	return tok, nil
}

// globMatch reports whether s matches a shell-style pattern where '*' spans any
// run of characters (including '/' and ':') and '?' matches exactly one.
//
// path.Match is unusable here: it treats '/' as a segment separator, so
// "arn:aws:sts::*:assumed-role/*" would never match a three-segment
// assumed-role ARN. The implementation is an iterative two-pointer matcher with
// backtracking: O(len(pattern)*len(s)) worst case, no recursion on hostile input.
func globMatch(pattern, s string) bool {
	var (
		p, i  int
		starP = -1
		starI int
	)
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			// Remember the star and try to match zero characters first.
			starP, starI = p, i
			p++
		case starP >= 0:
			// Backtrack: let the last star consume one more character.
			starI++
			p, i = starP+1, starI
		default:
			return false
		}
	}
	// Trailing stars in the pattern may still match the empty remainder.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
