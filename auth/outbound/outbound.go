// Package outbound provides token sources for gateway→MCP-server
// authentication.
//
// Every source here produces a [TokenSource]: a function the backend
// transport calls once per outbound request to obtain the bearer credential.
// Returning an empty string means "send no Authorization header", which keeps
// the "auth: none" case on the same code path as every other mode instead of
// forcing callers to nil-check a source.
//
// The concrete sources are static (a fixed secret), passthrough (a credential
// the MCP client supplied on the inbound request), and OAuth (see the oauth
// subpackage: authorization-code with PKCE, refresh, and RFC 8693 exchange).
// [Resolve] maps a config.Backend onto one of them.
package outbound

import (
	"context"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// The vocabulary below lives in an internal package so that oauth (which
// outbound imports to build OAuth sources) can speak it without an import
// cycle. These aliases are the public names; nothing outside this module tree
// should reference the internal package.
type (
	// TokenSource yields the credential for one outbound request.
	//
	// An empty token with a nil error means "no Authorization header": callers
	// MUST treat that as success, not as a missing credential. The backend
	// transport calls implementations on the request path, so they must be
	// safe for concurrent use.
	TokenSource = core.TokenSource

	// GrantKey identifies a stored grant.
	//
	// User is empty for backend-wide grants (the common case: one service
	// account shared by every caller) and carries the authenticated end-user
	// subject when the backend is configured per_user, so two users never
	// share an upstream token.
	GrantKey = core.GrantKey

	// Token is a persisted OAuth grant.
	Token = core.Token

	// TokenStore persists grants across gateway restarts.
	TokenStore = core.TokenStore

	// EncryptedFile is a single AES-256-GCM sealed JSON document on disk.
	EncryptedFile = core.EncryptedFile
)

// KeySize is the AES-256 key length a keyfile must contain.
const KeySize = core.KeySize

// ErrNotFound reports that no grant is stored for the key. [TokenStore.Get]
// returns it to signal that a caller should start an authorization flow, not
// that storage broke.
var ErrNotFound = core.ErrNotFound

// LoadOrCreateKey reads a 32-byte raw AES key from path, generating one with
// crypto/rand and writing it 0600 if the file does not exist.
var LoadOrCreateKey = core.LoadOrCreateKey

type userCtxKey struct{}

// WithUser records the authenticated end-user subject on ctx. The gateway's
// inbound auth middleware sets it; per-user outbound grants key off it.
func WithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userCtxKey{}, user)
}

// UserFrom returns the subject recorded by [WithUser]. The boolean is false
// when no user is present. A per_user backend treats that as a hard error and
// does not fall back to a shared grant.
func UserFrom(ctx context.Context) (string, bool) {
	u, ok := ctx.Value(userCtxKey{}).(string)
	return u, ok && u != ""
}

type inboundTokenCtxKey struct{}

// WithInboundToken records the raw bearer token the caller presented to the
// gateway. RFC 8693 exchange uses it as the subject token, deriving the
// upstream credential from the caller's own proof of identity instead of a
// shared service account.
func WithInboundToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, inboundTokenCtxKey{}, token)
}

// InboundTokenFrom returns the token recorded by [WithInboundToken].
func InboundTokenFrom(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(inboundTokenCtxKey{}).(string)
	return t, ok && t != ""
}
