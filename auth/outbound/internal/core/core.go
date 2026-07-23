// Package core holds the value types shared by auth/outbound and its oauth
// subpackage.
//
// It exists only to keep the dependency graph acyclic: outbound.Resolve builds
// OAuth sources so outbound imports oauth, while oauth needs the Token and
// TokenStore vocabulary. Parking that vocabulary here lets both import it.
// Every name is re-exported as an alias from auth/outbound, which is the only
// package callers should reference.
package core

import (
	"context"
	"errors"
	"time"
)

// TokenSource yields the credential for one outbound request. An empty token
// with a nil error means "send no Authorization header".
type TokenSource func(ctx context.Context) (string, error)

// GrantKey identifies a stored grant. User is empty for backend-wide grants
// and carries the authenticated subject for per-user backends.
type GrantKey struct {
	Backend string
	User    string
}

// Token is a persisted OAuth grant.
//
// Expiry is absolute rather than the lifetime seconds the wire format uses,
// because a stored token is read back long after it was issued and a relative
// duration would be meaningless by then.
type Token struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	TokenType    string            `json:"token_type,omitempty"`
	Expiry       time.Time         `json:"expiry,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
}

// Valid reports whether the access token is present and will still be accepted
// at now+margin.
//
// A zero Expiry means the token never expires: providers that omit expires_in
// are promising exactly that, and treating the zero time as "already expired"
// would send every such token straight to a pointless refresh.
func (t *Token) Valid(now time.Time, margin time.Duration) bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	if t.Expiry.IsZero() {
		return true
	}
	return now.Add(margin).Before(t.Expiry)
}

// Clone returns a deep copy. Stores hand out copies so a caller mutating a
// token cannot corrupt another holder's view.
func (t *Token) Clone() *Token {
	if t == nil {
		return nil
	}
	c := *t
	if t.Extra != nil {
		c.Extra = make(map[string]string, len(t.Extra))
		for k, v := range t.Extra {
			c.Extra[k] = v
		}
	}
	return &c
}

// ErrNotFound is returned by TokenStore.Get when no grant is stored for the
// key. It is an expected condition — the signal to start an authorization
// flow — not a failure.
var ErrNotFound = errors.New("outbound: token not found")

// TokenStore persists grants across gateway restarts.
//
// Get MUST return an error wrapping [ErrNotFound] when the key is absent, so
// callers can distinguish "never authorized" from "storage is broken" and only
// trigger a flow for the former.
type TokenStore interface {
	Get(ctx context.Context, k GrantKey) (*Token, error)
	Put(ctx context.Context, k GrantKey, t *Token) error
	Delete(ctx context.Context, k GrantKey) error
}
