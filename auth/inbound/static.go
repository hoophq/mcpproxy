package inbound

import (
	"crypto/subtle"
	"fmt"
	"net/http"

	"github.com/hoophq/mcpproxy/inspect"
)

// StaticSubject is the subject granted to any caller presenting the shared
// token. A static token names no principal, so the identity says little by
// design: audit records show that *the* token was used, not who used it.
const StaticSubject = "static-token"

// Static accepts a single shared bearer token.
//
// The comparison runs in constant time. A byte-by-byte string compare would
// leak the token prefix through response timing, enough to recover a secret
// over a few thousand requests against a local gateway.
func Static(token string) (Resolver, error) {
	if token == "" {
		return nil, fmt.Errorf("inbound static: token must not be empty")
	}
	want := []byte(token)
	id := inspect.Identity{Subject: StaticSubject}
	return func(r *http.Request) (inspect.Identity, error) {
		got, err := bearerToken(r)
		if err != nil {
			return inspect.Identity{}, err
		}
		// ConstantTimeCompare returns 0 for unequal lengths without reading
		// the operands, so this leaks length. The length of a configured
		// token is not the part worth protecting.
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			return inspect.Identity{}, fmt.Errorf("%w: invalid static token", ErrUnauthenticated)
		}
		return id, nil
	}, nil
}
