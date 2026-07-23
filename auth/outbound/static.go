package outbound

import "context"

// NewStatic returns a source that always yields token.
//
// An empty token yields the no-header source, so "auth: static" with an unset
// secret behaves exactly like "auth: none" instead of sending a bare
// "Authorization: Bearer" that upstreams reject with a confusing 401.
func NewStatic(token string) TokenSource {
	return func(context.Context) (string, error) { return token, nil }
}

// NewNone returns a source that never supplies a credential.
func NewNone() TokenSource {
	return func(context.Context) (string, error) { return "", nil }
}
