package authserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/hoophq/mcpproxy/auth/outbound"
)

// ErrNoUpstreamToken means no upstream token is held for the subject: either
// no IdP is federated, or the user has not completed a login since the
// gateway last restarted.
var ErrNoUpstreamToken = errors.New("authserver: no upstream token for subject")

// UpstreamAccessToken returns the upstream IdP access token held for subject.
//
// This is the "token swap" path: the caller authenticated to the gateway with
// a token this server minted, and a backend needs a token the *upstream*
// provider will accept. One login produced both, so the swap is a lookup
// instead of an exchange: no RFC 8693 round trip, no extra IdP configuration.
//
// An expired upstream token comes back as an expiry error. The user must log
// in again; refreshing it here would extend a session the IdP meant to end.
func (s *Server) UpstreamAccessToken(subject string) (string, error) {
	if subject == "" {
		return "", fmt.Errorf("%w: empty subject", ErrNoUpstreamToken)
	}
	tok, ok := s.store.getUpstream(subject)
	if !ok || tok == nil || tok.AccessToken == "" {
		return "", fmt.Errorf("%w: %s", ErrNoUpstreamToken, subject)
	}
	// Zero margin: the backend call follows this line.
	if !tok.Valid(s.now(), 0) {
		return "", fmt.Errorf("%w: %s (upstream token expired)", ErrNoUpstreamToken, subject)
	}
	return tok.AccessToken, nil
}

// NewUpstreamSwapSource returns an outbound.TokenSource that authenticates
// backend calls as the end user, using the upstream token captured during
// their login.
//
// It reads the user from the context (outbound.WithUser), so the gateway must
// tag the outbound request with the caller's subject. A missing user raises
// an error instead of yielding an empty token: an unauthenticated request to
// a backend that expects the user's credentials would surface as a 401 far
// from the mistake that caused it.
func NewUpstreamSwapSource(s *Server) outbound.TokenSource {
	return func(ctx context.Context) (string, error) {
		user, ok := outbound.UserFrom(ctx)
		if !ok || user == "" {
			return "", fmt.Errorf("%w: request carries no user", ErrNoUpstreamToken)
		}
		return s.UpstreamAccessToken(user)
	}
}
