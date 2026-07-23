package oauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// ExpiryMargin is how early a token is treated as expired.
//
// A token that expires while in flight fails the request it was fetched for, so
// renewal happens 30 seconds ahead of the stated expiry to cover clock skew
// between us and the authorization server plus the upstream round trip.
const ExpiryMargin = 30 * time.Second

// ErrReauthorize signals that a grant cannot be renewed without a human: no
// refresh token was ever issued, or the server rejected the one we hold.
//
// The gateway surfaces this to the caller as an actionable "run the login flow
// for this backend" rather than retrying a grant that will never succeed.
type ErrReauthorize struct {
	Key    core.GrantKey
	Reason string
	Err    error
}

func (e *ErrReauthorize) Error() string {
	who := e.Key.Backend
	if e.Key.User != "" {
		who += " (user " + e.Key.User + ")"
	}
	return fmt.Sprintf("oauth: backend %s requires re-authorization: %s", who, e.Reason)
}

func (e *ErrReauthorize) Unwrap() error { return e.Err }

// RefreshConfig configures a refreshing token source.
type RefreshConfig struct {
	// Client identifies the OAuth client and token endpoint used for renewal.
	Client ClientConfig
	// Margin overrides [ExpiryMargin].
	Margin time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

func (c RefreshConfig) margin() time.Duration {
	if c.Margin > 0 {
		return c.Margin
	}
	return ExpiryMargin
}

func (c RefreshConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// refreshingSource renews and persists a stored grant on demand.
type refreshingSource struct {
	store core.TokenStore
	key   core.GrantKey
	cfg   RefreshConfig

	// mu serializes renewal for this key. Without it, a burst of concurrent
	// tool calls on an expired token fires N parallel refreshes; servers that
	// rotate refresh tokens invalidate the loser's token and leave the grant
	// permanently broken.
	mu sync.Mutex
	// cached is the last known-good token, so the hot path skips the store.
	cached *core.Token
}

// NewRefreshingSource returns a outbound.TokenSource backed by a stored
// grant: it serves the cached access token while valid and runs the
// refresh-token grant when it is not.
func NewRefreshingSource(store core.TokenStore, key core.GrantKey, cfg RefreshConfig) core.TokenSource {
	s := &refreshingSource{store: store, key: key, cfg: cfg}
	return s.token
}

func (s *refreshingSource) token(ctx context.Context) (string, error) {
	margin := s.cfg.margin()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-checking under the lock is what makes this a singleflight: whoever
	// waited behind a refresh finds the fresh token here instead of running a
	// second one.
	if s.cached.Valid(s.cfg.now(), margin) {
		return s.cached.AccessToken, nil
	}

	tok, err := s.store.Get(ctx, s.key)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return "", &ErrReauthorize{Key: s.key, Reason: "no stored grant", Err: err}
		}
		return "", err
	}
	if tok.Valid(s.cfg.now(), margin) {
		s.cached = tok
		return tok.AccessToken, nil
	}
	if tok.RefreshToken == "" {
		return "", &ErrReauthorize{Key: s.key, Reason: "stored token expired and no refresh token is available"}
	}

	fresh, err := Refresh(ctx, s.cfg.Client, tok.RefreshToken)
	if err != nil {
		var te *TokenError
		if errors.As(err, &te) && te.InvalidGrant() {
			// The refresh token is dead; drop it so the next call reports a
			// clean "not authorized" instead of retrying a rejected grant.
			_ = s.store.Delete(ctx, s.key)
			s.cached = nil
			return "", &ErrReauthorize{Key: s.key, Reason: "refresh token was rejected", Err: err}
		}
		return "", fmt.Errorf("oauth: refresh grant for %s: %w", s.key.Backend, err)
	}
	// Carry forward extras (id_token and friends) the refresh response omitted.
	if fresh.Extra == nil && tok.Extra != nil {
		fresh.Extra = tok.Extra
	}

	if err := s.store.Put(ctx, s.key, fresh); err != nil {
		return "", fmt.Errorf("oauth: persist refreshed token for %s: %w", s.key.Backend, err)
	}
	s.cached = fresh
	return fresh.AccessToken, nil
}
