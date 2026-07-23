package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// RFC 8693 token-exchange URNs.
const (
	// GrantTypeTokenExchange is the RFC 8693 grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeAccessToken is the RFC 8693 token type URN for access tokens.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// ExchangeConfig configures an RFC 8693 token-exchange source.
//
// Portions adapted from ToolHive (github.com/stacklok/toolhive), Apache-2.0.
type ExchangeConfig struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string

	// SubjectToken yields the inbound token to exchange, typically the
	// caller's own access token as validated by inbound auth.
	SubjectToken func(ctx context.Context) (string, error)

	// Audience is the RFC 8693 "audience" parameter: which upstream the
	// returned token should be valid for.
	Audience string
	// Scopes narrows the returned token.
	Scopes []string
	// Resource is the RFC 8707 resource indicator, for servers that key on it
	// instead of audience.
	Resource string

	// Margin overrides [ExpiryMargin] for the cache.
	Margin time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time

	HTTPClient *http.Client
}

// exchangeSource caches one exchanged token per subject token.
type exchangeSource struct {
	cfg    ExchangeConfig
	client ClientConfig

	mu sync.Mutex
	// subjectHash pins the cache to the identity it was minted for. Two users
	// hitting the same backend must never share an exchanged token, and a
	// re-login (new subject token) must invalidate the old one.
	subjectHash string
	cached      *core.Token
}

// NewExchangeSource returns a outbound.TokenSource that exchanges the inbound
// subject token for an upstream token (RFC 8693).
//
// This is the alternative to running an authorization flow per backend: the
// caller already authenticated to the gateway, and the authorization server is
// willing to mint a downstream-scoped token from that proof.
func NewExchangeSource(cfg ExchangeConfig) core.TokenSource {
	s := &exchangeSource{
		cfg: cfg,
		client: ClientConfig{
			ClientID:      cfg.ClientID,
			ClientSecret:  cfg.ClientSecret,
			TokenEndpoint: cfg.TokenEndpoint,
			HTTPClient:    cfg.HTTPClient,
		},
	}
	return s.token
}

func (s *exchangeSource) margin() time.Duration {
	if s.cfg.Margin > 0 {
		return s.cfg.Margin
	}
	return ExpiryMargin
}

func (s *exchangeSource) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

func (s *exchangeSource) token(ctx context.Context) (string, error) {
	if s.cfg.SubjectToken == nil {
		return "", errors.New("oauth: token exchange configured without a subject token source")
	}
	subject, err := s.cfg.SubjectToken(ctx)
	if err != nil {
		return "", fmt.Errorf("oauth: obtain subject token: %w", err)
	}
	if subject == "" {
		return "", errors.New("oauth: token exchange requires an inbound subject token, but the caller presented none")
	}
	hash := hashToken(subject)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.subjectHash == hash && s.cached.Valid(s.now(), s.margin()) {
		return s.cached.AccessToken, nil
	}

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", subject)
	form.Set("subject_token_type", TokenTypeAccessToken)
	form.Set("requested_token_type", TokenTypeAccessToken)
	if s.cfg.Audience != "" {
		form.Set("audience", s.cfg.Audience)
	}
	if len(s.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}
	if s.cfg.Resource != "" {
		form.Set("resource", s.cfg.Resource)
	}

	tok, err := postToken(ctx, s.client, form)
	if err != nil {
		return "", fmt.Errorf("oauth: token exchange: %w", err)
	}

	s.subjectHash, s.cached = hash, tok
	return tok.AccessToken, nil
}

// hashToken derives a cache key from a bearer token. The token itself is never
// stored as a map key so a heap dump or a logged key does not leak credentials.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
