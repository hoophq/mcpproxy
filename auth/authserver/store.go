package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound"
)

// codeTTL bounds how long an authorization code stays redeemable. RFC 6749
// §4.1.2 recommends a maximum of 10 minutes.
const codeTTL = 10 * time.Minute

// grantTTL bounds a pending authorization (the window between /authorize and
// the upstream IdP returning to /callback). Generous, because it contains a
// human typing a password.
const grantTTL = 15 * time.Minute

// client is a registered OAuth client. Every client is public (no secret):
// MCP clients are native/CLI apps that cannot keep one, which is why PKCE is
// mandatory rather than optional here.
type client struct {
	ID           string
	RedirectURIs []string
	Name         string
	IssuedAt     time.Time
}

// allowsRedirect reports whether uri was registered. Exact string match is
// deliberate — prefix or wildcard matching on redirect URIs is the classic
// open-redirect hole in OAuth deployments.
func (c *client) allowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// grant is one in-flight authorization request. It is created at /authorize,
// completed either immediately (no upstream) or at /callback (federated), and
// consumed once at /token.
type grant struct {
	ID          string
	ClientID    string
	RedirectURI string
	State       string // the client's state, echoed back on redirect
	Challenge   string // PKCE code_challenge (S256)
	Scope       string
	CreatedAt   time.Time

	// Filled in on approval.
	Subject string
	Email   string
	Claims  map[string]any

	Code       string
	CodeIssued time.Time
}

// refreshGrant is what a refresh token stands for. Refresh tokens are opaque
// random strings, not JWTs, so revoking one means deleting a map entry.
type refreshGrant struct {
	ClientID string
	Subject  string
	Email    string
	Scope    string
	Claims   map[string]any
	Expires  time.Time
}

// store holds every mutable piece of authorization state in memory. That is a
// deliberate limit: restarting the gateway logs everyone out. Persisting it
// would mean choosing a database, and this gateway is meant to run as a
// single sidecar process next to its MCP backends.
type store struct {
	mu      sync.Mutex
	clients map[string]*client
	// pending holds authorizations awaiting approval, keyed by grant id.
	// A grant leaves this map the moment it is approved or abandoned, which
	// is what makes a replayed upstream callback find nothing.
	pending map[string]*grant
	// codes holds approved authorizations, keyed by the code we handed the
	// client. Disjoint from pending by construction: a grant lives in exactly
	// one of the two, never both.
	codes    map[string]*grant
	refresh  map[string]*refreshGrant
	upstream map[string]*outbound.Token // subject -> upstream tokens
}

func newStore() *store {
	return &store{
		clients:  make(map[string]*client),
		pending:  make(map[string]*grant),
		codes:    make(map[string]*grant),
		refresh:  make(map[string]*refreshGrant),
		upstream: make(map[string]*outbound.Token),
	}
}

func (s *store) putClient(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
}

func (s *store) getClient(id string) (*client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	return c, ok
}

func (s *store) putGrant(g *grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[g.ID] = g
}

// takeGrant removes and returns a pending grant. Removal is the point: a
// federated callback may only be redeemed against a grant once, so a replayed
// upstream redirect finds nothing. The caller checks expiry.
func (s *store) takeGrant(id string) (*grant, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.pending[id]
	if !ok {
		return nil, false
	}
	delete(s.pending, id)
	return g, true
}

// putCode files an approved grant under its authorization code.
func (s *store) putCode(g *grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[g.Code] = g
}

// takeCode redeems an authorization code exactly once. A second call for the
// same code fails, which is what makes code replay detectable at /token.
func (s *store) takeCode(code string, now time.Time) (*grant, bool) {
	if code == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.codes[code]
	if !ok {
		return nil, false
	}
	delete(s.codes, code)
	if now.Sub(g.CodeIssued) > codeTTL {
		return nil, false
	}
	return g, true
}

func (s *store) putRefresh(token string, rg *refreshGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token] = rg
}

// takeRefresh consumes a refresh token. Refresh tokens rotate: the caller
// issues a fresh one, so the presented token must not survive the exchange.
func (s *store) takeRefresh(token string, now time.Time) (*refreshGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rg, ok := s.refresh[token]
	if !ok {
		return nil, false
	}
	delete(s.refresh, token)
	if now.After(rg.Expires) {
		return nil, false
	}
	return rg, true
}

func (s *store) putUpstream(subject string, tok *outbound.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstream[subject] = tok
}

func (s *store) getUpstream(subject string) (*outbound.Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.upstream[subject]
	return t, ok
}

// sweep drops expired grants, codes and refresh tokens. Called opportunistically
// from the token endpoint so a long-running gateway does not accumulate the
// debris of abandoned logins; there is no background goroutine to leak.
func (s *store) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.pending {
		if now.Sub(g.CreatedAt) > grantTTL {
			delete(s.pending, id)
		}
	}
	for code, g := range s.codes {
		if now.Sub(g.CodeIssued) > codeTTL {
			delete(s.codes, code)
		}
	}
	for tok, rg := range s.refresh {
		if now.After(rg.Expires) {
			delete(s.refresh, tok)
		}
	}
}

// randomToken returns n bytes of cryptographic randomness as base64url, the
// source of every opaque identifier this package hands out (client ids, grant
// ids, authorization codes, refresh tokens).
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
