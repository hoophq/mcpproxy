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

// grantTTL bounds a pending authorization, the window between /authorize and
// the upstream IdP returning to /callback. It runs long because a human is
// typing a password inside it.
const grantTTL = 15 * time.Minute

// client is a registered OAuth client. Every client is public and holds no
// secret: MCP clients are native and CLI apps that cannot keep one, so PKCE
// is mandatory here.
type client struct {
	ID           string
	RedirectURIs []string
	Name         string
	IssuedAt     time.Time
}

// allowsRedirect reports whether uri was registered. The exact string match
// is the point: prefix or wildcard matching on redirect URIs is the classic
// open-redirect hole in OAuth deployments.
func (c *client) allowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// grant is one in-flight authorization request. /authorize creates it,
// /authorize itself completes it when no upstream is configured or /callback
// does when federated, and /token consumes it once.
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
// random strings rather than JWTs, so revoking one deletes a map entry.
type refreshGrant struct {
	ClientID string
	Subject  string
	Email    string
	Scope    string
	Claims   map[string]any
	Expires  time.Time
}

// store holds every mutable piece of authorization state in memory. That
// bound is a choice: restarting the gateway logs everyone out. Persisting it
// would mean picking a database, and this gateway runs as a single sidecar
// process next to its MCP backends.
type store struct {
	mu      sync.Mutex
	clients map[string]*client
	// pending holds authorizations awaiting approval, keyed by grant id.
	// A grant leaves this map as soon as it is approved or abandoned, so a
	// replayed upstream callback finds nothing.
	pending map[string]*grant
	// codes holds approved authorizations, keyed by the code the server
	// handed the client. Disjoint from pending by construction: a grant sits
	// in one of the two maps, never both.
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

// takeCode redeems an authorization code once. A second call for the same
// code fails, which makes code replay visible at /token.
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

// sweep drops expired grants, codes and refresh tokens. The token endpoint
// calls it when it happens to run, so a long-running gateway does not
// accumulate the debris of abandoned logins and no background goroutine can
// leak.
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

// randomToken returns n bytes of cryptographic randomness as base64url. It is
// the source of every opaque identifier this package hands out: client ids,
// grant ids, authorization codes, refresh tokens.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
