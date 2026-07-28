package authserver

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// handleAuthorize implements GET /authorize.
//
// Errors split two ways, as RFC 6749 §4.1.2.1 requires. While the
// client_id/redirect_uri pair is still untrusted, the server renders the
// error itself, because redirecting to an unvalidated URI is how
// authorization codes get stolen. Once the pair checks out, every later
// failure goes back to the client as a redirect with error parameters.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	c, ok := s.store.getClient(clientID)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if redirectURI == "" {
		// A client with exactly one registered URI may omit the parameter.
		if len(c.RedirectURIs) != 1 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"redirect_uri is required when the client registered more than one")
			return
		}
		redirectURI = c.RedirectURIs[0]
	}
	if !c.allowsRedirect(redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		return
	}

	// From here on, errors are safe to send to redirectURI.
	state := q.Get("state")
	redirectErr := func(code, desc string) {
		s.redirectError(w, r, redirectURI, state, code, desc)
	}

	if rt := q.Get("response_type"); rt != "code" {
		redirectErr("unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		redirectErr("invalid_request", "code_challenge is required")
		return
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		// OAuth 2.1 removed "plain", and an absent method defaults to it, so
		// an absent method is rejected rather than downgraded in silence.
		redirectErr("invalid_request", "code_challenge_method must be S256")
		return
	}

	id, err := randomToken(24)
	if err != nil {
		s.log.Error("generate grant id", "error", err)
		redirectErr("server_error", "could not start authorization")
		return
	}
	g := &grant{
		ID:          id,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
		Challenge:   challenge,
		Scope:       q.Get("scope"),
		CreatedAt:   s.now(),
	}

	if s.upstream == nil {
		// No IdP: every caller is the same user. That suits local development
		// and is dangerous anywhere else, hence a warning per authorization.
		s.log.Warn("auth server has no upstream IdP; auto-approving as dev identity",
			"subject", devSubject, "client_id", clientID)
		g.Subject = devSubject
		g.Email = devSubject + "@localhost"
		g.Claims = map[string]any{"sub": devSubject, "email": g.Email}
		s.issueCode(w, r, g)
		return
	}

	// Federated: park the grant and bounce the user to the IdP. The grant id
	// travels as the upstream `state` so /callback can find it again, and it
	// is unguessable random, which is what state needs to be.
	s.store.putGrant(g)
	upstreamURL, err := s.upstream.AuthorizeURL(id)
	if err != nil {
		s.log.Error("build upstream authorize URL", "error", err)
		redirectErr("server_error", "could not reach the identity provider")
		return
	}
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

// handleCallback implements GET /callback, where the upstream IdP returns the
// user. It completes the parked grant, then redirects onward to the MCP
// client with an authorization code this server minted.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.upstream == nil {
		writeOAuthError(w, http.StatusNotFound, "invalid_request", "no upstream identity provider is configured")
		return
	}

	q := r.URL.Query()
	g, ok := s.store.takeGrant(q.Get("state"))
	if !ok {
		// Unknown, replayed or expired state. Nothing to redirect to, since
		// the grant carried the one redirect URI this server had validated.
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown or expired authorization state")
		return
	}
	if now := s.now(); now.Sub(g.CreatedAt) > grantTTL {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization request expired")
		return
	}

	redirectErr := func(code, desc string) {
		s.redirectError(w, r, g.RedirectURI, g.State, code, desc)
	}

	if e := q.Get("error"); e != "" {
		s.log.Info("upstream IdP denied authorization", "error", e, "client_id", g.ClientID)
		redirectErr("access_denied", "the identity provider denied the request: "+e)
		return
	}
	code := q.Get("code")
	if code == "" {
		redirectErr("invalid_request", "the identity provider returned no code")
		return
	}

	claims, tokens, err := s.upstream.Exchange(r.Context(), code)
	if err != nil {
		s.log.Error("upstream code exchange failed", "error", err, "client_id", g.ClientID)
		redirectErr("access_denied", "could not complete login with the identity provider")
		return
	}
	iss, _ := claims["iss"].(string)
	subject, email, err := identityFromClaims(claims, iss)
	if err != nil {
		s.log.Error("upstream identity extraction failed", "error", err)
		redirectErr("access_denied", "the identity provider returned no usable identity")
		return
	}

	g.Subject = subject
	g.Email = email
	g.Claims = claims
	if tokens != nil {
		// Keyed by this server's subject so the token-swap source can find it
		// later from the authenticated caller alone. See swap.go.
		s.store.putUpstream(subject, tokens)
	}
	s.log.Debug("federated login complete", "subject", subject, "client_id", g.ClientID)
	s.issueCode(w, r, g)
}

// issueCode mints the authorization code and redirects back to the client.
func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, g *grant) {
	code, err := randomToken(32)
	if err != nil {
		s.log.Error("generate authorization code", "error", err)
		s.redirectError(w, r, g.RedirectURI, g.State, "server_error", "could not issue an authorization code")
		return
	}
	g.Code = code
	g.CodeIssued = s.now()
	s.store.putCode(g)

	target, err := appendQuery(g.RedirectURI, map[string]string{"code": code, "state": g.State})
	if err != nil {
		// Registration validated the URI, so client input cannot reach this
		// branch; fail closed rather than redirect somewhere odd.
		s.log.Error("build client redirect", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not build the redirect")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// redirectError sends an OAuth error back to the client's redirect URI.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	target, err := appendQuery(redirectURI, map[string]string{
		"error":             code,
		"error_description": desc,
		"state":             state,
	})
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, code, desc)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// appendQuery adds parameters to a URI, preserving any it already carries.
// Empty values are skipped so an absent `state` does not become `state=`.
func appendQuery(raw string, params map[string]string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse redirect URI: %w", err)
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateRedirectURI states where this server will redirect a browser after
// authentication: an absolute URI with no fragment (RFC 6749 §3.1.2), under
// either a private-use scheme for native apps ("com.example.app:/callback")
// or http/https.
func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URI", raw)
	}
	if !u.IsAbs() {
		return fmt.Errorf("redirect_uri %q must be absolute", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", raw)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return fmt.Errorf("redirect_uri %q has no host", raw)
		}
	default:
		// Private-use scheme. Requiring a dot follows RFC 8252 §7.1, which
		// recommends a reverse-DNS scheme for native clients.
		if !strings.Contains(u.Scheme, ".") {
			return fmt.Errorf("redirect_uri %q uses unsupported scheme %q", raw, u.Scheme)
		}
	}
	return nil
}

// verifyPKCE checks a code_verifier against the stored S256 challenge.
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	// RFC 7636 §4.1: 43..128 characters from the unreserved set. The length
	// floor carries the security property, giving the verifier enough entropy
	// to resist guessing.
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}
