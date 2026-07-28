package authserver

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleToken implements POST /token for the two grants the server advertises.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}
	// Opportunistic GC: every live client hits the token endpoint on a
	// schedule, making it a free place to expire abandoned state without a
	// background goroutine.
	s.store.sweep(s.now())

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.authorizationCodeGrant(w, r)
	case "refresh_token":
		s.refreshTokenGrant(w, r)
	case "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code and refresh_token are supported")
	}
}

func (s *Server) authorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	code := f.Get("code")
	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	// takeCode deletes the code, so a replay lands here and fails, which is
	// the point of one-time codes.
	g, ok := s.store.takeCode(code, s.now())
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is unknown, used or expired")
		return
	}
	// Binding the code to the client that requested it stops a malicious
	// client from redeeming a code it observed.
	if cid := f.Get("client_id"); cid != g.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code was not issued to this client")
		return
	}
	// RFC 6749 §4.1.3: redirect_uri must match the authorization request when
	// one was sent there.
	if ru := f.Get("redirect_uri"); ru != "" && ru != g.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if !verifyPKCE(f.Get("code_verifier"), g.Challenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}

	s.issueTokens(w, g.ClientID, g.Subject, g.Email, g.Scope, g.Claims)
}

func (s *Server) refreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	presented := f.Get("refresh_token")
	if presented == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Rotation: takeRefresh consumes the presented token and issueTokens mints
	// a new one, so a stolen refresh token works at most once and the
	// legitimate client's next refresh fails in the open.
	rg, ok := s.store.takeRefresh(presented, s.now())
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is unknown, used or expired")
		return
	}
	if cid := f.Get("client_id"); cid != "" && cid != rg.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was not issued to this client")
		return
	}
	// A refresh request may narrow scope but never widen it (RFC 6749 §6).
	// This server takes the same scope or no scope parameter.
	scope := rg.Scope
	if want := f.Get("scope"); want != "" && want != rg.Scope {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "refresh cannot change the granted scope")
		return
	}

	s.issueTokens(w, rg.ClientID, rg.Subject, rg.Email, scope, rg.Claims)
}

// issueTokens mints the ES256 access token plus a fresh opaque refresh token.
func (s *Server) issueTokens(w http.ResponseWriter, clientID, subject, email, scope string, claims map[string]any) {
	now := s.now()
	access, err := s.signAccessToken(clientID, subject, email, scope, now)
	if err != nil {
		s.log.Error("sign access token", "error", err, "subject", subject)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue an access token")
		return
	}
	refresh, err := randomToken(32)
	if err != nil {
		s.log.Error("generate refresh token", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a refresh token")
		return
	}
	s.store.putRefresh(refresh, &refreshGrant{
		ClientID: clientID,
		Subject:  subject,
		Email:    email,
		Scope:    scope,
		Claims:   claims,
		Expires:  now.Add(refreshTokenTTL),
	})

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.tokenTTL / time.Second),
		RefreshToken: refresh,
		Scope:        scope,
	})
}

// signAccessToken builds the JWT the gateway verifies later in ValidateToken.
// The audience is the client id: these tokens call this gateway on behalf of
// that client, and nothing else should accept them.
func (s *Server) signAccessToken(clientID, subject, email, scope string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": subject,
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(s.tokenTTL).Unix(),
	}
	if email != "" {
		claims["email"] = email
	}
	if scope != "" {
		claims["scope"] = scope
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.key)
}
