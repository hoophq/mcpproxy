package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAS is an authorization server that implements just enough of RFC 6749 +
// RFC 7636 to prove the flow end to end: it records the challenge presented at
// /authorize and refuses to issue a token unless the verifier presented at
// /token hashes to it.
type fakeAS struct {
	*httptest.Server

	mu sync.Mutex
	// codes maps an issued authorization code to the challenge it was bound to.
	codes map[string]string
	// lastTokenForm is the most recent /token request body.
	lastTokenForm url.Values
	// lastAuthQuery is the most recent /authorize query.
	lastAuthQuery url.Values

	// issuedRefresh, when set, is returned as refresh_token.
	issuedRefresh string
	// expiresIn, when non-zero, is returned as expires_in.
	expiresIn int
	// extra fields merged into the token response.
	extra map[string]string
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	as := &fakeAS{codes: make(map[string]string)}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", as.handleAuthorize)
	mux.HandleFunc("/token", as.handleToken(t))
	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)
	return as
}

func (as *fakeAS) clientCfg() ClientConfig {
	return ClientConfig{
		ClientID:      "test-client",
		AuthEndpoint:  as.URL + "/authorize",
		TokenEndpoint: as.URL + "/token",
		Scopes:        []string{"read", "write"},
		HTTPClient:    as.Client(),
	}
}

// handleAuthorize issues a code bound to the presented challenge and redirects
// straight back, standing in for a user who instantly approves.
func (as *fakeAS) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	as.mu.Lock()
	as.lastAuthQuery = q
	code := fmt.Sprintf("code-%d", len(as.codes)+1)
	as.codes[code] = q.Get("code_challenge")
	as.mu.Unlock()

	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (as *fakeAS) handleToken(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		as.mu.Lock()
		as.lastTokenForm = r.PostForm
		as.mu.Unlock()

		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			as.mu.Lock()
			challenge, ok := as.codes[r.PostForm.Get("code")]
			delete(as.codes, r.PostForm.Get("code")) // single use
			as.mu.Unlock()
			if !ok {
				writeJSON(t, w, map[string]string{"error": "invalid_grant"})
				return
			}
			verifier := r.PostForm.Get("code_verifier")
			sum := sha256.Sum256([]byte(verifier))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(t, w, map[string]string{
					"error": "invalid_grant", "error_description": "PKCE verifier does not match challenge",
				})
				return
			}
		case "refresh_token":
			if r.PostForm.Get("refresh_token") == "" {
				writeJSON(t, w, map[string]string{"error": "invalid_request"})
				return
			}
		default:
			writeJSON(t, w, map[string]string{"error": "unsupported_grant_type"})
			return
		}

		resp := map[string]any{"access_token": "at-1", "token_type": "Bearer"}
		if as.issuedRefresh != "" {
			resp["refresh_token"] = as.issuedRefresh
		}
		if as.expiresIn != 0 {
			resp["expires_in"] = as.expiresIn
		}
		for k, v := range as.extra {
			resp[k] = v
		}
		writeJSON(t, w, resp)
	}
}

func (as *fakeAS) tokenForm() url.Values {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastTokenForm
}

func (as *fakeAS) authQuery() url.Values {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastAuthQuery
}

// scriptedAuthorizer follows the authorization URL with an HTTP client that
// does not auto-follow, then reads the code out of the redirect — exactly what
// a browser would deliver to a real redirect handler.
type scriptedAuthorizer struct {
	client      *http.Client
	redirectURI string
	// tamperState, when set, replaces the state the callback carries.
	tamperState string
}

func (s *scriptedAuthorizer) RedirectURI(context.Context) (string, error) {
	return s.redirectURI, nil
}

func (s *scriptedAuthorizer) Authorize(ctx context.Context, req AuthorizeRequest) (string, string, error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return "", "", err
	}
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(hreq)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}
	gotState := loc.Query().Get("state")
	if s.tamperState != "" {
		gotState = s.tamperState
	}
	if gotState != req.State {
		return "", "", errors.New("state mismatch")
	}
	return loc.Query().Get("code"), s.redirectURI, nil
}

func TestAuthorize_FullPKCEFlow(t *testing.T) {
	as := newFakeAS(t)
	as.issuedRefresh = "rt-1"
	as.expiresIn = 3600
	as.extra = map[string]string{"id_token": "jwt-here", "scope": "read write"}

	az := &scriptedAuthorizer{client: as.Client(), redirectURI: "http://127.0.0.1:9999/callback"}
	tok, err := Authorize(context.Background(), as.clientCfg(), az)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if tok.AccessToken != "at-1" {
		t.Errorf("access_token = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-1" {
		t.Errorf("refresh_token = %q", tok.RefreshToken)
	}
	if tok.Expiry.IsZero() || time.Until(tok.Expiry) < 30*time.Minute {
		t.Errorf("expiry = %v, want ~1h out", tok.Expiry)
	}
	// The id_token is unrecoverable once the code is burned, so it must survive
	// the round trip.
	if tok.Extra["id_token"] != "jwt-here" {
		t.Errorf("extra id_token = %q", tok.Extra["id_token"])
	}
	if tok.Extra["scope"] != "read write" {
		t.Errorf("extra scope = %q", tok.Extra["scope"])
	}

	aq := as.authQuery()
	if aq.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", aq.Get("code_challenge_method"))
	}
	if aq.Get("code_challenge") == "" {
		t.Error("authorize URL carried no code_challenge")
	}
	if aq.Get("state") == "" {
		t.Error("authorize URL carried no state")
	}
	if aq.Get("scope") != "read write" {
		t.Errorf("scope = %q", aq.Get("scope"))
	}
	if aq.Get("redirect_uri") != "http://127.0.0.1:9999/callback" {
		t.Errorf("redirect_uri = %q, want the authorizer's own URI", aq.Get("redirect_uri"))
	}

	tf := as.tokenForm()
	if tf.Get("code_verifier") == "" {
		t.Error("token request carried no code_verifier")
	}
	// A public client must send client_id in the body: strict OAuth 2.1
	// servers reject Basic for token_endpoint_auth_method=none and burn the
	// single-use code doing it.
	if tf.Get("client_id") != "test-client" {
		t.Errorf("client_id in body = %q", tf.Get("client_id"))
	}
	if tf.Get("redirect_uri") != "http://127.0.0.1:9999/callback" {
		t.Errorf("token redirect_uri = %q", tf.Get("redirect_uri"))
	}
}

func TestAuthorize_WrongVerifierRejected(t *testing.T) {
	// Proves the fake AS actually enforces PKCE, so the happy-path test above
	// is not vacuous.
	as := newFakeAS(t)
	cfg := as.clientCfg()

	az := &scriptedAuthorizer{client: as.Client(), redirectURI: "http://127.0.0.1:1/cb"}
	code, redirect, err := az.Authorize(context.Background(), AuthorizeRequest{
		URL:   mustAuthURL(t, cfg, "http://127.0.0.1:1/cb", "st", challengeFor("the-real-verifier")),
		State: "st", RedirectURI: "http://127.0.0.1:1/cb",
	})
	if err != nil {
		t.Fatalf("scripted authorize: %v", err)
	}

	_, err = ExchangeCode(context.Background(), cfg, code, redirect, "a-different-verifier")
	if err == nil {
		t.Fatal("expected the token endpoint to reject a mismatched verifier")
	}
	var te *TokenError
	if !errors.As(err, &te) || !te.InvalidGrant() {
		t.Fatalf("error = %v, want invalid_grant TokenError", err)
	}
}

func TestAuthorize_ConfidentialClientUsesBasicAuth(t *testing.T) {
	var user, pass string
	var okBasic bool
	var body url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, okBasic = r.BasicAuth()
		_ = r.ParseForm()
		body = r.PostForm
		writeJSON(t, w, map[string]any{"access_token": "at", "token_type": "Bearer"})
	}))
	defer srv.Close()

	cfg := ClientConfig{
		ClientID: "cid", ClientSecret: "sec",
		TokenEndpoint: srv.URL, HTTPClient: srv.Client(),
	}
	if _, err := ExchangeCode(context.Background(), cfg, "code", "http://127.0.0.1/cb", "v"); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if !okBasic || user != "cid" || pass != "sec" {
		t.Errorf("basic auth = (%q,%q,%v)", user, pass, okBasic)
	}
	if body.Has("client_id") {
		t.Error("a confidential client must not also put client_id in the body")
	}
}

func TestExchangeCode_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": "invalid_client", "error_description": "unknown client"})
	}))
	defer srv.Close()

	_, err := ExchangeCode(context.Background(), ClientConfig{TokenEndpoint: srv.URL, HTTPClient: srv.Client()},
		"c", "", "")
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *TokenError", err)
	}
	if te.Code != "invalid_client" || te.InvalidGrant() {
		t.Errorf("TokenError = %+v", te)
	}
}

func TestRefresh_PreservesRefreshTokenWhenNotRotated(t *testing.T) {
	// Servers that do not rotate refresh tokens omit the field; dropping it
	// would make the next refresh impossible.
	as := newFakeAS(t)
	tok, err := Refresh(context.Background(), as.clientCfg(), "rt-original")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.RefreshToken != "rt-original" {
		t.Errorf("refresh_token = %q, want the original carried forward", tok.RefreshToken)
	}
	if as.tokenForm().Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", as.tokenForm().Get("grant_type"))
	}
}

func TestRefresh_RejectsEmptyToken(t *testing.T) {
	if _, err := Refresh(context.Background(), ClientConfig{TokenEndpoint: "https://x/token"}, ""); err == nil {
		t.Fatal("expected refresh with an empty token to be refused before any HTTP call")
	}
}

func TestAuthorize_NoAuthorizer(t *testing.T) {
	if _, err := Authorize(context.Background(), ClientConfig{}, nil); err == nil {
		t.Fatal("expected Authorize without an authorizer to fail")
	}
}

func TestLoopbackAuthorizer_DeliversCode(t *testing.T) {
	az := &LoopbackAuthorizer{
		Timeout: 5 * time.Second,
		Prompt:  func(string) {}, // silence the operator prompt
	}
	redirectURI, err := az.RedirectURI(context.Background())
	if err != nil {
		t.Fatalf("RedirectURI: %v", err)
	}
	if !strings.HasPrefix(redirectURI, "http://127.0.0.1:") {
		t.Fatalf("redirect URI = %q, want a loopback address", redirectURI)
	}

	done := make(chan struct{})
	az.Prompt = func(string) {
		// The listener is serving by the time the prompt fires, so the browser
		// hit is safe to simulate here.
		go func() {
			defer close(done)
			resp, err := http.Get(redirectURI + "?code=cb-code&state=the-state")
			if err != nil {
				t.Errorf("callback request: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}

	code, gotRedirect, err := az.Authorize(context.Background(), AuthorizeRequest{
		URL: "https://as.example.com/authorize", State: "the-state", RedirectURI: redirectURI,
	})
	<-done
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if code != "cb-code" {
		t.Errorf("code = %q", code)
	}
	if gotRedirect != redirectURI {
		t.Errorf("redirect = %q, want %q", gotRedirect, redirectURI)
	}
}

func TestLoopbackAuthorizer_RejectsStateMismatch(t *testing.T) {
	// Without this check an attacker's callback injects their authorization
	// code into our session (RFC 6749 §10.12).
	az := &LoopbackAuthorizer{Timeout: 5 * time.Second}
	redirectURI, err := az.RedirectURI(context.Background())
	if err != nil {
		t.Fatalf("RedirectURI: %v", err)
	}
	done := make(chan struct{})
	az.Prompt = func(string) {
		go func() {
			defer close(done)
			resp, err := http.Get(redirectURI + "?code=attacker-code&state=wrong")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}

	_, _, err = az.Authorize(context.Background(), AuthorizeRequest{State: "the-state"})
	<-done
	if err == nil {
		t.Fatal("expected a state mismatch to fail the flow")
	}
	if !strings.Contains(err.Error(), "state") {
		t.Errorf("error = %v, want it to name the state mismatch", err)
	}
}

func TestLoopbackAuthorizer_PropagatesServerError(t *testing.T) {
	az := &LoopbackAuthorizer{Timeout: 5 * time.Second}
	redirectURI, err := az.RedirectURI(context.Background())
	if err != nil {
		t.Fatalf("RedirectURI: %v", err)
	}
	done := make(chan struct{})
	az.Prompt = func(string) {
		go func() {
			defer close(done)
			resp, err := http.Get(redirectURI + "?error=access_denied&error_description=user+said+no")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}

	_, _, err = az.Authorize(context.Background(), AuthorizeRequest{State: "st"})
	<-done
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "access_denied" {
		t.Fatalf("error = %v, want an access_denied TokenError", err)
	}
}

func TestLoopbackAuthorizer_ContextCancel(t *testing.T) {
	az := &LoopbackAuthorizer{Timeout: time.Minute, Prompt: func(string) {}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, _, err := az.Authorize(ctx, AuthorizeRequest{State: "st"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestBuildAuthorizeURL_PreservesExistingQuery(t *testing.T) {
	cfg := ClientConfig{
		ClientID:     "cid",
		AuthEndpoint: "https://as.example.com/authorize?tenant=acme",
		Audience:     "https://mcp.example.com",
	}
	raw, err := BuildAuthorizeURL(cfg, "http://127.0.0.1/cb", "st", "ch")
	if err != nil {
		t.Fatalf("BuildAuthorizeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("tenant") != "acme" {
		t.Errorf("existing query param was dropped: %q", raw)
	}
	if q.Get("resource") != "https://mcp.example.com" {
		t.Errorf("resource = %q", q.Get("resource"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mustAuthURL(t *testing.T, cfg ClientConfig, redirectURI, state, challenge string) string {
	t.Helper()
	u, err := BuildAuthorizeURL(cfg, redirectURI, state, challenge)
	if err != nil {
		t.Fatalf("BuildAuthorizeURL: %v", err)
	}
	return u
}
