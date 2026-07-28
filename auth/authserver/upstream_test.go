package authserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound"
	"github.com/hoophq/mcpproxy/config"
)

// fakeIdP is a minimal OIDC provider: discovery, an authorization endpoint
// that redirects straight back with no login UI, and a token endpoint
// returning an unsigned ID token. Unsigned matches what the code under test
// does. Exchange reads the ID token's claims without verifying the signature,
// trusting the authenticated TLS channel to the token endpoint instead.
type fakeIdP struct {
	server *httptest.Server

	// Recorded from the last authorization request.
	lastAuthQuery url.Values
	// Recorded from the last token request.
	lastTokenForm url.Values

	// Knobs.
	subject      string
	email        string
	issuerClaim  string // overrides the ID token's iss when non-empty
	omitIDToken  bool
	accessToken  string
	refreshToken string
	expiresIn    int
	tokenStatus  int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{
		subject:      "upstream-sub-42",
		email:        "user@corp.example",
		accessToken:  "upstream-access-token",
		refreshToken: "upstream-refresh-token",
		expiresIn:    3600,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		base := idp.server.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/auth",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		idp.lastAuthQuery = r.URL.Query()
		// Bounce back with a code, as if the user had logged in.
		back, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := back.Query()
		q.Set("code", "upstream-code")
		q.Set("state", r.URL.Query().Get("state"))
		back.RawQuery = q.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.lastTokenForm = r.PostForm
		if idp.tokenStatus != 0 && idp.tokenStatus != http.StatusOK {
			w.WriteHeader(idp.tokenStatus)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		body := map[string]any{
			"access_token":  idp.accessToken,
			"token_type":    "Bearer",
			"expires_in":    idp.expiresIn,
			"refresh_token": idp.refreshToken,
		}
		if !idp.omitIDToken {
			iss := idp.server.URL
			if idp.issuerClaim != "" {
				iss = idp.issuerClaim
			}
			body["id_token"] = unsignedJWT(map[string]any{
				"iss":   iss,
				"sub":   idp.subject,
				"email": idp.email,
				"aud":   "gateway-client",
				"exp":   time.Now().Add(time.Hour).Unix(),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// unsignedJWT builds a JWT with an empty signature: enough structure for a
// claims parse, and no pretense of exercising signature verification.
func unsignedJWT(claims map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return hdr + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// federatedHarness wires a gateway auth server to a fake IdP.
type federatedHarness struct {
	*testHarness
	idp *fakeIdP
}

func newFederatedHarness(t *testing.T) *federatedHarness {
	t.Helper()
	idp := newFakeIdP(t)

	// The gateway's own listener must exist before anything can name its
	// /callback URL to the federator, so start it empty and install the
	// handler after.
	gw := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(gw.Close)

	fed, err := NewOIDCFederator(context.Background(), config.OAuthClient{
		Issuer:       idp.server.URL,
		ClientID:     "gateway-client",
		ClientSecret: "gateway-secret",
		Scopes:       []string{"profile"},
	}, gw.URL+"/callback", nil)
	if err != nil {
		t.Fatalf("NewOIDCFederator: %v", err)
	}

	s, err := New(config.AuthServer{Issuer: gw.URL}, fed)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.Config.Handler = s.Routes()

	return &federatedHarness{
		testHarness: &testHarness{
			t:    t,
			srv:  s,
			http: gw,
			client: &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
		},
		idp: idp,
	}
}

// login walks the federated flow end to end and returns the token response.
func (h *federatedHarness) login(clientID, redirectURI, verifier, challenge string) tokenResponse {
	h.t.Helper()

	// /authorize must bounce the caller to the IdP rather than the client.
	toIdP := h.authorize(url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"client-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
	if !strings.HasPrefix(toIdP.String(), h.idp.server.URL) {
		h.t.Fatalf("authorize redirected to %s, want the upstream IdP at %s", toIdP, h.idp.server.URL)
	}

	// Follow the IdP redirect back to the gateway's /callback.
	idpResp, err := h.client.Get(toIdP.String())
	if err != nil {
		h.t.Fatalf("GET upstream authorize: %v", err)
	}
	idpResp.Body.Close()
	if idpResp.StatusCode != http.StatusFound {
		h.t.Fatalf("upstream authorize: status %d, want 302", idpResp.StatusCode)
	}
	cbResp, err := h.client.Get(idpResp.Header.Get("Location"))
	if err != nil {
		h.t.Fatalf("GET callback: %v", err)
	}
	defer cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(cbResp.Body)
		h.t.Fatalf("callback: status %d, want 302; body %s", cbResp.StatusCode, body)
	}

	toClient, err := url.Parse(cbResp.Header.Get("Location"))
	if err != nil {
		h.t.Fatalf("parse client redirect: %v", err)
	}
	if got := toClient.Scheme + "://" + toClient.Host + toClient.Path; got != redirectURI {
		h.t.Fatalf("callback redirected to %q, want the client's %q", got, redirectURI)
	}
	if got := toClient.Query().Get("state"); got != "client-state" {
		h.t.Errorf("state = %q, want the client's own state round-tripped", got)
	}
	code := toClient.Query().Get("code")
	if code == "" {
		h.t.Fatalf("no code in the client redirect %s", toClient)
	}

	resp := h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("token: status %d, body %s", resp.StatusCode, body)
	}
	return decode[tokenResponse](h.t, resp)
}

func TestFederatedLoginExtractsIdentityAndKeepsUpstreamTokens(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newFederatedHarness(t)
	clientID := h.register(redirectURI)
	verifier, challenge := pkce(testVerifier)

	tok := h.login(clientID, redirectURI, verifier, challenge)

	// The upstream authorize request must be well-formed.
	if got := h.idp.lastAuthQuery.Get("client_id"); got != "gateway-client" {
		t.Errorf("upstream client_id = %q, want gateway-client", got)
	}
	if got := h.idp.lastAuthQuery.Get("response_type"); got != "code" {
		t.Errorf("upstream response_type = %q, want code", got)
	}
	if got := h.idp.lastAuthQuery.Get("state"); got == "" {
		t.Error("upstream request carried no state")
	} else if got == "client-state" {
		t.Error("upstream state leaked the client's state; it must be our internal grant id")
	}
	if scope := h.idp.lastAuthQuery.Get("scope"); !strings.Contains(scope, "openid") {
		t.Errorf("upstream scope = %q, want openid included (needed for the ID token)", scope)
	}
	if scope := h.idp.lastAuthQuery.Get("scope"); !strings.Contains(scope, "profile") {
		t.Errorf("upstream scope = %q, want the configured profile scope", scope)
	}

	// The gateway's access token must carry the upstream identity,
	// namespaced by issuer.
	wantSubject := h.idp.server.URL + "#" + h.idp.subject
	id, err := h.srv.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if id.Subject != wantSubject {
		t.Errorf("subject = %q, want %q (issuer-namespaced upstream sub)", id.Subject, wantSubject)
	}
	if id.Email != h.idp.email {
		t.Errorf("email = %q, want %q", id.Email, h.idp.email)
	}

	// The server must retain the upstream tokens under that subject.
	up, ok := h.srv.UpstreamTokens(wantSubject)
	if !ok {
		t.Fatalf("no upstream tokens stored for %q", wantSubject)
	}
	if up.AccessToken != h.idp.accessToken {
		t.Errorf("upstream access token = %q, want %q", up.AccessToken, h.idp.accessToken)
	}
	if up.RefreshToken != h.idp.refreshToken {
		t.Errorf("upstream refresh token = %q, want %q", up.RefreshToken, h.idp.refreshToken)
	}

	// The swap source must hand that token to a backend call.
	src := NewUpstreamSwapSource(h.srv)
	got, err := src(outbound.WithUser(context.Background(), wantSubject))
	if err != nil {
		t.Fatalf("swap source: %v", err)
	}
	if got != h.idp.accessToken {
		t.Errorf("swap source returned %q, want the upstream access token %q", got, h.idp.accessToken)
	}
}

func TestSwapSourceFailsWithoutAUsableToken(t *testing.T) {
	h := newHarness(t, nil)
	src := NewUpstreamSwapSource(h.srv)

	t.Run("no user in context", func(t *testing.T) {
		if _, err := src(context.Background()); err == nil {
			t.Fatal("swap source succeeded with no user in context")
		}
	})

	t.Run("user has never logged in", func(t *testing.T) {
		_, err := src(outbound.WithUser(context.Background(), "stranger"))
		if err == nil {
			t.Fatal("swap source succeeded for an unknown subject")
		}
		if !strings.Contains(err.Error(), "stranger") {
			t.Errorf("error %v should name the subject", err)
		}
	})

	t.Run("stored token has expired", func(t *testing.T) {
		base := time.Now()
		h.srv.now = func() time.Time { return base }
		h.srv.store.putUpstream("alice", &outbound.Token{
			AccessToken: "stale",
			Expiry:      base.Add(time.Minute),
		})
		if _, err := src(outbound.WithUser(context.Background(), "alice")); err != nil {
			t.Fatalf("valid token rejected: %v", err)
		}
		h.srv.now = func() time.Time { return base.Add(2 * time.Minute) }
		if _, err := src(outbound.WithUser(context.Background(), "alice")); err == nil {
			t.Fatal("swap source returned an expired upstream token")
		}
	})

	t.Run("empty subject", func(t *testing.T) {
		if _, err := h.srv.UpstreamAccessToken(""); err == nil {
			t.Fatal("UpstreamAccessToken accepted an empty subject")
		}
	})
}

func TestCallbackRejectsUnknownAndReplayedState(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newFederatedHarness(t)
	clientID := h.register(redirectURI)
	_, challenge := pkce(testVerifier)

	t.Run("unknown state", func(t *testing.T) {
		resp := h.get("/callback?code=x&state=never-issued")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("no state", func(t *testing.T) {
		resp := h.get("/callback?code=x")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("state is single-use", func(t *testing.T) {
		toIdP := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		})
		state := toIdP.Query().Get("state")

		first := h.get("/callback?code=upstream-code&state=" + state)
		if first.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(first.Body)
			t.Fatalf("first callback: status %d, want 302; body %s", first.StatusCode, body)
		}
		second := h.get("/callback?code=upstream-code&state=" + state)
		if second.StatusCode != http.StatusBadRequest {
			t.Errorf("replayed callback: status %d, want 400", second.StatusCode)
		}
	})
}

func TestCallbackSurfacesUpstreamFailures(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"

	startFlow := func(h *federatedHarness, clientID, challenge string) string {
		h.t.Helper()
		toIdP := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"state":                 {"cs"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		})
		return toIdP.Query().Get("state")
	}

	tests := []struct {
		name    string
		setup   func(*federatedHarness)
		query   func(state string) string
		wantErr string
	}{
		{
			name:    "IdP denied the request",
			query:   func(s string) string { return "/callback?error=access_denied&state=" + s },
			wantErr: "access_denied",
		},
		{
			name:    "IdP returned no code",
			query:   func(s string) string { return "/callback?state=" + s },
			wantErr: "invalid_request",
		},
		{
			name:    "token endpoint failed",
			setup:   func(h *federatedHarness) { h.idp.tokenStatus = http.StatusBadRequest },
			query:   func(s string) string { return "/callback?code=c&state=" + s },
			wantErr: "access_denied",
		},
		{
			name:    "no ID token",
			setup:   func(h *federatedHarness) { h.idp.omitIDToken = true },
			query:   func(s string) string { return "/callback?code=c&state=" + s },
			wantErr: "access_denied",
		},
		{
			name:    "ID token from a different issuer",
			setup:   func(h *federatedHarness) { h.idp.issuerClaim = "https://attacker.example" },
			query:   func(s string) string { return "/callback?code=c&state=" + s },
			wantErr: "access_denied",
		},
		{
			name:    "ID token without a subject",
			setup:   func(h *federatedHarness) { h.idp.subject = "" },
			query:   func(s string) string { return "/callback?code=c&state=" + s },
			wantErr: "access_denied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newFederatedHarness(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			clientID := h.register(redirectURI)
			_, challenge := pkce(testVerifier)
			state := startFlow(h, clientID, challenge)

			resp := h.get(tc.query(state))
			if resp.StatusCode != http.StatusFound {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want a 302 error redirect; body %s", resp.StatusCode, body)
			}
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if got := loc.Query().Get("error"); got != tc.wantErr {
				t.Errorf("error = %q, want %q (redirect %s)", got, tc.wantErr, loc)
			}
			if loc.Query().Get("code") != "" {
				t.Error("failed callback must not hand the client a code")
			}
			if got := loc.Query().Get("state"); got != "cs" {
				t.Errorf("state = %q, want the client's state echoed", got)
			}
		})
	}
}

func TestCallbackIsNotMountedWithoutAnUpstream(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.get("/callback?code=x&state=y")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no IdP is configured", resp.StatusCode)
	}
}

func TestExchangeSendsTheRegisteredRedirectURI(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newFederatedHarness(t)
	clientID := h.register(redirectURI)
	verifier, challenge := pkce(testVerifier)

	h.login(clientID, redirectURI, verifier, challenge)

	form := h.idp.lastTokenForm
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("upstream grant_type = %q, want authorization_code", got)
	}
	if got := form.Get("code"); got != "upstream-code" {
		t.Errorf("upstream code = %q, want upstream-code", got)
	}
	// The redirect_uri at the token endpoint must match the one used at the
	// authorization endpoint, or a conforming IdP rejects the exchange.
	wantRedirect := h.idp.lastAuthQuery.Get("redirect_uri")
	if got := form.Get("redirect_uri"); got != wantRedirect {
		t.Errorf("upstream token redirect_uri = %q, want %q", got, wantRedirect)
	}
}

func TestNewOIDCFederatorValidatesConfig(t *testing.T) {
	idp := newFakeIdP(t)
	ctx := context.Background()

	tests := []struct {
		name        string
		cfg         config.OAuthClient
		redirectURI string
	}{
		{"no issuer", config.OAuthClient{ClientID: "c"}, "http://127.0.0.1/cb"},
		{"no client id", config.OAuthClient{Issuer: idp.server.URL}, "http://127.0.0.1/cb"},
		{"no redirect", config.OAuthClient{Issuer: idp.server.URL, ClientID: "c"}, ""},
		{"undiscoverable issuer", config.OAuthClient{Issuer: "http://127.0.0.1:1/nope", ClientID: "c"}, "http://127.0.0.1/cb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewOIDCFederator(ctx, tc.cfg, tc.redirectURI, nil); err == nil {
				t.Fatal("NewOIDCFederator accepted an invalid configuration")
			}
		})
	}
}

func TestAuthorizeURLCarriesState(t *testing.T) {
	idp := newFakeIdP(t)
	fed, err := NewOIDCFederator(context.Background(), config.OAuthClient{
		Issuer:   idp.server.URL,
		ClientID: "c",
	}, "http://127.0.0.1:1/cb", nil)
	if err != nil {
		t.Fatalf("NewOIDCFederator: %v", err)
	}

	raw, err := fed.AuthorizeURL("grant-id-xyz")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := u.Query().Get("state"); got != "grant-id-xyz" {
		t.Errorf("state = %q, want grant-id-xyz", got)
	}
	if got := u.Query().Get("redirect_uri"); got != "http://127.0.0.1:1/cb" {
		t.Errorf("redirect_uri = %q", got)
	}

	if _, err := fed.AuthorizeURL(""); err == nil {
		t.Error("AuthorizeURL accepted an empty state")
	}
}

func TestIdentityFromClaims(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]any
		issuer      string
		wantSubject string
		wantEmail   string
		wantErr     bool
	}{
		{
			name:        "email claim",
			claims:      map[string]any{"sub": "u1", "email": "a@b.c"},
			issuer:      "https://idp.example",
			wantSubject: "https://idp.example#u1",
			wantEmail:   "a@b.c",
		},
		{
			name:        "falls back to preferred_username",
			claims:      map[string]any{"sub": "u1", "preferred_username": "a@b.c"},
			issuer:      "https://idp.example",
			wantSubject: "https://idp.example#u1",
			wantEmail:   "a@b.c",
		},
		{
			name:        "trailing slash issuer normalized",
			claims:      map[string]any{"sub": "u1"},
			issuer:      "https://idp.example/",
			wantSubject: "https://idp.example#u1",
		},
		{
			name:        "no issuer leaves sub bare",
			claims:      map[string]any{"sub": "u1"},
			wantSubject: "u1",
		},
		{
			name:    "no sub is an error",
			claims:  map[string]any{"email": "a@b.c"},
			issuer:  "https://idp.example",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sub, email, err := identityFromClaims(tc.claims, tc.issuer)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("identityFromClaims: %v", err)
			}
			if sub != tc.wantSubject {
				t.Errorf("subject = %q, want %q", sub, tc.wantSubject)
			}
			if email != tc.wantEmail {
				t.Errorf("email = %q, want %q", email, tc.wantEmail)
			}
		})
	}
}

func TestParseJWTClaimsRejectsMalformedTokens(t *testing.T) {
	for _, raw := range []string{"", "a.b", "a.b.c.d", "a.!!!.c"} {
		if _, err := parseJWTClaims(raw); err == nil {
			t.Errorf("parseJWTClaims(%q) succeeded, want an error", raw)
		}
	}
	claims, err := parseJWTClaims(unsignedJWT(map[string]any{"sub": "x"}))
	if err != nil {
		t.Fatalf("parseJWTClaims: %v", err)
	}
	if claims["sub"] != "x" {
		t.Errorf("sub = %v, want x", claims["sub"])
	}
}
