package authserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// testHarness is a Server behind an httptest server whose issuer matches the
// test server's own URL, so redirects and metadata are self-consistent.
type testHarness struct {
	t    *testing.T
	srv  *Server
	http *httptest.Server
	// client follows no redirects: the tests assert on the 302s themselves.
	client *http.Client
}

// TestMain silences the server's slog output. It writes to stderr, which the
// test framework does not capture, so leaving it on buries real failures.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func newHarness(t *testing.T, upstream UpstreamFederator) *testHarness {
	t.Helper()

	// The issuer must equal the listener URL, but New needs the issuer before
	// the listener exists. Start the listener first, then build the server
	// around its URL and install the handler.
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	t.Cleanup(ts.Close)

	s, err := New(config.AuthServer{Issuer: ts.URL}, upstream)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts.Config.Handler = s.Routes()

	return &testHarness{
		t:    t,
		srv:  s,
		http: ts,
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (h *testHarness) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(h.http.URL + path)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	h.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (h *testHarness) postForm(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.client.PostForm(h.http.URL+path, form)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	h.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (h *testHarness) postJSON(path, body string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Post(h.http.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	h.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var v T
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v (body: %s)", resp.Request.URL.Path, err, body)
	}
	return v
}

// register performs DCR and returns the new client id.
func (h *testHarness) register(redirectURI string) string {
	h.t.Helper()
	resp := h.postJSON("/register", `{"redirect_uris":["`+redirectURI+`"],"client_name":"test"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("register: status %d, body %s", resp.StatusCode, body)
	}
	reg := decode[registrationResponse](h.t, resp)
	if reg.ClientID == "" {
		h.t.Fatal("register returned an empty client_id")
	}
	return reg.ClientID
}

// pkce returns a verifier and its S256 challenge.
func pkce(verifier string) (string, string) {
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

const testVerifier = "a-code-verifier-long-enough-to-satisfy-rfc7636-min-length"

func TestMetadataDescribesTheServer(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.get("/.well-known/oauth-authorization-server")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	md := decode[metadata](t, resp)

	base := h.http.URL
	for _, tc := range []struct{ name, got, want string }{
		{"issuer", md.Issuer, base},
		{"authorization_endpoint", md.AuthorizationEndpoint, base + "/authorize"},
		{"token_endpoint", md.TokenEndpoint, base + "/token"},
		{"registration_endpoint", md.RegistrationEndpoint, base + "/register"},
		{"jwks_uri", md.JWKSURI, base + "/.well-known/jwks.json"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if got := md.CodeChallengeMethodsSupported; len(got) != 1 || got[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256] only (OAuth 2.1 forbids plain)", got)
	}
	if !contains(md.GrantTypesSupported, "authorization_code") || !contains(md.GrantTypesSupported, "refresh_token") {
		t.Errorf("grant_types_supported = %v, want authorization_code and refresh_token", md.GrantTypesSupported)
	}
	if !contains(md.ResponseTypesSupported, "code") {
		t.Errorf("response_types_supported = %v, want code", md.ResponseTypesSupported)
	}
}

func TestJWKSPublishesTheES256VerificationKey(t *testing.T) {
	h := newHarness(t, nil)

	set := decode[jwkSet](t, h.get("/.well-known/jwks.json"))
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
		t.Errorf("jwk = %+v, want EC/P-256/ES256/sig", k)
	}
	if k.Kid == "" {
		t.Error("jwk has no kid; clients cannot select the key")
	}
	// RFC 7518 §6.2.1.2: coordinates are fixed-width for the curve, so the
	// decoded length must be exactly 32 bytes even when the value has leading
	// zero bytes.
	for name, coord := range map[string]string{"x": k.X, "y": k.Y} {
		raw, err := base64.RawURLEncoding.DecodeString(coord)
		if err != nil {
			t.Errorf("%s is not base64url: %v", name, err)
			continue
		}
		if len(raw) != 32 {
			t.Errorf("%s decodes to %d bytes, want 32 (fixed-width P-256)", name, len(raw))
		}
	}

	// The kid in the JWKS must match the one tokens carry, or verification
	// by key lookup breaks.
	if set.Keys[0].Kid != h.srv.kid {
		t.Errorf("JWKS kid %q != signing kid %q", set.Keys[0].Kid, h.srv.kid)
	}
}

func TestRegisterIssuesAPublicClient(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.postJSON("/register", `{"redirect_uris":["http://127.0.0.1:9999/cb"],"client_name":"probe"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	reg := decode[registrationResponse](t, resp)

	if reg.ClientID == "" {
		t.Error("client_id is empty")
	}
	if reg.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q, want none (public client)", reg.TokenEndpointAuthMethod)
	}
	if len(reg.RedirectURIs) != 1 || reg.RedirectURIs[0] != "http://127.0.0.1:9999/cb" {
		t.Errorf("redirect_uris = %v, want the registered URI echoed", reg.RedirectURIs)
	}
	if reg.ClientName != "probe" {
		t.Errorf("client_name = %q, want probe", reg.ClientName)
	}
	if reg.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at is zero")
	}

	// Two registrations must not collide.
	other := h.register("http://127.0.0.1:9999/cb")
	if other == reg.ClientID {
		t.Error("two registrations returned the same client_id")
	}
}

func TestRegisterRejectsBadMetadata(t *testing.T) {
	h := newHarness(t, nil)

	tests := []struct {
		name string
		body string
	}{
		{"no redirect_uris", `{"client_name":"x"}`},
		{"empty redirect_uris", `{"redirect_uris":[]}`},
		{"relative redirect", `{"redirect_uris":["/callback"]}`},
		{"fragment in redirect", `{"redirect_uris":["http://127.0.0.1:1/cb#frag"]}`},
		{"opaque scheme", `{"redirect_uris":["weird:/cb"]}`},
		{"not json", `not json at all`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.postJSON("/register", tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if e := decode[oauthError](t, resp); e.Error == "" {
				t.Error("error response carries no error code")
			}
		})
	}
}

// authorize drives GET /authorize and returns the parsed redirect Location.
func (h *testHarness) authorize(params url.Values) *url.URL {
	h.t.Helper()
	resp := h.get("/authorize?" + params.Encode())
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("authorize: status %d, want 302; body %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		h.t.Fatalf("parse Location: %v", err)
	}
	return loc
}

func TestFullCodeFlowWithAutoApproval(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newHarness(t, nil)
	clientID := h.register(redirectURI)
	verifier, challenge := pkce(testVerifier)

	loc := h.authorize(url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"client-state-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"mcp"},
	})

	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != redirectURI {
		t.Fatalf("redirected to %q, want the client's redirect_uri %q", got, redirectURI)
	}
	if got := loc.Query().Get("state"); got != "client-state-123" {
		t.Errorf("state = %q, want it echoed back", got)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %s", loc)
	}

	resp := h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token: status %d, body %s", resp.StatusCode, body)
	}
	tok := decode[tokenResponse](t, resp)
	if tok.AccessToken == "" {
		t.Fatal("no access_token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", tok.TokenType)
	}
	if tok.RefreshToken == "" {
		t.Error("no refresh_token")
	}
	if want := int64(defaultAccessTokenTTL / time.Second); tok.ExpiresIn != want {
		t.Errorf("expires_in = %d, want %d (default TTL)", tok.ExpiresIn, want)
	}

	// The gateway must accept its own token.
	id, err := h.srv.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if id.Subject != devSubject {
		t.Errorf("subject = %q, want %q", id.Subject, devSubject)
	}
	if id.Email == "" {
		t.Error("identity has no email claim")
	}
	if aud, _ := id.Claims["aud"].(string); aud != clientID {
		t.Errorf("aud = %v, want the client_id %q", id.Claims["aud"], clientID)
	}
	if iss, _ := id.Claims["iss"].(string); iss != h.http.URL {
		t.Errorf("iss = %v, want %q", id.Claims["iss"], h.http.URL)
	}

	// A "Bearer " prefix is tolerated so callers can pass the raw header.
	if _, err := h.srv.ValidateToken(context.Background(), "Bearer "+tok.AccessToken); err != nil {
		t.Errorf("ValidateToken with Bearer prefix: %v", err)
	}
}

func TestTokenRejectsBadVerifierAndCodeReuse(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"

	newCode := func(h *testHarness, clientID, challenge string) string {
		loc := h.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		})
		return loc.Query().Get("code")
	}

	t.Run("wrong verifier", func(t *testing.T) {
		h := newHarness(t, nil)
		clientID := h.register(redirectURI)
		_, challenge := pkce(testVerifier)
		code := newCode(h, clientID, challenge)

		resp := h.postForm("/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {"b-different-verifier-also-long-enough-for-rfc7636-rules"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decode[oauthError](t, resp); e.Error != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", e.Error)
		}
	})

	t.Run("missing verifier", func(t *testing.T) {
		h := newHarness(t, nil)
		clientID := h.register(redirectURI)
		_, challenge := pkce(testVerifier)
		code := newCode(h, clientID, challenge)

		resp := h.postForm("/token", url.Values{
			"grant_type": {"authorization_code"},
			"code":       {code},
			"client_id":  {clientID},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("code is one-time", func(t *testing.T) {
		h := newHarness(t, nil)
		clientID := h.register(redirectURI)
		verifier, challenge := pkce(testVerifier)
		code := newCode(h, clientID, challenge)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {verifier},
		}
		if resp := h.postForm("/token", form); resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("first redemption: status %d, body %s", resp.StatusCode, body)
		}
		resp := h.postForm("/token", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("replay: status = %d, want 400", resp.StatusCode)
		}
		if e := decode[oauthError](t, resp); e.Error != "invalid_grant" {
			t.Errorf("replay error = %q, want invalid_grant", e.Error)
		}
	})

	t.Run("code bound to its client", func(t *testing.T) {
		h := newHarness(t, nil)
		clientID := h.register(redirectURI)
		other := h.register(redirectURI)
		verifier, challenge := pkce(testVerifier)
		code := newCode(h, clientID, challenge)

		resp := h.postForm("/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {other},
			"code_verifier": {verifier},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 when another client redeems the code", resp.StatusCode)
		}
	})

	t.Run("expired code", func(t *testing.T) {
		h := newHarness(t, nil)
		clientID := h.register(redirectURI)
		verifier, challenge := pkce(testVerifier)

		base := time.Now()
		h.srv.now = func() time.Time { return base }
		code := newCode(h, clientID, challenge)

		h.srv.now = func() time.Time { return base.Add(codeTTL + time.Second) }
		resp := h.postForm("/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {verifier},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for an expired code", resp.StatusCode)
		}
	})
}

func TestAuthorizeRejectsBadRequests(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newHarness(t, nil)
	clientID := h.register(redirectURI)
	_, challenge := pkce(testVerifier)

	base := func() url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
	}

	// Unvalidated client/redirect: the error must be rendered, never
	// redirected, or we become an open redirector.
	t.Run("unknown client renders the error", func(t *testing.T) {
		v := base()
		v.Set("client_id", "nope")
		resp := h.get("/authorize?" + v.Encode())
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decode[oauthError](t, resp); e.Error != "invalid_client" {
			t.Errorf("error = %q, want invalid_client", e.Error)
		}
	})

	t.Run("unregistered redirect renders the error", func(t *testing.T) {
		v := base()
		v.Set("redirect_uri", "http://evil.example/steal")
		resp := h.get("/authorize?" + v.Encode())
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (never redirect to an unregistered URI)", resp.StatusCode)
		}
	})

	// Validated pair: errors go back to the client as redirect params.
	redirected := []struct {
		name    string
		mutate  func(url.Values)
		wantErr string
	}{
		{"no challenge", func(v url.Values) { v.Del("code_challenge") }, "invalid_request"},
		{"plain challenge method", func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"absent challenge method", func(v url.Values) { v.Del("code_challenge_method") }, "invalid_request"},
		{"token response type", func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
	}
	for _, tc := range redirected {
		t.Run(tc.name, func(t *testing.T) {
			v := base()
			v.Set("state", "st")
			tc.mutate(v)
			loc := h.authorize(v)
			if got := loc.Query().Get("error"); got != tc.wantErr {
				t.Errorf("error = %q, want %q (in redirect %s)", got, tc.wantErr, loc)
			}
			if got := loc.Query().Get("state"); got != "st" {
				t.Errorf("state = %q, want it echoed on the error redirect", got)
			}
			if loc.Query().Get("code") != "" {
				t.Error("error redirect must not carry a code")
			}
		})
	}
}

func TestRefreshTokenRotates(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newHarness(t, nil)
	clientID := h.register(redirectURI)
	verifier, challenge := pkce(testVerifier)

	loc := h.authorize(url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"mcp"},
	})
	first := decode[tokenResponse](t, h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}))
	if first.AccessToken == "" {
		t.Fatal("no access token from the code grant")
	}

	resp := h.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {clientID},
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("refresh: status %d, body %s", resp.StatusCode, body)
	}
	second := decode[tokenResponse](t, resp)
	if second.RefreshToken == "" {
		t.Fatal("refresh response carried no new refresh token")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token was not rotated")
	}
	if second.Scope != "mcp" {
		t.Errorf("scope = %q, want the originally granted mcp", second.Scope)
	}

	// The rotated-away token must be dead.
	replay := h.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {clientID},
	})
	if replay.StatusCode != http.StatusBadRequest {
		t.Errorf("replaying the old refresh token: status %d, want 400", replay.StatusCode)
	}

	// The new access token must still identify the same user.
	id, err := h.srv.ValidateToken(context.Background(), second.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken after refresh: %v", err)
	}
	if id.Subject != devSubject {
		t.Errorf("subject after refresh = %q, want %q", id.Subject, devSubject)
	}

	// The fresh one keeps working.
	if r := h.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {second.RefreshToken},
		"client_id":     {clientID},
	}); r.StatusCode != http.StatusOK {
		t.Errorf("refreshing with the rotated token: status %d, want 200", r.StatusCode)
	}
}

func TestTokenRejectsUnknownGrantTypes(t *testing.T) {
	h := newHarness(t, nil)

	for _, tc := range []struct{ name, grant, wantErr string }{
		{"missing", "", "invalid_request"},
		{"password", "password", "unsupported_grant_type"},
		{"client_credentials", "client_credentials", "unsupported_grant_type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := url.Values{}
			if tc.grant != "" {
				v.Set("grant_type", tc.grant)
			}
			resp := h.postForm("/token", v)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if e := decode[oauthError](t, resp); e.Error != tc.wantErr {
				t.Errorf("error = %q, want %q", e.Error, tc.wantErr)
			}
		})
	}
}

func TestValidateTokenRejectsForeignAndExpiredTokens(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newHarness(t, nil)
	other := newHarness(t, nil)

	mint := func(hh *testHarness) string {
		hh.t.Helper()
		clientID := hh.register(redirectURI)
		verifier, challenge := pkce(testVerifier)
		loc := hh.authorize(url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		})
		return decode[tokenResponse](hh.t, hh.postForm("/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {loc.Query().Get("code")},
			"client_id":     {clientID},
			"code_verifier": {verifier},
		})).AccessToken
	}

	mine := mint(h)
	theirs := mint(other)

	if _, err := h.srv.ValidateToken(context.Background(), theirs); err == nil {
		t.Error("accepted a token signed by another server's key")
	}
	if _, err := h.srv.ValidateToken(context.Background(), ""); err == nil {
		t.Error("accepted an empty token")
	}
	if _, err := h.srv.ValidateToken(context.Background(), "not.a.jwt"); err == nil {
		t.Error("accepted a malformed token")
	}

	// alg=none must not be accepted even though the claims look right.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + h.http.URL + `","sub":"attacker","exp":` +
			strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`))
	if _, err := h.srv.ValidateToken(context.Background(), hdr+"."+payload+"."); err == nil {
		t.Error("accepted an alg=none token")
	}

	// Same token, clock moved past exp.
	if _, err := h.srv.ValidateToken(context.Background(), mine); err != nil {
		t.Fatalf("own token rejected before expiry: %v", err)
	}
	h.srv.now = func() time.Time { return time.Now().Add(defaultAccessTokenTTL + time.Minute) }
	if _, err := h.srv.ValidateToken(context.Background(), mine); err == nil {
		t.Error("accepted an expired token")
	}
}

func TestResolverReadsTheAuthorizationHeader(t *testing.T) {
	const redirectURI = "http://127.0.0.1:7777/callback"
	h := newHarness(t, nil)
	clientID := h.register(redirectURI)
	verifier, challenge := pkce(testVerifier)
	loc := h.authorize(url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
	tok := decode[tokenResponse](t, h.postForm("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	id, err := h.srv.Resolver(req)
	if err != nil {
		t.Fatalf("Resolver: %v", err)
	}
	if id.Subject != devSubject {
		t.Errorf("subject = %q, want %q", id.Subject, devSubject)
	}

	if _, err := h.srv.Resolver(httptest.NewRequest(http.MethodPost, "/mcp", nil)); err == nil {
		t.Error("Resolver accepted a request with no Authorization header")
	}
}

func TestNewRequiresIssuer(t *testing.T) {
	if _, err := New(config.AuthServer{}, nil); err == nil {
		t.Fatal("New accepted an empty issuer")
	}
}

func TestSigningKeyIsPersistedAndReused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "signing.pem")

	cfg := config.AuthServer{Issuer: "https://gw.example", SigningKeyFile: path}
	first, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", perm)
	}

	second, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	if first.kid != second.kid {
		t.Errorf("kid changed across restart: %q -> %q; tokens would stop verifying", first.kid, second.kid)
	}

	// A token from the first instance must verify on the second — that is the
	// observable reason to persist the key at all.
	tokenStr, err := first.signAccessToken("client", "alice", "alice@example.com", "", time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	id, err := second.ValidateToken(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("reloaded server rejected a token from the original: %v", err)
	}
	if id.Subject != "alice" || id.Email != "alice@example.com" {
		t.Errorf("identity = %+v, want alice", id)
	}
}

func TestSigningKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("this is not a PEM file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.AuthServer{Issuer: "https://gw.example", SigningKeyFile: path}, nil); err == nil {
		t.Fatal("New accepted an unparseable signing key file")
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier, challenge := pkce(testVerifier)

	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{"match", verifier, challenge, true},
		{"mismatch", "z-another-verifier-that-is-also-long-enough-for-the-rules", challenge, false},
		{"empty verifier", "", challenge, false},
		{"empty challenge", verifier, "", false},
		{"too short", "short", "", false},
		{"exactly 42 chars is too short", strings.Repeat("a", 42), s256(strings.Repeat("a", 42)), false},
		{"exactly 43 chars is ok", strings.Repeat("a", 43), s256(strings.Repeat("a", 43)), true},
		{"exactly 128 chars is ok", strings.Repeat("a", 128), s256(strings.Repeat("a", 128)), true},
		{"129 chars is too long", strings.Repeat("a", 129), s256(strings.Repeat("a", 129)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyPKCE(tc.verifier, tc.challenge); got != tc.want {
				t.Errorf("verifyPKCE = %v, want %v", got, tc.want)
			}
		})
	}
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func contains(list []string, want string) bool {
	return slices.Contains(list, want)
}
