package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hoophq/mcpproxy/auth/outbound/oauth"
	"github.com/hoophq/mcpproxy/config"
)

// fakeProvider serves protected-resource metadata, AS metadata, dynamic client
// registration, and a token endpoint from one httptest server, so a resolver
// test exercises discovery→DCR→token in the same shape production sees.
type fakeProvider struct {
	*httptest.Server

	registrations atomic.Int32
	tokenCalls    atomic.Int32

	lastTokenForm atomic.Pointer[url.Values]

	// omitRegistration drops registration_endpoint from AS metadata.
	omitRegistration bool
	// challengeMethods overrides code_challenge_methods_supported.
	challengeMethods []string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	p := &fakeProvider{challengeMethods: []string{"S256"}}
	mux := http.NewServeMux()

	mux.HandleFunc(oauth.WellKnownResourcePath+"/mcp", func(w http.ResponseWriter, _ *http.Request) {
		p.writeJSON(t, w, map[string]any{
			"resource":              p.URL + "/mcp",
			"authorization_servers": []string{p.URL},
		})
	})
	mux.HandleFunc(oauth.WellKnownASPath, func(w http.ResponseWriter, _ *http.Request) {
		md := map[string]any{
			"issuer":                                p.URL,
			"authorization_endpoint":                p.URL + "/authorize",
			"token_endpoint":                        p.URL + "/token",
			"code_challenge_methods_supported":      p.challengeMethods,
			"token_endpoint_auth_methods_supported": []string{"none"},
		}
		if !p.omitRegistration {
			md["registration_endpoint"] = p.URL + "/register"
		}
		p.writeJSON(t, w, md)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		p.registrations.Add(1)
		w.WriteHeader(http.StatusCreated)
		p.writeJSON(t, w, map[string]any{"client_id": "dcr-client", "token_endpoint_auth_method": "none"})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect", http.StatusBadRequest)
			return
		}
		rq := redirect.Query()
		rq.Set("code", "the-code")
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		p.tokenCalls.Add(1)
		_ = r.ParseForm()
		form := r.PostForm
		p.lastTokenForm.Store(&form)
		p.writeJSON(t, w, map[string]any{
			"access_token": "upstream-at", "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": "upstream-rt",
		})
	})

	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func (p *fakeProvider) writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode: %v", err)
	}
}

// redirectFollower plays the browser: it fetches the authorize URL and reads
// the code out of the redirect.
type redirectFollower struct {
	client *http.Client
	calls  atomic.Int32
}

func (f *redirectFollower) RedirectURI(context.Context) (string, error) {
	return "http://127.0.0.1:9/callback", nil
}

func (f *redirectFollower) Authorize(ctx context.Context, req oauth.AuthorizeRequest) (string, string, error) {
	f.calls.Add(1)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return "", "", err
	}
	c := *f.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(hreq)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}
	if loc.Query().Get("state") != req.State {
		return "", "", errors.New("state mismatch")
	}
	return loc.Query().Get("code"), req.RedirectURI, nil
}

func TestResolve_NoneAndEmpty(t *testing.T) {
	for _, mode := range []string{"", "none", "NONE", " none "} {
		src, err := Resolve(context.Background(), "b",
			config.Backend{Transport: "streamable-http", URL: "https://x", Auth: mode}, Deps{})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", mode, err)
		}
		tok, err := src(context.Background())
		if err != nil || tok != "" {
			t.Errorf("mode %q yielded (%q, %v), want an empty token", mode, tok, err)
		}
	}
}

func TestResolve_StdioIgnoresAuthMode(t *testing.T) {
	// A subprocess has no HTTP request to carry a credential on; its auth is
	// the process environment.
	src, err := Resolve(context.Background(), "b",
		config.Backend{Transport: "stdio", Command: []string{"echo"}, Auth: "oauth"}, Deps{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tok, err := src(context.Background()); err != nil || tok != "" {
		t.Errorf("stdio source yielded (%q, %v)", tok, err)
	}
}

func TestResolve_Static(t *testing.T) {
	src, err := Resolve(context.Background(), "b", config.Backend{
		Transport: "streamable-http", URL: "https://x", Auth: "static",
		Headers: map[string]string{"Authorization": "Bearer configured-secret"},
	}, Deps{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "configured-secret" {
		t.Errorf("token = %q, want the header value with Bearer stripped", got)
	}
}

func TestResolve_Passthrough(t *testing.T) {
	src, err := Resolve(context.Background(), "b",
		config.Backend{Transport: "streamable-http", URL: "https://x", Auth: "passthrough"}, Deps{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, err := src(WithClientToken(context.Background(), "caller-cred"))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "caller-cred" {
		t.Errorf("token = %q", got)
	}
}

func TestResolve_UnknownMode(t *testing.T) {
	_, err := Resolve(context.Background(), "b",
		config.Backend{Transport: "streamable-http", URL: "https://x", Auth: "magic"}, Deps{})
	if err == nil {
		t.Fatal("expected an unknown auth mode to be rejected at startup")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error should name the mode, got %v", err)
	}
}

func TestResolve_OAuthDiscoveryDCRAndFlow(t *testing.T) {
	p := newFakeProvider(t)
	az := &redirectFollower{client: p.Client()}
	store := NewMemoryStore()
	clients := oauth.NewMemoryClientStore()

	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Scopes: []string{"repo"}},
	}, Deps{Store: store, Authorizer: az, ClientStore: clients, HTTPClient: p.Client()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.registrations.Load() != 1 {
		t.Errorf("registrations = %d, want DCR to run once at startup", p.registrations.Load())
	}

	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("first token: %v", err)
	}
	if got != "upstream-at" {
		t.Errorf("token = %q", got)
	}
	if az.calls.Load() != 1 {
		t.Errorf("authorizer ran %d times, want 1", az.calls.Load())
	}

	// The grant is persisted, so a later request is served without another
	// browser round trip.
	stored, err := store.Get(context.Background(), GrantKey{Backend: "github"})
	if err != nil {
		t.Fatalf("stored grant: %v", err)
	}
	if stored.RefreshToken != "upstream-rt" {
		t.Errorf("stored refresh token = %q", stored.RefreshToken)
	}
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("second token: %v", err)
	}
	if az.calls.Load() != 1 {
		t.Errorf("authorizer ran again (%d) instead of serving the cached grant", az.calls.Load())
	}

	// A registered client is reused across resolves rather than re-registered.
	if _, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Scopes: []string{"repo"}},
	}, Deps{Store: store, Authorizer: az, ClientStore: clients, HTTPClient: p.Client()}); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if p.registrations.Load() != 1 {
		t.Errorf("registrations = %d, want the stored client reused", p.registrations.Load())
	}
}

func TestResolve_OAuthManualClientSkipsDCR(t *testing.T) {
	p := newFakeProvider(t)
	az := &redirectFollower{client: p.Client()}

	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Issuer: p.URL, ClientID: "manual-id", ClientSecret: "manual-secret"},
	}, Deps{Store: NewMemoryStore(), Authorizer: az, HTTPClient: p.Client()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.registrations.Load() != 0 {
		t.Error("a manually configured client must not trigger DCR")
	}
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("token: %v", err)
	}
	if form := p.lastTokenForm.Load(); form.Has("client_id") {
		t.Error("a confidential client must authenticate with Basic, not client_id in the body")
	}
}

func TestResolve_OAuthWithoutRegistrationEndpointOrClientID(t *testing.T) {
	p := newFakeProvider(t)
	p.omitRegistration = true

	_, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
	}, Deps{HTTPClient: p.Client()})
	if err == nil {
		t.Fatal("expected a clear startup failure when neither DCR nor a client_id is available")
	}
	if !strings.Contains(err.Error(), "registration_endpoint") {
		t.Errorf("error = %v", err)
	}
}

func TestResolve_OAuthRefusesWithoutS256(t *testing.T) {
	// Registering a public client without PKCE would be a downgrade the
	// operator never asked for.
	p := newFakeProvider(t)
	p.challengeMethods = []string{"plain"}

	_, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
	}, Deps{HTTPClient: p.Client()})
	if err == nil {
		t.Fatal("expected registration to be refused without S256 PKCE")
	}
	if !strings.Contains(err.Error(), "S256") {
		t.Errorf("error = %v", err)
	}
}

func TestResolve_OAuthPerUserKeysGrantsByUser(t *testing.T) {
	p := newFakeProvider(t)
	az := &redirectFollower{client: p.Client()}
	store := NewMemoryStore()

	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Issuer: p.URL, ClientID: "cid", PerUser: true},
	}, Deps{Store: store, Authorizer: az, HTTPClient: p.Client()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// No authenticated user means we cannot tell whose grant to use; falling
	// back to a shared one would hand alice bob's upstream access.
	if _, err := src(context.Background()); err == nil {
		t.Fatal("expected a per_user backend to refuse an unauthenticated request")
	}

	for _, user := range []string{"alice", "bob"} {
		if _, err := src(WithUser(context.Background(), user)); err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if _, err := store.Get(context.Background(), GrantKey{Backend: "github", User: user}); err != nil {
			t.Errorf("no grant stored for %s: %v", user, err)
		}
	}
	if az.calls.Load() != 2 {
		t.Errorf("authorizer ran %d times, want one flow per user", az.calls.Load())
	}
	// Neither user's grant may land on the shared key.
	if _, err := store.Get(context.Background(), GrantKey{Backend: "github"}); !errors.Is(err, ErrNotFound) {
		t.Error("a per_user backend must not write a backend-wide grant")
	}

	// A repeat request reuses the stored grant.
	if _, err := src(WithUser(context.Background(), "alice")); err != nil {
		t.Fatalf("alice again: %v", err)
	}
	if az.calls.Load() != 2 {
		t.Errorf("authorizer ran %d times, want the cached grant reused", az.calls.Load())
	}
}

func TestResolve_OAuthTokenExchange(t *testing.T) {
	p := newFakeProvider(t)

	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Issuer: p.URL, ClientID: "cid", TokenExchange: true},
	}, Deps{HTTPClient: p.Client()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Exchange derives the upstream credential from the caller's own token, so
	// a request without one must fail rather than fall back to a shared grant.
	if _, err := src(context.Background()); err == nil {
		t.Fatal("expected exchange to fail without an inbound token")
	}

	got, err := src(WithInboundToken(context.Background(), "caller-jwt"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got != "upstream-at" {
		t.Errorf("token = %q", got)
	}

	form := p.lastTokenForm.Load()
	if form.Get("grant_type") != oauth.GrantTypeTokenExchange {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("subject_token") != "caller-jwt" {
		t.Errorf("subject_token = %q", form.Get("subject_token"))
	}
	if form.Get("audience") != p.URL+"/mcp" {
		t.Errorf("audience = %q, want the backend URL", form.Get("audience"))
	}
}

func TestResolve_OAuthTokenExchangeUsesDepsInboundToken(t *testing.T) {
	p := newFakeProvider(t)
	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Issuer: p.URL, ClientID: "cid", TokenExchange: true},
	}, Deps{
		HTTPClient:   p.Client(),
		InboundToken: func(context.Context) (string, error) { return "injected-jwt", nil },
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := p.lastTokenForm.Load().Get("subject_token"); got != "injected-jwt" {
		t.Errorf("subject_token = %q, want the Deps-supplied source to win", got)
	}
}

func TestResolve_UpstreamSwapWins(t *testing.T) {
	// The embedded auth server already federated the user; running our own
	// flow on top would prompt the same person twice.
	p := newFakeProvider(t)
	az := &redirectFollower{client: p.Client()}

	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Issuer: p.URL, ClientID: "cid"},
	}, Deps{
		Authorizer:   az,
		HTTPClient:   p.Client(),
		UpstreamSwap: NewStatic("swapped-token"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "swapped-token" {
		t.Errorf("token = %q", got)
	}
	if az.calls.Load() != 0 {
		t.Error("upstream swap must short-circuit the authorization flow")
	}
}

func TestResolve_OAuthWithoutAuthorizerReportsReauthorize(t *testing.T) {
	// No authorizer means nobody can complete the flow; the caller needs to
	// hear that rather than wait on a browser that will never open.
	p := newFakeProvider(t)
	src, err := Resolve(context.Background(), "github", config.Backend{
		Transport: "streamable-http", URL: p.URL + "/mcp", Auth: "oauth",
		OAuth: &config.OAuthClient{Issuer: p.URL, ClientID: "cid"},
	}, Deps{Store: NewMemoryStore(), HTTPClient: p.Client()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var reauth *oauth.ErrReauthorize
	if _, err := src(context.Background()); !errors.As(err, &reauth) {
		t.Fatalf("error = %v, want *oauth.ErrReauthorize", err)
	}
}

func TestResolve_OAuthMissingIssuerAndURL(t *testing.T) {
	_, err := Resolve(context.Background(), "b",
		config.Backend{Transport: "streamable-http", Auth: "oauth"}, Deps{})
	if err == nil {
		t.Fatal("expected oauth with neither an issuer nor a URL to be rejected")
	}
}

func TestNewLoopbackAuthorizer(t *testing.T) {
	az := NewLoopbackAuthorizer(nil)
	rp, ok := az.(oauth.RedirectURIProvider)
	if !ok {
		t.Fatal("the loopback authorizer must declare its redirect URI before the authorize URL is built")
	}
	uri, err := rp.RedirectURI(context.Background())
	if err != nil {
		t.Fatalf("RedirectURI: %v", err)
	}
	if !strings.HasPrefix(uri, "http://127.0.0.1:") || !strings.HasSuffix(uri, "/callback") {
		t.Errorf("redirect URI = %q", uri)
	}
}
