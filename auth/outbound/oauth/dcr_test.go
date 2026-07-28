package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterClient_PublicByDefault(t *testing.T) {
	var got registrationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decode registration request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(t, w, registrationResponse{ClientID: "generated-id"})
	}))
	defer srv.Close()

	c, err := RegisterClient(context.Background(), srv.URL,
		[]string{"http://127.0.0.1/callback"}, []string{"openid", "profile"},
		RegisterOptions{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	if c.ClientID != "generated-id" {
		t.Errorf("client_id = %q", c.ClientID)
	}
	if !c.Public() {
		t.Error("a client registered without Confidential must be public")
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q, want none", got.TokenEndpointAuthMethod)
	}
	if got.Scope != "openid profile" {
		t.Errorf("scope = %q", got.Scope)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "http://127.0.0.1/callback" {
		t.Errorf("redirect_uris = %v", got.RedirectURIs)
	}
}

func TestRegisterClient_Confidential(t *testing.T) {
	var got registrationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		writeJSON(t, w, registrationResponse{
			ClientID: "cid", ClientSecret: "shh", TokenEndpointAuthMethod: "client_secret_basic",
		})
	}))
	defer srv.Close()

	c, err := RegisterClient(context.Background(), srv.URL,
		[]string{"https://gw.example.com/callback"}, nil,
		RegisterOptions{Confidential: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if c.Public() {
		t.Error("a client with a secret must not report as public")
	}
	if got.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("token_endpoint_auth_method = %q", got.TokenEndpointAuthMethod)
	}
	if c.AuthMethod != "client_secret_basic" {
		t.Errorf("AuthMethod = %q", c.AuthMethod)
	}
}

func TestRegisterClient_InitialAccessToken(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		writeJSON(t, w, registrationResponse{ClientID: "cid"})
	}))
	defer srv.Close()

	if _, err := RegisterClient(context.Background(), srv.URL, []string{"http://127.0.0.1/cb"}, nil,
		RegisterOptions{InitialAccessToken: "iat-123", HTTPClient: srv.Client()}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if auth != "Bearer iat-123" {
		t.Errorf("Authorization = %q", auth)
	}
}

func TestRegisterClient_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, registrationResponse{
			Error: "invalid_redirect_uri", ErrorDescription: "loopback required",
		})
	}))
	defer srv.Close()

	_, err := RegisterClient(context.Background(), srv.URL, []string{"http://evil.example.com/cb"}, nil,
		RegisterOptions{HTTPClient: srv.Client()})
	if err == nil {
		t.Fatal("expected the registration error to surface")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "invalid_redirect_uri") || !strings.Contains(got, "loopback required") {
		t.Errorf("error should carry the server's code and description, got %q", got)
	}
}

func TestRegisterClient_RejectsEmptyRedirects(t *testing.T) {
	if _, err := RegisterClient(context.Background(), "https://as.example.com/register", nil, nil,
		RegisterOptions{}); err == nil {
		t.Fatal("expected registration without a redirect URI to be refused")
	}
}

func TestEnsureClient_RegistersOnceThenReusesStore(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeJSON(t, w, registrationResponse{ClientID: "cid"})
	}))
	defer srv.Close()

	store := NewMemoryClientStore()
	ctx := context.Background()
	for i := range 3 {
		c, err := EnsureClient(ctx, store, "https://as.example.com", srv.URL,
			[]string{"http://127.0.0.1/cb"}, nil, RegisterOptions{HTTPClient: srv.Client()})
		if err != nil {
			t.Fatalf("EnsureClient #%d: %v", i, err)
		}
		if c.ClientID != "cid" {
			t.Fatalf("client_id = %q", c.ClientID)
		}
	}
	if calls != 1 {
		t.Errorf("registration endpoint hit %d times, want 1", calls)
	}
}

func TestEnsureClient_ReregistersWhenEndpointChanged(t *testing.T) {
	// The issuer string alone does not pin the authorization server. A cached
	// client_id presented to a different one fails opaquely at token time.
	newSrv := func(id string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, registrationResponse{ClientID: id})
		}))
	}
	a, b := newSrv("from-a"), newSrv("from-b")
	defer a.Close()
	defer b.Close()

	store := NewMemoryClientStore()
	ctx := context.Background()

	if _, err := EnsureClient(ctx, store, "https://as.example.com", a.URL,
		[]string{"http://127.0.0.1/cb"}, nil, RegisterOptions{HTTPClient: a.Client()}); err != nil {
		t.Fatalf("first EnsureClient: %v", err)
	}
	c, err := EnsureClient(ctx, store, "https://as.example.com", b.URL,
		[]string{"http://127.0.0.1/cb"}, nil, RegisterOptions{HTTPClient: b.Client()})
	if err != nil {
		t.Fatalf("second EnsureClient: %v", err)
	}
	if c.ClientID != "from-b" {
		t.Errorf("client_id = %q, want a fresh registration against the new endpoint", c.ClientID)
	}
}

func TestMemoryClientStore_NotFound(t *testing.T) {
	_, err := NewMemoryClientStore().Get(context.Background(), "https://as.example.com")
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("error = %v, want ErrClientNotFound", err)
	}
}

func TestFileClientStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.enc")
	keyPath := filepath.Join(dir, "clients.key")

	store, err := NewFileClientStore(path, keyPath)
	if err != nil {
		t.Fatalf("NewFileClientStore: %v", err)
	}
	want := &Client{ClientID: "cid", ClientSecret: "shh", RegistrationEndpoint: "https://as/register"}
	if err := store.Put(context.Background(), "https://as.example.com", want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A second store over the same files must read what the first wrote.
	reopened, err := NewFileClientStore(path, keyPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := reopened.Get(context.Background(), "https://as.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientID != want.ClientID || got.ClientSecret != want.ClientSecret {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
