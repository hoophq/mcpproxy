package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// exchangeAS records every token request and answers with a token derived from
// the subject it was given, so the test can prove which subject produced which
// upstream credential.
type exchangeAS struct {
	*httptest.Server

	calls atomic.Int32

	mu    sync.Mutex
	forms []url.Values

	expiresIn int
}

func newExchangeAS(t *testing.T) *exchangeAS {
	t.Helper()
	as := &exchangeAS{expiresIn: 3600}
	as.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		as.calls.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		as.mu.Lock()
		as.forms = append(as.forms, r.PostForm)
		as.mu.Unlock()

		resp := map[string]any{
			"access_token":      "upstream-for-" + r.PostForm.Get("subject_token"),
			"issued_token_type": TokenTypeAccessToken,
			"token_type":        "Bearer",
		}
		if as.expiresIn != 0 {
			resp["expires_in"] = as.expiresIn
		}
		writeJSON(t, w, resp)
	}))
	t.Cleanup(as.Close)
	return as
}

func (as *exchangeAS) form(i int) url.Values {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.forms[i]
}

func TestExchangeSource_SendsRFC8693Request(t *testing.T) {
	as := newExchangeAS(t)
	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: as.URL,
		ClientID:      "gateway",
		ClientSecret:  "secret",
		SubjectToken:  func(context.Context) (string, error) { return "inbound-jwt", nil },
		Audience:      "https://mcp.example.com",
		Scopes:        []string{"read", "write"},
		Resource:      "https://mcp.example.com/mcp",
		HTTPClient:    as.Client(),
	})

	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got != "upstream-for-inbound-jwt" {
		t.Errorf("token = %q", got)
	}

	f := as.form(0)
	checks := map[string]string{
		"grant_type":           GrantTypeTokenExchange,
		"subject_token":        "inbound-jwt",
		"subject_token_type":   TokenTypeAccessToken,
		"requested_token_type": TokenTypeAccessToken,
		"audience":             "https://mcp.example.com",
		"scope":                "read write",
		"resource":             "https://mcp.example.com/mcp",
	}
	for k, want := range checks {
		if got := f.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// A confidential client authenticates with Basic, not by putting the id in
	// the body.
	if f.Has("client_id") {
		t.Error("client_id must not be in the body for a confidential client")
	}
}

func TestExchangeSource_CachesUntilExpiry(t *testing.T) {
	as := newExchangeAS(t)
	now := time.Now()
	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: as.URL,
		SubjectToken:  func(context.Context) (string, error) { return "same-subject", nil },
		Now:           func() time.Time { return now },
		HTTPClient:    as.Client(),
	})

	for i := range 5 {
		if _, err := src(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := as.calls.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1", got)
	}
}

func TestExchangeSource_ReexchangesAfterExpiry(t *testing.T) {
	as := newExchangeAS(t)
	as.expiresIn = 60

	now := time.Now()
	clock := func() time.Time { return now }
	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: as.URL,
		SubjectToken:  func(context.Context) (string, error) { return "s", nil },
		Now:           func() time.Time { return clock() },
		HTTPClient:    as.Client(),
	})

	if _, err := src(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := as.calls.Load(); got != 2 {
		t.Errorf("token endpoint hit %d times, want 2", got)
	}
}

func TestExchangeSource_DifferentSubjectsDoNotShareTokens(t *testing.T) {
	// Two users hitting the same backend must never share an exchanged token.
	as := newExchangeAS(t)
	var subject atomic.Value
	subject.Store("alice-jwt")

	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: as.URL,
		SubjectToken:  func(context.Context) (string, error) { return subject.Load().(string), nil },
		HTTPClient:    as.Client(),
	})

	first, err := src(context.Background())
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	subject.Store("bob-jwt")
	second, err := src(context.Background())
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	if first == second {
		t.Fatal("a new subject token must invalidate the cached exchange")
	}
	if second != "upstream-for-bob-jwt" {
		t.Errorf("second token = %q", second)
	}
	if got := as.calls.Load(); got != 2 {
		t.Errorf("token endpoint hit %d times, want 2", got)
	}
}

func TestExchangeSource_PublicClientSendsClientIDInBody(t *testing.T) {
	as := newExchangeAS(t)
	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: as.URL,
		ClientID:      "public-gateway",
		SubjectToken:  func(context.Context) (string, error) { return "s", nil },
		HTTPClient:    as.Client(),
	})
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := as.form(0).Get("client_id"); got != "public-gateway" {
		t.Errorf("client_id = %q", got)
	}
}

func TestExchangeSource_MissingSubjectToken(t *testing.T) {
	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: "http://127.0.0.1:1/never",
		SubjectToken:  func(context.Context) (string, error) { return "", nil },
	})
	_, err := src(context.Background())
	if err == nil {
		t.Fatal("expected an error when the caller presented no subject token")
	}
	if !strings.Contains(err.Error(), "subject token") {
		t.Errorf("error = %v, want it to name the missing subject token", err)
	}
}

func TestExchangeSource_NoSubjectFunc(t *testing.T) {
	src := NewExchangeSource(ExchangeConfig{TokenEndpoint: "http://127.0.0.1:1/never"})
	if _, err := src(context.Background()); err == nil {
		t.Fatal("expected an error when no subject token source is configured")
	}
}

func TestExchangeSource_SubjectErrorPropagates(t *testing.T) {
	sentinel := errors.New("inbound token unavailable")
	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: "http://127.0.0.1:1/never",
		SubjectToken:  func(context.Context) (string, error) { return "", sentinel },
	})
	if _, err := src(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the subject error", err)
	}
}

func TestExchangeSource_ServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": "invalid_target", "error_description": "unknown audience"})
	}))
	defer srv.Close()

	src := NewExchangeSource(ExchangeConfig{
		TokenEndpoint: srv.URL,
		SubjectToken:  func(context.Context) (string, error) { return "s", nil },
		HTTPClient:    srv.Client(),
	})
	_, err := src(context.Background())
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "invalid_target" {
		t.Fatalf("error = %v, want an invalid_target TokenError", err)
	}
}

func TestHashToken_DoesNotLeakTheToken(t *testing.T) {
	// The cache key ends up in memory dumps; it must not be the credential.
	const tok = "super-secret-jwt"
	h := hashToken(tok)
	if strings.Contains(h, tok) {
		t.Fatal("hash contains the raw token")
	}
	if h != hashToken(tok) {
		t.Fatal("hash is not stable")
	}
	if h == hashToken(tok+"x") {
		t.Fatal("hash collides across distinct tokens")
	}
}
