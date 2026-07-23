package inbound

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/config"
)

// req builds a request carrying an optional Bearer credential.
func req(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestNewDispatchesOnMode(t *testing.T) {
	// Each mode must produce a resolver whose behaviour identifies it, so a
	// mis-wired switch cannot pass by returning "some resolver".
	cases := []struct {
		name    string
		cfg     config.Inbound
		wantSub string // subject for a request that should succeed
		token   string
	}{
		{name: "empty defaults to anonymous", cfg: config.Inbound{}, wantSub: AnonymousSubject},
		{name: "anonymous", cfg: config.Inbound{Mode: "anonymous"}, wantSub: AnonymousSubject},
		{name: "static", cfg: config.Inbound{Mode: "static", Token: "s3cret"}, token: "s3cret", wantSub: StaticSubject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := New(tc.cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			id, err := res(req(tc.token))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if id.Subject != tc.wantSub {
				t.Errorf("subject = %q, want %q", id.Subject, tc.wantSub)
			}
		})
	}
}

func TestNewLocalUsesOSUser(t *testing.T) {
	res, err := New(config.Inbound{Mode: "local"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := res(req(""))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user available: %v", err)
	}
	if id.Subject != u.Username {
		t.Errorf("subject = %q, want %q", id.Subject, u.Username)
	}
	if id.Claims["uid"] != u.Uid {
		t.Errorf("uid claim = %v, want %q", id.Claims["uid"], u.Uid)
	}
}

func TestNewGitHubModeCallsAPI(t *testing.T) {
	// Dispatch for github/awssts is proven by the resolver reaching out to the
	// right protocol surface, since neither mode can succeed offline.
	var hit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octocat","email":"octo@example.com"}`))
	}))
	defer srv.Close()

	res := GitHub(GitHubOptions{BaseURL: srv.URL})
	id, err := res(req("gho_token"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if hit != "/user" {
		t.Errorf("called %q, want /user", hit)
	}
	if id.Subject != "octocat" {
		t.Errorf("subject = %q, want octocat", id.Subject)
	}
}

func TestNewRejectsUnknownAndInvalidModes(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Inbound
	}{
		{"unknown mode", config.Inbound{Mode: "kerberos"}},
		{"static without token", config.Inbound{Mode: "static"}},
		{"oidc without issuer", config.Inbound{Mode: "oidc"}},
		{"awssts without mappings", config.Inbound{Mode: "awssts"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestNewCoversEveryValidatedMode(t *testing.T) {
	// config.Validate accepts this set; New must not reject any of them when
	// their required fields are present, or a valid config would fail at boot.
	cfgs := []config.Inbound{
		{Mode: ""},
		{Mode: "anonymous"},
		{Mode: "local"},
		{Mode: "static", Token: "t"},
		{Mode: "oidc", Issuer: "https://issuer.example"},
		{Mode: "github"},
		{Mode: "awssts", AWSRoleMappings: map[string]string{"arn:*": "dev"}},
	}
	for _, cfg := range cfgs {
		if _, err := New(cfg); err != nil {
			t.Errorf("New(%q): %v", cfg.Mode, err)
		}
	}
}

func TestOIDCConstructionDoesNotDialIssuer(t *testing.T) {
	// Discovery must be lazy: an IdP that is down at startup cannot be allowed
	// to prevent the daemon from booting.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	res, err := New(config.Inbound{Mode: "oidc", Issuer: srv.URL})
	if err != nil {
		t.Fatalf("New must not fail when the issuer is unreachable: %v", err)
	}
	if calls != 0 {
		t.Fatalf("construction made %d issuer calls, want 0", calls)
	}
	if _, err := res(req("some.jwt.token")); err == nil {
		t.Fatal("resolve against a down issuer must fail")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{"standard", "Bearer abc", "abc", true},
		{"lowercase scheme", "bearer abc", "abc", true},
		{"mixed case scheme", "BeArEr abc", "abc", true},
		{"surrounding space", "Bearer   abc  ", "abc", true},
		{"missing header", "", "", false},
		{"wrong scheme", "Basic abc", "", false},
		{"scheme only", "Bearer ", "", false},
		{"bare token", "abc", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			got, err := bearerToken(r)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want {
					t.Errorf("token = %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("error %v does not wrap ErrUnauthenticated", err)
			}
		})
	}
}

func TestGlobMatch(t *testing.T) {
	// ':' and '/' must be ordinary characters: ARNs use both, and path.Match
	// semantics would break every realistic mapping pattern.
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"exact", "exact", true},
		{"exact", "exacts", false},
		{"arn:aws:sts::*", "arn:aws:sts::123:assumed-role/Dev/s", true},
		{"arn:aws:sts::123:assumed-role/Dev/*", "arn:aws:sts::123:assumed-role/Dev/alice", true},
		{"arn:aws:sts::123:assumed-role/Dev/*", "arn:aws:sts::123:assumed-role/Ops/alice", false},
		{"a*c*e", "abcde", true},
		{"a*c*e", "abcd", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"pre*", "pre", true},
		{"*suf", "suf", true},
		{"**", "x", true},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestGlobMatchDoesNotBlowUpOnPathologicalInput(t *testing.T) {
	// A naive recursive matcher goes exponential here; the iterative one must
	// return promptly. If this hangs, the resolver is a DoS vector.
	pattern := strings.Repeat("a*", 20) + "b"
	s := strings.Repeat("a", 200)
	if globMatch(pattern, s) {
		t.Error("want no match")
	}
}
