package inbound

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGitHub is a stand-in for the GitHub REST API that records what the
// resolver asked for and how it authenticated.
type fakeGitHub struct {
	srv *httptest.Server
	// validToken is the only credential the fake accepts.
	validToken string
	// orgs is what /user/orgs returns for the valid token.
	orgs []string
	// userCalls and orgCalls count endpoint hits, proving cache behaviour.
	userCalls atomic.Int64
	orgCalls  atomic.Int64
	// lastAuth records the Authorization header the resolver forwarded.
	lastAuth atomic.Value
	// fail, when set, makes every endpoint return this status.
	fail atomic.Int64
}

func newFakeGitHub(t *testing.T, validToken string, orgs []string) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{validToken: validToken, orgs: orgs}

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		g.userCalls.Add(1)
		if !g.authorize(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octocat","id":583231,"email":"octo@github.com","name":"The Octocat","type":"User"}`))
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		g.orgCalls.Add(1)
		if !g.authorize(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(g.orgsJSON()))
	})

	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) authorize(w http.ResponseWriter, r *http.Request) bool {
	g.lastAuth.Store(r.Header.Get("Authorization"))
	if code := g.fail.Load(); code != 0 {
		http.Error(w, "forced failure", int(code))
		return false
	}
	if r.Header.Get("Authorization") != "Bearer "+g.validToken {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func (g *fakeGitHub) orgsJSON() string {
	out := "["
	for i, o := range g.orgs {
		if i > 0 {
			out += ","
		}
		out += `{"login":"` + o + `"}`
	}
	return out + "]"
}

func TestGitHubValidToken(t *testing.T) {
	g := newFakeGitHub(t, "ghp_valid", nil)
	res := GitHub(GitHubOptions{BaseURL: g.srv.URL, HTTPClient: g.srv.Client()})

	id, err := res(req("ghp_valid"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.Subject != "octocat" {
		t.Errorf("subject = %q, want octocat", id.Subject)
	}
	if id.Email != "octo@github.com" {
		t.Errorf("email = %q, want octo@github.com", id.Email)
	}
	if id.Claims["provider"] != "github" {
		t.Errorf("provider claim = %v, want github", id.Claims["provider"])
	}
	// The caller's own token must be forwarded: validating with a different
	// credential would authenticate the wrong principal.
	if got := g.lastAuth.Load(); got != "Bearer ghp_valid" {
		t.Errorf("forwarded auth = %v, want Bearer ghp_valid", got)
	}
	// Without an org allowlist there is no reason to spend an extra API call.
	if n := g.orgCalls.Load(); n != 0 {
		t.Errorf("/user/orgs called %d times with no allowlist, want 0", n)
	}
}

func TestGitHubRejectsBadToken(t *testing.T) {
	g := newFakeGitHub(t, "ghp_valid", nil)
	res := GitHub(GitHubOptions{BaseURL: g.srv.URL, HTTPClient: g.srv.Client()})

	_, err := res(req("ghp_bogus"))
	if err == nil {
		t.Fatal("want rejection")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("error %v does not wrap ErrUnauthenticated", err)
	}
}

func TestGitHubOrgAllowlist(t *testing.T) {
	cases := []struct {
		name     string
		userOrgs []string
		allowed  []string
		ok       bool
	}{
		{"member of the allowed org", []string{"acme"}, []string{"acme"}, true},
		{"member of one of several", []string{"other", "acme"}, []string{"acme", "widgets"}, true},
		{"case-insensitive match", []string{"ACME"}, []string{"acme"}, true},
		{"member of no allowed org", []string{"other"}, []string{"acme"}, false},
		{"member of nothing", nil, []string{"acme"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGitHub(t, "ghp_valid", tc.userOrgs)
			res := GitHub(GitHubOptions{
				BaseURL:     g.srv.URL,
				HTTPClient:  g.srv.Client(),
				AllowedOrgs: tc.allowed,
			})
			id, err := res(req("ghp_valid"))
			if tc.ok {
				if err != nil {
					t.Fatalf("want acceptance, got %v", err)
				}
				if id.Claims["org"] == nil {
					t.Error("accepted identity carries no org claim")
				}
				return
			}
			if err == nil {
				t.Fatalf("want rejection, got identity %+v", id)
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("error %v does not wrap ErrUnauthenticated", err)
			}
		})
	}
}

func TestGitHubCachesValidatedTokens(t *testing.T) {
	g := newFakeGitHub(t, "ghp_valid", []string{"acme"})
	clock := time.Unix(1700000000, 0)
	res := GitHub(GitHubOptions{
		BaseURL:     g.srv.URL,
		HTTPClient:  g.srv.Client(),
		AllowedOrgs: []string{"acme"},
		Now:         func() time.Time { return clock },
	})

	for range 5 {
		if _, err := res(req("ghp_valid")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	// An MCP session issues many messages; one API round trip per message
	// would blow through GitHub's rate limit within minutes.
	if n := g.userCalls.Load(); n != 1 {
		t.Errorf("/user called %d times within the TTL, want 1", n)
	}
	if n := g.orgCalls.Load(); n != 1 {
		t.Errorf("/user/orgs called %d times within the TTL, want 1", n)
	}

	// Just inside the TTL: still cached.
	clock = clock.Add(githubCacheTTL - time.Second)
	if _, err := res(req("ghp_valid")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n := g.userCalls.Load(); n != 1 {
		t.Errorf("/user called %d times just inside the TTL, want 1", n)
	}

	// Past the TTL: revalidated, so a revoked token stops working.
	clock = clock.Add(2 * time.Second)
	if _, err := res(req("ghp_valid")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n := g.userCalls.Load(); n != 2 {
		t.Errorf("/user called %d times after the TTL, want 2", n)
	}
}

func TestGitHubDoesNotCacheRejections(t *testing.T) {
	// A token rejected because GitHub was briefly unavailable must be retried,
	// not written off for the whole TTL.
	g := newFakeGitHub(t, "ghp_valid", nil)
	g.fail.Store(http.StatusServiceUnavailable)
	res := GitHub(GitHubOptions{BaseURL: g.srv.URL, HTTPClient: g.srv.Client()})

	_, err := res(req("ghp_valid"))
	if err == nil {
		t.Fatal("want failure while GitHub is down")
	}
	// A 5xx is GitHub's fault, not the caller's, so it must not be reported as
	// an authentication failure.
	if errors.Is(err, ErrUnauthenticated) {
		t.Errorf("upstream 503 reported as ErrUnauthenticated: %v", err)
	}

	g.fail.Store(0)
	if _, err := res(req("ghp_valid")); err != nil {
		t.Fatalf("resolver did not recover after GitHub came back: %v", err)
	}
}

func TestGitHubDistinctTokensGetDistinctCacheEntries(t *testing.T) {
	// A single shared cache slot would let one caller's identity leak to
	// another caller presenting a different token.
	g := newFakeGitHub(t, "ghp_valid", nil)
	res := GitHub(GitHubOptions{BaseURL: g.srv.URL, HTTPClient: g.srv.Client()})

	if _, err := res(req("ghp_valid")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := res(req("ghp_other")); err == nil {
		t.Fatal("a different token must not inherit the cached identity")
	}
}

func TestGitHubMissingCredential(t *testing.T) {
	g := newFakeGitHub(t, "ghp_valid", nil)
	res := GitHub(GitHubOptions{BaseURL: g.srv.URL, HTTPClient: g.srv.Client()})

	if _, err := res(req("")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error %v does not wrap ErrUnauthenticated", err)
	}
	if n := g.userCalls.Load(); n != 0 {
		t.Errorf("GitHub called %d times for a credential-less request, want 0", n)
	}
}

func TestGitHubConcurrentResolves(t *testing.T) {
	// The gateway resolves identities on every inbound HTTP request, so the
	// token cache is touched from many goroutines at once. Run under -race.
	g := newFakeGitHub(t, "ghp_valid", []string{"acme"})
	res := GitHub(GitHubOptions{
		BaseURL:     g.srv.URL,
		HTTPClient:  g.srv.Client(),
		AllowedOrgs: []string{"acme"},
	})

	const workers = 32
	errs := make(chan error, workers)
	start := make(chan struct{})
	for i := range workers {
		go func(i int) {
			<-start
			// Mix hits and misses so both cache paths run concurrently.
			tok := "ghp_valid"
			if i%4 == 0 {
				tok = "ghp_bogus"
			}
			id, err := res(req(tok))
			switch {
			case tok == "ghp_valid" && err != nil:
				errs <- err
			case tok == "ghp_valid" && id.Subject != "octocat":
				errs <- errors.New("valid token resolved to " + id.Subject)
			case tok == "ghp_bogus" && err == nil:
				errs <- errors.New("bogus token accepted as " + id.Subject)
			default:
				errs <- nil
			}
		}(i)
	}
	close(start)
	for range workers {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}
