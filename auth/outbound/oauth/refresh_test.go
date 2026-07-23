package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// memStore is a minimal in-memory core.TokenStore for these tests. The
// exported outbound.MemoryStore lives in the parent package, which imports
// this one, so it cannot be used here.
type memStore struct {
	mu      sync.Mutex
	grants  map[core.GrantKey]*core.Token
	puts    atomic.Int32
	deletes atomic.Int32
}

func newMemStore() *memStore {
	return &memStore{grants: make(map[core.GrantKey]*core.Token)}
}

func (s *memStore) Get(_ context.Context, k core.GrantKey) (*core.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.grants[k]
	if !ok {
		return nil, core.ErrNotFound
	}
	return t.Clone(), nil
}

func (s *memStore) Put(_ context.Context, k core.GrantKey, t *core.Token) error {
	s.puts.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[k] = t.Clone()
	return nil
}

func (s *memStore) Delete(_ context.Context, k core.GrantKey) error {
	s.deletes.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, k)
	return nil
}

var testKey = core.GrantKey{Backend: "github"}

func TestRefreshingSource_ServesValidTokenWithoutNetwork(t *testing.T) {
	store := newMemStore()
	now := time.Now()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "still-good", Expiry: now.Add(time.Hour),
	})

	// A token endpoint that would fail the test if it were ever reached.
	cfg := RefreshConfig{
		Client: ClientConfig{TokenEndpoint: "http://127.0.0.1:1/never"},
		Now:    func() time.Time { return now },
	}
	src := NewRefreshingSource(store, testKey, cfg)

	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "still-good" {
		t.Errorf("token = %q", got)
	}
	if store.puts.Load() != 1 {
		t.Errorf("store writes = %d, want only the seed write", store.puts.Load())
	}
}

func TestRefreshingSource_RefreshesExpiredAndPersists(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		if got := r.PostForm.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("refresh_token"); got != "rt-old" {
			t.Errorf("refresh_token = %q", got)
		}
		writeJSON(t, w, map[string]any{
			"access_token": "at-new", "refresh_token": "rt-new",
			"token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	store := newMemStore()
	now := time.Now()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "at-old", RefreshToken: "rt-old", Expiry: now.Add(-time.Minute),
		Extra: map[string]string{"id_token": "carried-forward"},
	})

	src := NewRefreshingSource(store, testKey, RefreshConfig{
		Client: ClientConfig{ClientID: "cid", TokenEndpoint: srv.URL, HTTPClient: srv.Client()},
		Now:    func() time.Time { return now },
	})

	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "at-new" {
		t.Errorf("token = %q", got)
	}

	stored, err := store.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("stored token: %v", err)
	}
	if stored.AccessToken != "at-new" || stored.RefreshToken != "rt-new" {
		t.Errorf("stored = %+v, want the refreshed pair persisted", stored)
	}
	// Extras the refresh response omitted must survive; the id_token cannot be
	// re-fetched.
	if stored.Extra["id_token"] != "carried-forward" {
		t.Errorf("stored extras = %v", stored.Extra)
	}

	// A second call is served from cache: the fresh token is still valid.
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("second token: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("token endpoint hit %d times, want 1", calls.Load())
	}
}

func TestRefreshingSource_ExpiryMargin(t *testing.T) {
	// A token expiring inside the margin would die mid-request; renewal must
	// happen early.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeJSON(t, w, map[string]any{"access_token": "at-new", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer srv.Close()

	now := time.Now()
	store := newMemStore()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "at-old", RefreshToken: "rt", Expiry: now.Add(10 * time.Second),
	})

	src := NewRefreshingSource(store, testKey, RefreshConfig{
		Client: ClientConfig{TokenEndpoint: srv.URL, HTTPClient: srv.Client()},
		Now:    func() time.Time { return now },
	})
	got, err := src(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "at-new" {
		t.Errorf("token = %q, want a refresh inside the %s margin", got, ExpiryMargin)
	}
	if calls.Load() != 1 {
		t.Errorf("refresh calls = %d", calls.Load())
	}
}

func TestRefreshingSource_NoRefreshTokenYieldsErrReauthorize(t *testing.T) {
	now := time.Now()
	store := newMemStore()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "at-old", Expiry: now.Add(-time.Hour),
	})

	src := NewRefreshingSource(store, testKey, RefreshConfig{
		Client: ClientConfig{TokenEndpoint: "http://127.0.0.1:1/never"},
		Now:    func() time.Time { return now },
	})

	_, err := src(context.Background())
	var reauth *ErrReauthorize
	if !errors.As(err, &reauth) {
		t.Fatalf("error = %v, want *ErrReauthorize", err)
	}
	if reauth.Key != testKey {
		t.Errorf("key = %+v", reauth.Key)
	}
}

func TestRefreshingSource_NoStoredGrantYieldsErrReauthorize(t *testing.T) {
	src := NewRefreshingSource(newMemStore(), testKey, RefreshConfig{
		Client: ClientConfig{TokenEndpoint: "http://127.0.0.1:1/never"},
	})
	var reauth *ErrReauthorize
	if _, err := src(context.Background()); !errors.As(err, &reauth) {
		t.Fatalf("error = %v, want *ErrReauthorize", err)
	}
}

func TestRefreshingSource_RejectedRefreshTokenIsDropped(t *testing.T) {
	// A dead refresh token must not be retried on every request; dropping it
	// makes the next call report a clean "not authorized".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": "invalid_grant", "error_description": "revoked"})
	}))
	defer srv.Close()

	now := time.Now()
	store := newMemStore()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "at", RefreshToken: "rt-dead", Expiry: now.Add(-time.Hour),
	})

	src := NewRefreshingSource(store, testKey, RefreshConfig{
		Client: ClientConfig{TokenEndpoint: srv.URL, HTTPClient: srv.Client()},
		Now:    func() time.Time { return now },
	})

	var reauth *ErrReauthorize
	if _, err := src(context.Background()); !errors.As(err, &reauth) {
		t.Fatalf("error = %v, want *ErrReauthorize", err)
	}
	if store.deletes.Load() != 1 {
		t.Errorf("deletes = %d, want the dead grant removed", store.deletes.Load())
	}
	if _, err := store.Get(context.Background(), testKey); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("grant still present after a rejected refresh: %v", err)
	}
}

func TestRefreshingSource_TransientErrorIsNotReauthorize(t *testing.T) {
	// A 500 is the server's problem, not the grant's; forcing a human through
	// the login flow over a blip would be wrong.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(t, w, map[string]string{"error": "server_error"})
	}))
	defer srv.Close()

	now := time.Now()
	store := newMemStore()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "at", RefreshToken: "rt", Expiry: now.Add(-time.Hour),
	})
	src := NewRefreshingSource(store, testKey, RefreshConfig{
		Client: ClientConfig{TokenEndpoint: srv.URL, HTTPClient: srv.Client()},
		Now:    func() time.Time { return now },
	})

	_, err := src(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	var reauth *ErrReauthorize
	if errors.As(err, &reauth) {
		t.Errorf("a transient server error must not demand re-authorization: %v", err)
	}
	if store.deletes.Load() != 0 {
		t.Error("a transient error must not delete the grant")
	}
}

func TestRefreshingSource_ConcurrentCallsRefreshOnce(t *testing.T) {
	// Servers that rotate refresh tokens invalidate the loser of a parallel
	// refresh, permanently breaking the grant.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond) // widen the race window
		writeJSON(t, w, map[string]any{
			"access_token": "at-new", "refresh_token": "rt-new", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	now := time.Now()
	store := newMemStore()
	_ = store.Put(context.Background(), testKey, &core.Token{
		AccessToken: "at-old", RefreshToken: "rt-old", Expiry: now.Add(-time.Hour),
	})
	src := NewRefreshingSource(store, testKey, RefreshConfig{
		Client: ClientConfig{TokenEndpoint: srv.URL, HTTPClient: srv.Client()},
		Now:    func() time.Time { return now },
	})

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	toks := make([]string, n)
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			toks[i], errs[i] = src(context.Background())
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if toks[i] != "at-new" {
			t.Fatalf("goroutine %d got %q", i, toks[i])
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want exactly 1", got)
	}
}

func TestErrReauthorize_MessageNamesTheBackendAndUser(t *testing.T) {
	e := &ErrReauthorize{Key: core.GrantKey{Backend: "github", User: "alice"}, Reason: "no stored grant"}
	msg := e.Error()
	for _, want := range []string{"github", "alice", "no stored grant"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q should mention %q", msg, want)
		}
	}
}
