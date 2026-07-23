package inbound

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/inspect"
)

// DefaultGitHubAPI is the GitHub.com REST API root. GitHub Enterprise Server is
// not a supported target: its token formats and org semantics differ enough
// that pointing this at one would silently weaken the org allowlist.
const DefaultGitHubAPI = "https://api.github.com"

// githubCacheTTL bounds how long a validated token is trusted without
// re-asking GitHub. Five minutes keeps a revoked token's window short while
// cutting per-request API calls to roughly nothing under normal MCP traffic
// (which issues many messages per session).
const githubCacheTTL = 5 * time.Minute

// GitHubOptions configures GitHub personal-access/OAuth token validation.
type GitHubOptions struct {
	// AllowedOrgs, when non-empty, requires the caller to be a member of at
	// least one listed organization. Membership is read from /user/orgs,
	// which only lists orgs the token itself can see: a token without the
	// read:org scope will appear to belong to no orgs and be rejected.
	AllowedOrgs []string
	// BaseURL overrides the API root. Tests point this at an httptest server.
	BaseURL string
	// HTTPClient overrides the client used for API calls.
	HTTPClient *http.Client
	// Now overrides the clock, for deterministic cache-expiry tests.
	Now func() time.Time
}

// githubUser is the subset of GET /user the gateway needs.
type githubUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Type  string `json:"type"`
}

type githubEntry struct {
	id      inspect.Identity
	expires time.Time
}

// githubValidator validates tokens against the GitHub API with a short-lived
// positive cache.
//
// Failures are never cached: a token rejected because GitHub was briefly
// unreachable must not stay rejected for five minutes.
type githubValidator struct {
	client  *http.Client
	baseURL string
	orgs    []string
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]githubEntry
}

// GitHub validates `Authorization: Bearer <github token>` by calling the
// GitHub API as that token and adopting the resulting user as the identity.
//
// There is no offline check: GitHub tokens are opaque, so the API round-trip
// is the validation. Token prefixes (ghp_, gho_, github_pat_) are not screened
// because GitHub keeps minting new ones and a prefix allowlist would reject
// valid credentials for no security gain — an invalid token simply 401s.
func GitHub(opts GitHubOptions) Resolver {
	v := &githubValidator{
		client:  opts.HTTPClient,
		baseURL: strings.TrimSuffix(opts.BaseURL, "/"),
		orgs:    append([]string(nil), opts.AllowedOrgs...),
		now:     opts.Now,
		cache:   make(map[string]githubEntry),
	}
	if v.client == nil {
		v.client = &http.Client{Timeout: 10 * time.Second}
	}
	if v.baseURL == "" {
		v.baseURL = DefaultGitHubAPI
	}
	if v.now == nil {
		v.now = time.Now
	}

	return func(r *http.Request) (inspect.Identity, error) {
		tok, err := bearerToken(r)
		if err != nil {
			return inspect.Identity{}, err
		}
		if id, ok := v.cached(tok); ok {
			return id, nil
		}
		id, err := v.validate(r, tok)
		if err != nil {
			return inspect.Identity{}, err
		}
		v.store(tok, id)
		return id, nil
	}
}

func (v *githubValidator) cached(tok string) (inspect.Identity, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[tok]
	if !ok {
		return inspect.Identity{}, false
	}
	if !v.now().Before(e.expires) {
		delete(v.cache, tok)
		return inspect.Identity{}, false
	}
	return e.id, true
}

func (v *githubValidator) store(tok string, id inspect.Identity) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cache[tok] = githubEntry{id: id, expires: v.now().Add(githubCacheTTL)}
}

func (v *githubValidator) validate(r *http.Request, tok string) (inspect.Identity, error) {
	var u githubUser
	if err := v.get(r, tok, "/user", &u); err != nil {
		return inspect.Identity{}, err
	}
	if u.Login == "" {
		return inspect.Identity{}, fmt.Errorf("%w: GitHub returned a user with no login", ErrUnauthenticated)
	}

	claims := map[string]any{
		"login":    u.Login,
		"id":       u.ID,
		"name":     u.Name,
		"provider": "github",
	}

	if len(v.orgs) > 0 {
		var orgs []struct {
			Login string `json:"login"`
		}
		if err := v.get(r, tok, "/user/orgs", &orgs); err != nil {
			return inspect.Identity{}, err
		}
		names := make([]string, 0, len(orgs))
		for _, o := range orgs {
			names = append(names, o.Login)
		}
		matched, ok := firstAllowed(names, v.orgs)
		if !ok {
			return inspect.Identity{}, fmt.Errorf(
				"%w: user %q is not a member of any allowed organization", ErrUnauthenticated, u.Login)
		}
		claims["orgs"] = names
		claims["org"] = matched
	}

	return inspect.Identity{Subject: u.Login, Email: u.Email, Claims: claims}, nil
}

// get performs an authenticated GET against the GitHub API and decodes JSON
// into out. Non-200 responses become unauthenticated errors, except 5xx, which
// signal that GitHub — not the credential — is the problem.
func (v *githubValidator) get(r *http.Request, tok, path string, out any) error {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, v.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("inbound github: building request for %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("inbound github: calling %s: %w", path, err)
	}
	defer resp.Body.Close()

	// Bound the read: a hostile or misconfigured BaseURL should not be able to
	// stream unbounded data into the gateway's heap.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("inbound github: reading %s: %w", path, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 500:
		return fmt.Errorf("inbound github: %s returned %s (upstream failure)", path, resp.Status)
	default:
		return fmt.Errorf("%w: GitHub rejected the token (%s on %s)", ErrUnauthenticated, resp.Status, path)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("inbound github: decoding %s: %w", path, err)
	}
	return nil
}

// firstAllowed returns the first entry of have that appears in allow. GitHub
// org names are case-insensitive, so the comparison is too.
func firstAllowed(have, allow []string) (string, bool) {
	for _, h := range have {
		for _, a := range allow {
			if strings.EqualFold(h, a) {
				return h, true
			}
		}
	}
	return "", false
}
