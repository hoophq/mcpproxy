package approval

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "s3cret-token"

// serve spins the API over a live httptest server and returns a helper that
// issues authenticated requests against it.
func serve(t *testing.T, s *Store, token string) (*httptest.Server, func(method, path, bearer string) *http.Response) {
	t.Helper()
	// Mounted the way the daemon mounts it, so path handling is exercised for
	// real rather than at the root.
	mux := http.NewServeMux()
	mux.Handle("/approvals/", http.StripPrefix("/approvals", NewAPI(s, token)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	do := func(method, path, bearer string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/approvals"+path, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	return srv, do
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var v T
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return v
}

func TestAPIApproveHappyPath(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	_, do := serve(t, s, testToken)

	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}

	// The reviewer lists, inspects, then decides.
	resp := do(http.MethodGet, "/", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	list := decode[[]PendingView](t, resp)
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("GET / = %+v, want the one held call %q", list, id)
	}
	if string(list[0].Args) != `{"repo":"prod"}` {
		t.Errorf("args = %s, want the raw params", list[0].Args)
	}

	resp = do(http.MethodGet, "/"+id, testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /{id} = %d, want 200", resp.StatusCode)
	}
	if v := decode[PendingView](t, resp); v.ID != id || v.Tool != "delete_repo" {
		t.Errorf("GET /{id} = %+v, want the held call", v)
	}

	resp = do(http.MethodPost, "/"+id+"/approve", testToken)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST approve = %d, want 204", resp.StatusCode)
	}
	if got := recv(t, ch); !got {
		t.Fatal("verdict = false, want true")
	}

	// Approved calls leave the queue.
	resp = do(http.MethodGet, "/", testToken)
	if got := decode[[]PendingView](t, resp); len(got) != 0 {
		t.Errorf("GET / after approve = %+v, want empty", got)
	}
	resp = do(http.MethodGet, "/"+id, testToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /{id} after approve = %d, want 404", resp.StatusCode)
	}
}

func TestAPIRejectHappyPath(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	_, do := serve(t, s, testToken)

	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if resp := do(http.MethodPost, "/"+id+"/reject", testToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST reject = %d, want 204", resp.StatusCode)
	}
	if got := recv(t, ch); got {
		t.Fatal("verdict = true, want false")
	}
}

func TestAPIAuth(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	id, _, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	_, do := serve(t, s, testToken)

	tests := []struct {
		name   string
		bearer string
		want   int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "nope", http.StatusUnauthorized},
		{"prefix of token", testToken[:5], http.StatusUnauthorized},
		{"token plus suffix", testToken + "x", http.StatusUnauthorized},
		{"correct token", testToken, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(http.MethodGet, "/", tc.bearer)
			if resp.StatusCode != tc.want {
				t.Fatalf("GET / = %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusUnauthorized {
				if h := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(h, "Bearer ") {
					t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", h)
				}
			}
		})
	}

	// Auth guards mutation too, and a rejected request must not resolve.
	if resp := do(http.MethodPost, "/"+id+"/approve", "nope"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST approve unauthenticated = %d, want 401", resp.StatusCode)
	}
	if len(s.List()) != 1 {
		t.Fatal("unauthenticated request resolved the call")
	}
}

// An empty token means the daemon fronts the API with its own protection.
func TestAPIEmptyTokenAllowsAnonymous(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	_, do := serve(t, s, "")
	if resp := do(http.MethodGet, "/", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / with no auth configured = %d, want 200", resp.StatusCode)
	}
}

func TestAPIUnknownAndResolvedIDs(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	_, do := serve(t, s, testToken)

	for _, path := range []string{"/deadbeef/approve", "/deadbeef/reject"} {
		resp := do(http.MethodPost, path, testToken)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", path, resp.StatusCode)
		}
		if got := decode[map[string]string](t, resp); got["error"] == "" {
			t.Errorf("POST %s returned no error message", path)
		}
	}
	if resp := do(http.MethodGet, "/deadbeef", testToken); resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /deadbeef = %d, want 404", resp.StatusCode)
	}

	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if resp := do(http.MethodPost, "/"+id+"/approve", testToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first approve = %d, want 204", resp.StatusCode)
	}
	recv(t, ch)

	// Second decision on the same call: 409, and no extra verdict escapes.
	for _, path := range []string{"/" + id + "/approve", "/" + id + "/reject"} {
		if resp := do(http.MethodPost, path, testToken); resp.StatusCode != http.StatusConflict {
			t.Errorf("POST %s after resolution = %d, want 409", path, resp.StatusCode)
		}
	}
	mustNoVerdict(t, ch)
}

func TestAPIRouting(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	id, _, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	_, do := serve(t, s, testToken)

	tests := []struct {
		name           string
		method, path   string
		want           int
		wantAllowLikes string
	}{
		{name: "GET on approve route", method: http.MethodGet, path: "/" + id + "/approve",
			want: http.StatusMethodNotAllowed, wantAllowLikes: "POST"},
		{name: "POST on list", method: http.MethodPost, path: "/",
			want: http.StatusMethodNotAllowed, wantAllowLikes: "GET"},
		{name: "unknown verb path", method: http.MethodPost, path: "/" + id + "/maybe",
			want: http.StatusNotFound},
		{name: "deep path", method: http.MethodGet, path: "/" + id + "/a/b",
			want: http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(tc.method, tc.path, testToken)
			if resp.StatusCode != tc.want {
				t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.want)
			}
			if tc.wantAllowLikes != "" && !strings.Contains(resp.Header.Get("Allow"), tc.wantAllowLikes) {
				t.Errorf("Allow = %q, want it to include %q", resp.Header.Get("Allow"), tc.wantAllowLikes)
			}
		})
	}
	// None of the above touched the held call.
	if len(s.List()) != 1 {
		t.Fatal("a misrouted request resolved the call")
	}
}

func TestAPIListOrderAndShape(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	_, do := serve(t, s, testToken)

	var ids []string
	for i := range 3 {
		c := sampleCall()
		c.Tool = string(rune('a' + i))
		id, _, err := s.Hold(t.Context(), c)
		if err != nil {
			t.Fatalf("Hold %d: %v", i, err)
		}
		ids = append(ids, id)
		time.Sleep(time.Millisecond) // distinct creation instants
	}

	resp := do(http.MethodGet, "/", testToken)
	// Decode loosely to pin the wire contract: field names reviewers script
	// against, and age as seconds rather than raw nanoseconds.
	raw := decode[[]map[string]any](t, resp)
	if len(raw) != 3 {
		t.Fatalf("GET / = %d entries, want 3", len(raw))
	}
	for i, m := range raw {
		if m["id"] != ids[i] {
			t.Errorf("entry %d id = %v, want %v (wrong order?)", i, m["id"], ids[i])
		}
		for _, k := range []string{"id", "session", "user", "backend", "tool", "args", "rule", "created", "age_seconds"} {
			if _, ok := m[k]; !ok {
				t.Errorf("entry %d missing field %q: %v", i, k, m)
			}
		}
		if _, ok := m["Age"]; ok {
			t.Errorf("entry %d leaked the raw Age duration: %v", i, m)
		}
		age, ok := m["age_seconds"].(float64)
		if !ok || age < 0 || age > 60 {
			t.Errorf("entry %d age_seconds = %v, want a small positive number", i, m["age_seconds"])
		}
	}
}
