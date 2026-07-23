package authserver

import (
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound"
)

func TestSweepDropsOnlyExpiredState(t *testing.T) {
	base := time.Now()
	s := newStore()

	// Fresh and stale pending authorizations.
	s.putGrant(&grant{ID: "fresh-pending", CreatedAt: base})
	s.putGrant(&grant{ID: "stale-pending", CreatedAt: base.Add(-grantTTL - time.Minute)})

	// Fresh and stale authorization codes.
	s.putCode(&grant{ID: "g1", Code: "fresh-code", CodeIssued: base})
	s.putCode(&grant{ID: "g2", Code: "stale-code", CodeIssued: base.Add(-codeTTL - time.Minute)})

	// Live and dead refresh tokens.
	s.putRefresh("live-refresh", &refreshGrant{Expires: base.Add(time.Hour)})
	s.putRefresh("dead-refresh", &refreshGrant{Expires: base.Add(-time.Minute)})

	s.sweep(base)

	if _, ok := s.takeGrant("stale-pending"); ok {
		t.Error("sweep kept an expired pending grant")
	}
	if _, ok := s.takeCode("stale-code", base); ok {
		t.Error("sweep kept an expired code")
	}
	if _, ok := s.takeRefresh("dead-refresh", base); ok {
		t.Error("sweep kept an expired refresh token")
	}

	if _, ok := s.takeGrant("fresh-pending"); !ok {
		t.Error("sweep dropped a live pending grant")
	}
	if _, ok := s.takeCode("fresh-code", base); !ok {
		t.Error("sweep dropped a live code")
	}
	if _, ok := s.takeRefresh("live-refresh", base); !ok {
		t.Error("sweep dropped a live refresh token")
	}

	// Upstream tokens are keyed by subject and outlive individual grants:
	// a user's backend access must not die because they stopped refreshing.
	s.putUpstream("alice", &outbound.Token{AccessToken: "t"})
	s.sweep(base.Add(365 * 24 * time.Hour))
	if _, ok := s.getUpstream("alice"); !ok {
		t.Error("sweep discarded an upstream token")
	}
}

func TestPendingGrantsAndCodesAreDisjoint(t *testing.T) {
	base := time.Now()
	s := newStore()

	// A federated grant is parked, then approved. Approval must move it out
	// of the pending map, or a replayed IdP callback mints a second code for
	// the same login.
	g := &grant{ID: "gid", CreatedAt: base}
	s.putGrant(g)
	taken, ok := s.takeGrant("gid")
	if !ok {
		t.Fatal("parked grant was not retrievable")
	}
	taken.Code = "the-code"
	taken.CodeIssued = base
	s.putCode(taken)

	if _, ok := s.takeGrant("gid"); ok {
		t.Error("an approved grant is still pending; the callback could be replayed")
	}
	if _, ok := s.takeCode("the-code", base); !ok {
		t.Error("approved grant is not redeemable by its code")
	}
}

func TestTakeRejectsEmptyKeys(t *testing.T) {
	s := newStore()
	now := time.Now()

	if _, ok := s.takeGrant(""); ok {
		t.Error("takeGrant accepted an empty id")
	}
	if _, ok := s.takeCode("", now); ok {
		t.Error("takeCode accepted an empty code")
	}
	if _, ok := s.takeRefresh("", now); ok {
		t.Error("takeRefresh accepted an empty token")
	}
}

func TestRandomTokenIsUniqueAndURLSafe(t *testing.T) {
	seen := make(map[string]bool, 128)
	for range 128 {
		tok, err := randomToken(32)
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		if seen[tok] {
			t.Fatalf("randomToken repeated %q", tok)
		}
		seen[tok] = true
		// base64url has no characters needing escaping in a query string.
		for _, r := range tok {
			ok := r == '-' || r == '_' ||
				(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			if !ok {
				t.Fatalf("randomToken produced %q containing %q, which is not URL-safe", tok, r)
			}
		}
	}
}

func TestClientRedirectMatchingIsExact(t *testing.T) {
	c := &client{RedirectURIs: []string{"http://127.0.0.1:9000/cb"}}

	tests := []struct {
		uri  string
		want bool
	}{
		{"http://127.0.0.1:9000/cb", true},
		{"http://127.0.0.1:9000/cb/", false},
		{"http://127.0.0.1:9000/cb/../evil", false},
		{"http://127.0.0.1:9000/cbx", false},
		{"http://127.0.0.1:9001/cb", false},
		{"https://127.0.0.1:9000/cb", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := c.allowsRedirect(tc.uri); got != tc.want {
			t.Errorf("allowsRedirect(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}
