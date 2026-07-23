package inbound

import (
	"errors"
	"strings"
	"testing"
)

func TestStatic(t *testing.T) {
	const token = "correct-horse-battery-staple"
	res, err := Static(token)
	if err != nil {
		t.Fatalf("Static: %v", err)
	}

	t.Run("accepts the configured token", func(t *testing.T) {
		id, err := res(req(token))
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if id.Subject != StaticSubject {
			t.Errorf("subject = %q, want %q", id.Subject, StaticSubject)
		}
	})

	rejects := []struct {
		name  string
		token string
	}{
		{"wrong token", "wrong-horse-battery-staple"},
		{"prefix of the token", token[:10]},
		{"token plus suffix", token + "x"},
		{"case-shifted token", strings.ToUpper(token)},
		{"no credential", ""},
	}
	for _, tc := range rejects {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			id, err := res(req(tc.token))
			if err == nil {
				t.Fatalf("want rejection, got identity %+v", id)
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("error %v does not wrap ErrUnauthenticated", err)
			}
			if id.Subject != "" {
				t.Errorf("rejected request yielded subject %q, want empty", id.Subject)
			}
		})
	}
}

func TestStaticRequiresNonEmptyToken(t *testing.T) {
	// An empty configured token would otherwise authenticate every caller that
	// sends "Bearer " — the worst possible failure mode.
	if _, err := Static(""); err == nil {
		t.Fatal("want error for empty token")
	}
}
