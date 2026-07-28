package outbound

import (
	"context"
	"strings"
	"testing"
)

func TestNewStatic(t *testing.T) {
	got, err := NewStatic("secret")(context.Background())
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	if got != "secret" {
		t.Errorf("token = %q", got)
	}
}

func TestNewNone(t *testing.T) {
	got, err := NewNone()(context.Background())
	if err != nil {
		t.Fatalf("none: %v", err)
	}
	if got != "" {
		t.Errorf("token = %q, want empty (no Authorization header)", got)
	}
}

func TestPassthrough(t *testing.T) {
	src := NewPassthrough()

	// A passthrough backend requires the caller's identity. An anonymous call
	// would fail upstream or succeed as another principal.
	if _, err := src(context.Background()); err == nil {
		t.Fatal("expected an error when no client token is on the context")
	} else if !strings.Contains(err.Error(), UpstreamAuthHeader) {
		t.Errorf("error should name the header, got %v", err)
	}

	ctx := WithClientToken(context.Background(), "client-cred")
	got, err := src(ctx)
	if err != nil {
		t.Fatalf("passthrough: %v", err)
	}
	if got != "client-cred" {
		t.Errorf("token = %q", got)
	}
}

func TestClientTokenFrom_EmptyIsAbsent(t *testing.T) {
	// An empty header value reads the same as no header at all.
	if _, ok := ClientTokenFrom(WithClientToken(context.Background(), "")); ok {
		t.Error("an empty client token must report as absent")
	}
}

func TestTrimBearer(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER  abc  ", "abc"},
		{"abc", "abc"},
		{"  abc  ", "abc"},
		{"", ""},
		{"Bearer", "Bearer"}, // no space: not a prefix, it is the value
	}
	for _, tt := range tests {
		if got := TrimBearer(tt.in); got != tt.want {
			t.Errorf("TrimBearer(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestUserContext(t *testing.T) {
	if _, ok := UserFrom(context.Background()); ok {
		t.Error("a bare context must carry no user")
	}
	if _, ok := UserFrom(WithUser(context.Background(), "")); ok {
		t.Error("an empty subject must report as absent")
	}
	got, ok := UserFrom(WithUser(context.Background(), "alice"))
	if !ok || got != "alice" {
		t.Errorf("UserFrom = (%q, %v)", got, ok)
	}
}

func TestInboundTokenContext(t *testing.T) {
	if _, ok := InboundTokenFrom(context.Background()); ok {
		t.Error("a bare context must carry no inbound token")
	}
	got, ok := InboundTokenFrom(WithInboundToken(context.Background(), "jwt"))
	if !ok || got != "jwt" {
		t.Errorf("InboundTokenFrom = (%q, %v)", got, ok)
	}
}

func TestContextKeysDoNotCollide(t *testing.T) {
	// User, client token, and inbound token ride the same context, and a
	// shared key type would return one in place of another.
	ctx := WithUser(context.Background(), "alice")
	ctx = WithClientToken(ctx, "client-cred")
	ctx = WithInboundToken(ctx, "inbound-jwt")

	if u, _ := UserFrom(ctx); u != "alice" {
		t.Errorf("user = %q", u)
	}
	if c, _ := ClientTokenFrom(ctx); c != "client-cred" {
		t.Errorf("client token = %q", c)
	}
	if i, _ := InboundTokenFrom(ctx); i != "inbound-jwt" {
		t.Errorf("inbound token = %q", i)
	}
}
