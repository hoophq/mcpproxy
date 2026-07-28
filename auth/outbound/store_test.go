package outbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	k := GrantKey{Backend: "github", User: "alice"}

	if _, err := s.Get(ctx, k); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty store = %v, want ErrNotFound", err)
	}

	want := &Token{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour)}
	if err := s.Put(ctx, k, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, k)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Errorf("got %+v", got)
	}

	// Grants are keyed by user, so alice's token must not answer for bob.
	if _, err := s.Get(ctx, GrantKey{Backend: "github", User: "bob"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob's Get = %v, want ErrNotFound", err)
	}

	if err := s.Delete(ctx, k); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, k); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	// Deleting an absent key succeeds: the caller wanted the key gone.
	if err := s.Delete(ctx, k); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

func TestMemoryStore_HandsOutCopies(t *testing.T) {
	// A caller mutating a returned token must not corrupt the store.
	ctx := context.Background()
	s := NewMemoryStore()
	k := GrantKey{Backend: "b"}
	_ = s.Put(ctx, k, &Token{AccessToken: "at", Extra: map[string]string{"id_token": "jwt"}})

	got, _ := s.Get(ctx, k)
	got.AccessToken = "tampered"
	got.Extra["id_token"] = "tampered"

	again, _ := s.Get(ctx, k)
	if again.AccessToken != "at" || again.Extra["id_token"] != "jwt" {
		t.Errorf("store was mutated through a returned token: %+v", again)
	}
}

func TestFileStore_RoundTripAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.enc")
	keyPath := filepath.Join(dir, "tokens.key")
	ctx := context.Background()

	s, err := NewFileStore(path, keyPath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	k := GrantKey{Backend: "github", User: "alice"}
	want := &Token{AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer", Expiry: expiry,
		Extra: map[string]string{"id_token": "jwt"}}
	if err := s.Put(ctx, k, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(ctx, GrantKey{Backend: "slack"}, &Token{AccessToken: "at2"}); err != nil {
		t.Fatalf("Put slack: %v", err)
	}

	reopened, err := NewFileStore(path, keyPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := reopened.Get(ctx, k)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !got.Expiry.Equal(expiry) {
		t.Errorf("expiry = %v, want %v", got.Expiry, expiry)
	}
	if got.Extra["id_token"] != "jwt" {
		t.Errorf("extras lost: %v", got.Extra)
	}
	if _, err := reopened.Get(ctx, GrantKey{Backend: "slack"}); err != nil {
		t.Errorf("second backend lost across reopen: %v", err)
	}
}

func TestFileStore_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.enc")
	ctx := context.Background()

	s, err := NewFileStore(path, filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := s.Put(ctx, GrantKey{Backend: "b"}, &Token{AccessToken: "at"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A second keyfile holds a different random key, and GCM must refuse the
	// blob rather than hand back garbage.
	_, err = NewFileStore(path, filepath.Join(dir, "b.key"))
	if err == nil {
		t.Fatal("expected opening the store with the wrong key to fail")
	}
}

func TestFileStore_TokensAreNotOnDiskInPlaintext(t *testing.T) {
	// A refresh token is a long-lived credential, and anyone who gets the file
	// must not be able to read it.
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.enc")
	s, err := NewFileStore(path, filepath.Join(dir, "tokens.key"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	const secret = "rt-do-not-leak-this"
	if err := s.Put(context.Background(), GrantKey{Backend: "b"},
		&Token{AccessToken: "at", RefreshToken: secret}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(blob, []byte(secret)) {
		t.Fatal("refresh token appears verbatim on disk")
	}
	if bytes.Contains(blob, []byte("access_token")) {
		t.Fatal("JSON field names appear on disk; the blob is not encrypted")
	}
}

func TestFileStore_TamperedCiphertextFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.enc")
	keyPath := filepath.Join(dir, "tokens.key")

	s, err := NewFileStore(path, keyPath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := s.Put(context.Background(), GrantKey{Backend: "b"}, &Token{AccessToken: "at"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	blob[len(blob)-1] ^= 0xff
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := NewFileStore(path, keyPath); err == nil {
		t.Fatal("expected GCM to reject a tampered blob")
	}
}

func TestFileStore_DeleteIsPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.enc")
	keyPath := filepath.Join(dir, "tokens.key")
	ctx := context.Background()

	s, err := NewFileStore(path, keyPath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	k := GrantKey{Backend: "b"}
	_ = s.Put(ctx, k, &Token{AccessToken: "at"})
	if err := s.Delete(ctx, k); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	reopened, err := NewFileStore(path, keyPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := reopened.Get(ctx, k); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after persisted delete = %v, want ErrNotFound", err)
	}
}

func TestFileStore_EmptyStoreIsNotAnError(t *testing.T) {
	// A missing store file is the first-run state and must open cleanly.
	dir := t.TempDir()
	s, err := NewFileStore(filepath.Join(dir, "nope.enc"), filepath.Join(dir, "nope.key"))
	if err != nil {
		t.Fatalf("NewFileStore on a fresh dir: %v", err)
	}
	if _, err := s.Get(context.Background(), GrantKey{Backend: "b"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get = %v, want ErrNotFound", err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "k.key")

	key, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("key length = %d, want %d", len(key), KeySize)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Key material must stay unreadable to group and world.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("keyfile mode = %o, want 600", perm)
	}

	again, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateKey: %v", err)
	}
	if string(again) != string(key) {
		t.Error("a second call regenerated the key instead of reading it")
	}
}

func TestLoadOrCreateKey_RejectsWrongLength(t *testing.T) {
	// Stretching or truncating operator key material would hide a
	// misconfiguration behind working encryption.
	dir := t.TempDir()
	path := filepath.Join(dir, "short.key")
	short := make([]byte, 16)
	if _, err := rand.Read(short); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, short, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("expected a 16-byte keyfile to be rejected")
	}
}

func TestTokenValid(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		tok    *Token
		margin time.Duration
		want   bool
	}{
		{"nil", nil, 0, false},
		{"no access token", &Token{Expiry: now.Add(time.Hour)}, 0, false},
		// A provider that omits expires_in promises a token that does not
		// expire; treating that as expired would force pointless refreshes.
		{"zero expiry never expires", &Token{AccessToken: "at"}, time.Hour, true},
		{"valid", &Token{AccessToken: "at", Expiry: now.Add(time.Hour)}, 0, true},
		{"expired", &Token{AccessToken: "at", Expiry: now.Add(-time.Second)}, 0, false},
		{"inside margin", &Token{AccessToken: "at", Expiry: now.Add(10 * time.Second)}, 30 * time.Second, false},
		{"outside margin", &Token{AccessToken: "at", Expiry: now.Add(time.Minute)}, 30 * time.Second, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.Valid(now, tt.margin); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}
