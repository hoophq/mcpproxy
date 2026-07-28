package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeySize is the AES-256 key length the file store expects in a keyfile.
const KeySize = 32

// LoadOrCreateKey reads a 32-byte raw AES key from path, generating one with
// crypto/rand and writing it 0600 if the file does not exist.
//
// The key lives in its own file rather than inside the store so an operator
// can keep it on a different volume from the ciphertext, a tmpfs or a secret
// mount. A short or long file is rejected outright: stretching or truncating
// operator key material would hide a misconfiguration behind working
// encryption.
func LoadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(key) != KeySize {
			return nil, fmt.Errorf("outbound: keyfile %s is %d bytes, want %d", path, len(key), KeySize)
		}
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("outbound: read keyfile %s: %w", path, err)
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("outbound: create keyfile dir: %w", err)
		}
	}
	key = make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("outbound: generate key: %w", err)
	}
	// O_EXCL so a concurrent creator loses rather than overwriting a key some
	// other process already encrypted data with.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreateKey(path)
		}
		return nil, fmt.Errorf("outbound: create keyfile %s: %w", path, err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, fmt.Errorf("outbound: write keyfile %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("outbound: close keyfile %s: %w", path, err)
	}
	return key, nil
}

// EncryptedFile is a single AES-256-GCM sealed JSON document on disk.
//
// The whole document is one blob rather than a record per key. These stores
// hold a handful of grants, and a single seal keeps the format atomic through
// rename, with no partial-write recovery logic to get wrong.
type EncryptedFile struct {
	Path string
	Key  []byte
}

// ReadJSON decrypts the file into v. A missing file leaves v untouched and
// returns nil, so callers can treat "no store yet" as "empty store".
func (e EncryptedFile) ReadJSON(v any) error {
	blob, err := os.ReadFile(e.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("outbound: read %s: %w", e.Path, err)
	}
	if len(blob) == 0 {
		return nil
	}

	gcm, err := e.aead()
	if err != nil {
		return err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return fmt.Errorf("outbound: %s is truncated (%d bytes)", e.Path, len(blob))
	}
	plain, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		// GCM authentication covers both a wrong key and tampering. The
		// gateway cannot tell them apart, and the operator response is the
		// same either way.
		return fmt.Errorf("outbound: decrypt %s (wrong key or corrupt file): %w", e.Path, err)
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("outbound: decode %s: %w", e.Path, err)
	}
	return nil
}

// WriteJSON seals v and replaces the file atomically.
func (e EncryptedFile) WriteJSON(v any) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("outbound: encode %s: %w", e.Path, err)
	}
	gcm, err := e.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("outbound: generate nonce: %w", err)
	}
	blob := gcm.Seal(nonce, nonce, plain, nil)

	dir := filepath.Dir(e.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("outbound: create store dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(e.Path)+".tmp*")
	if err != nil {
		return fmt.Errorf("outbound: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("outbound: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return fmt.Errorf("outbound: write temp file: %w", err)
	}
	// Durability before visibility: a rename that beats the data to disk can
	// expose an empty file after a crash, losing every stored refresh token.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("outbound: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("outbound: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, e.Path); err != nil {
		return fmt.Errorf("outbound: replace %s: %w", e.Path, err)
	}
	return nil
}

func (e EncryptedFile) aead() (cipher.AEAD, error) {
	if len(e.Key) != KeySize {
		return nil, fmt.Errorf("outbound: key is %d bytes, want %d", len(e.Key), KeySize)
	}
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, fmt.Errorf("outbound: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("outbound: new gcm: %w", err)
	}
	return gcm, nil
}
