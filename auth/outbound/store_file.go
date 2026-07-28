package outbound

import (
	"context"
	"fmt"
	"sync"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// FileStore persists grants in an AES-256-GCM encrypted file.
//
// Every operation re-reads the file before mutating it, so a stale in-memory
// snapshot cannot clobber writes from a second gateway process or from an
// operator revoking a grant by hand.
type FileStore struct {
	mu   sync.Mutex
	file core.EncryptedFile
}

// storedGrants is the on-disk shape. JSON object keys must be strings, so this
// flattens GrantKey into a nested map instead of using it directly.
type storedGrants struct {
	// Grants maps backend name → user ("" for backend-wide) → token.
	Grants map[string]map[string]*Token `json:"grants"`
}

// NewFileStore opens (or lazily creates) an encrypted grant store at path,
// using the AES-256 key in keyfilePath, generating that keyfile if absent.
func NewFileStore(path, keyfilePath string) (*FileStore, error) {
	key, err := core.LoadOrCreateKey(keyfilePath)
	if err != nil {
		return nil, err
	}
	s := &FileStore{file: core.EncryptedFile{Path: path, Key: key}}
	// Fail fast on an unreadable or wrongly-keyed store instead of surfacing
	// it mid-request as a spurious "not found" that triggers a pointless
	// re-authorization.
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() (*storedGrants, error) {
	var doc storedGrants
	if err := s.file.ReadJSON(&doc); err != nil {
		return nil, err
	}
	if doc.Grants == nil {
		doc.Grants = make(map[string]map[string]*Token)
	}
	return &doc, nil
}

// Get implements [TokenStore].
func (s *FileStore) Get(_ context.Context, k GrantKey) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	t, ok := doc.Grants[k.Backend][k.User]
	if !ok || t == nil {
		return nil, fmt.Errorf("grant %s/%s: %w", k.Backend, k.User, ErrNotFound)
	}
	return t, nil
}

// Put implements [TokenStore].
func (s *FileStore) Put(_ context.Context, k GrantKey, t *Token) error {
	if t == nil {
		return fmt.Errorf("outbound: put nil token for %s/%s", k.Backend, k.User)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return err
	}
	byUser := doc.Grants[k.Backend]
	if byUser == nil {
		byUser = make(map[string]*Token)
		doc.Grants[k.Backend] = byUser
	}
	byUser[k.User] = t
	return s.file.WriteJSON(doc)
}

// Delete implements [TokenStore]. Deleting an absent key succeeds: the caller
// wanted the key gone, and it is gone.
func (s *FileStore) Delete(_ context.Context, k GrantKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return err
	}
	byUser, ok := doc.Grants[k.Backend]
	if !ok {
		return nil
	}
	if _, ok := byUser[k.User]; !ok {
		return nil
	}
	delete(byUser, k.User)
	if len(byUser) == 0 {
		delete(doc.Grants, k.Backend)
	}
	return s.file.WriteJSON(doc)
}
