package outbound

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore keeps grants in process memory only. Suitable for tests and for
// deployments that would rather force a re-authorization on restart than write
// refresh tokens to disk.
type MemoryStore struct {
	mu     sync.RWMutex
	grants map[GrantKey]*Token
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{grants: make(map[GrantKey]*Token)}
}

// Get implements [TokenStore].
func (s *MemoryStore) Get(_ context.Context, k GrantKey) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.grants[k]
	if !ok {
		return nil, fmt.Errorf("grant %s/%s: %w", k.Backend, k.User, ErrNotFound)
	}
	// Copy: the caller may refresh in place, and the map must not alias it.
	return t.Clone(), nil
}

// Put implements [TokenStore].
func (s *MemoryStore) Put(_ context.Context, k GrantKey, t *Token) error {
	if t == nil {
		return fmt.Errorf("outbound: put nil token for %s/%s", k.Backend, k.User)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[k] = t.Clone()
	return nil
}

// Delete implements [TokenStore]. Deleting an absent key is not an error:
// callers delete to guarantee absence, and they got what they asked for.
func (s *MemoryStore) Delete(_ context.Context, k GrantKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, k)
	return nil
}
