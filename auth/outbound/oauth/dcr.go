package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// Client is a registered OAuth client.
type Client struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	// RegistrationEndpoint records where this client was registered, so
	// EnsureClient does not reuse a cached entry against a different
	// authorization server that shares an issuer string.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// AuthMethod is the token_endpoint_auth_method the server accepted.
	AuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

// Public reports whether the client has no secret and must authenticate at the
// token endpoint by client_id alone.
func (c *Client) Public() bool { return c == nil || c.ClientSecret == "" }

// registrationRequest is the RFC 7591 client metadata document.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
}

// registrationResponse is the RFC 7591 §3.2.1 success body, decoding only the
// fields this package acts on.
type registrationResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	Error                   string `json:"error,omitempty"`
	ErrorDescription        string `json:"error_description,omitempty"`
}

// RegisterOptions tunes a dynamic client registration.
type RegisterOptions struct {
	// ClientName is the human-readable name shown on consent screens.
	ClientName string
	// InitialAccessToken authenticates the registration request itself, for
	// servers that gate DCR (RFC 7591 §3.1).
	InitialAccessToken string
	// Confidential requests a client secret. The default is a public client
	// (token_endpoint_auth_method=none), the right choice for a loopback
	// redirect flow, where a secret shipped to a local listener protects
	// nothing.
	Confidential bool
	HTTPClient   *http.Client
}

// RegisterClient performs RFC 7591 dynamic client registration.
func RegisterClient(
	ctx context.Context,
	registrationEndpoint string,
	redirectURIs []string,
	scopes []string,
	opts RegisterOptions,
) (*Client, error) {
	if registrationEndpoint == "" {
		return nil, errors.New("oauth: registration endpoint is empty")
	}
	if len(redirectURIs) == 0 {
		return nil, errors.New("oauth: registration requires at least one redirect URI")
	}

	authMethod := "none"
	if opts.Confidential {
		authMethod = "client_secret_basic"
	}
	name := opts.ClientName
	if name == "" {
		name = "mcpproxy"
	}
	body, err := json.Marshal(registrationRequest{
		RedirectURIs:            redirectURIs,
		ClientName:              name,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: authMethod,
		Scope:                   strings.Join(scopes, " "),
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: encode registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("oauth: build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if opts.InitialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.InitialAccessToken)
	}

	resp, err := client(opts.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: register client: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return nil, fmt.Errorf("oauth: read registration response: %w", err)
	}

	var out registrationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("oauth: decode registration response (status %d): %w", resp.StatusCode, err)
	}
	// RFC 7591 mandates 201, but servers return 200 often enough that keying
	// on the client_id is more reliable than keying on the status code.
	if out.Error != "" || out.ClientID == "" {
		if out.Error != "" {
			return nil, fmt.Errorf("oauth: registration rejected (status %d): %s: %s",
				resp.StatusCode, out.Error, out.ErrorDescription)
		}
		return nil, fmt.Errorf("oauth: registration returned no client_id (status %d)", resp.StatusCode)
	}

	got := out.TokenEndpointAuthMethod
	if got == "" {
		got = authMethod
	}
	return &Client{
		ClientID:             out.ClientID,
		ClientSecret:         out.ClientSecret,
		RegistrationEndpoint: registrationEndpoint,
		AuthMethod:           got,
	}, nil
}

// ClientStore persists dynamically registered clients keyed by issuer.
//
// Re-registering on every restart leaves orphaned client records on the
// authorization server and, on servers that show one consent entry per client,
// fills the user's account page with duplicates. Persisting the registration
// keeps one client per (gateway, issuer) pair.
type ClientStore interface {
	Get(ctx context.Context, issuer string) (*Client, error)
	Put(ctx context.Context, issuer string, c *Client) error
}

// ErrClientNotFound reports that no client is registered for an issuer.
// [ClientStore.Get] returns it.
var ErrClientNotFound = errors.New("oauth: client not registered")

// MemoryClientStore keeps registrations in memory.
type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]*Client
}

// NewMemoryClientStore returns an empty in-memory client store.
func NewMemoryClientStore() *MemoryClientStore {
	return &MemoryClientStore{clients: make(map[string]*Client)}
}

// Get implements [ClientStore].
func (s *MemoryClientStore) Get(_ context.Context, issuer string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[issuer]
	if !ok {
		return nil, fmt.Errorf("issuer %s: %w", issuer, ErrClientNotFound)
	}
	cp := *c
	return &cp, nil
}

// Put implements [ClientStore].
func (s *MemoryClientStore) Put(_ context.Context, issuer string, c *Client) error {
	if c == nil {
		return fmt.Errorf("oauth: put nil client for %s", issuer)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.clients[issuer] = &cp
	return nil
}

// FileClientStore persists registrations in an AES-256-GCM encrypted file,
// reusing the mechanics of the outbound token store. A client secret is a
// credential and earns the same protection as a refresh token.
type FileClientStore struct {
	mu   sync.Mutex
	file core.EncryptedFile
}

type storedClients struct {
	Clients map[string]*Client `json:"clients"`
}

// NewFileClientStore opens (or lazily creates) an encrypted client store at
// path, using the AES-256 key in keyfilePath, generating that keyfile if
// absent.
func NewFileClientStore(path, keyfilePath string) (*FileClientStore, error) {
	key, err := core.LoadOrCreateKey(keyfilePath)
	if err != nil {
		return nil, err
	}
	s := &FileClientStore{file: core.EncryptedFile{Path: path, Key: key}}
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileClientStore) load() (*storedClients, error) {
	var doc storedClients
	if err := s.file.ReadJSON(&doc); err != nil {
		return nil, err
	}
	if doc.Clients == nil {
		doc.Clients = make(map[string]*Client)
	}
	return &doc, nil
}

// Get implements [ClientStore].
func (s *FileClientStore) Get(_ context.Context, issuer string) (*Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	c, ok := doc.Clients[issuer]
	if !ok || c == nil {
		return nil, fmt.Errorf("issuer %s: %w", issuer, ErrClientNotFound)
	}
	return c, nil
}

// Put implements [ClientStore].
func (s *FileClientStore) Put(_ context.Context, issuer string, c *Client) error {
	if c == nil {
		return fmt.Errorf("oauth: put nil client for %s", issuer)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return err
	}
	doc.Clients[issuer] = c
	return s.file.WriteJSON(doc)
}

// EnsureClient returns the stored client for issuer, registering one via DCR
// on first use.
//
// EnsureClient drops a cached client registered against a different endpoint
// instead of reusing it. The issuer string alone does not pin the
// authorization server, and presenting a client_id to the wrong server yields
// an opaque invalid_client at token time.
func EnsureClient(
	ctx context.Context,
	store ClientStore,
	issuer string,
	registrationEndpoint string,
	redirectURIs []string,
	scopes []string,
	opts RegisterOptions,
) (*Client, error) {
	if store != nil {
		c, err := store.Get(ctx, issuer)
		switch {
		case err == nil && c.ClientID != "" &&
			(c.RegistrationEndpoint == "" || c.RegistrationEndpoint == registrationEndpoint):
			return c, nil
		case err != nil && !errors.Is(err, ErrClientNotFound):
			return nil, err
		}
	}

	c, err := RegisterClient(ctx, registrationEndpoint, redirectURIs, scopes, opts)
	if err != nil {
		return nil, err
	}
	if store != nil {
		if err := store.Put(ctx, issuer, c); err != nil {
			return nil, fmt.Errorf("oauth: persist registered client: %w", err)
		}
	}
	return c, nil
}
