// Package authserver embeds an OAuth 2.1 authorization server in the gateway
// so MCP clients authenticate against the gateway itself instead of needing a
// separate IdP registration per client.
//
// It implements the subset of OAuth that the MCP authorization spec requires
// and nothing more: RFC 8414 metadata discovery, RFC 7591 dynamic client
// registration for public clients, authorization code with mandatory PKCE
// (S256), and refresh tokens with rotation. Access tokens are ES256 JWTs the
// gateway signs and verifies itself — ValidateToken is the inbound resolver
// when auth_server is enabled.
//
// Login is either local (no upstream configured: everyone becomes a fixed dev
// identity, which the server warns loudly about) or federated to a company
// OIDC provider. In the federated case the upstream access token is retained
// per subject so backends configured for token swap can call downstream APIs
// as the user; see swap.go.
//
// All state is in memory. Restarting the gateway invalidates outstanding
// codes, refresh tokens and upstream tokens, and access tokens survive only if
// a signing key file was configured.
package authserver

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hoophq/mcpproxy/auth/outbound"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
)

// defaultAccessTokenTTL applies when config.AuthServer.AccessTokenTTL is zero.
const defaultAccessTokenTTL = time.Hour

// refreshTokenTTL bounds an idle session. Rotation on every use means an
// active client keeps extending it; an abandoned one dies here.
const refreshTokenTTL = 30 * 24 * time.Hour

// maxRegisterBody caps the DCR request body. Generous for a legitimate client
// metadata document, small enough that an unauthenticated endpoint cannot be
// used to make us buffer megabytes.
const maxRegisterBody = 64 * 1024

// devSubject is the identity handed out when no upstream IdP is configured.
const devSubject = "local-user"

// Server is the embedded authorization server.
type Server struct {
	issuer   string
	key      *ecdsa.PrivateKey
	kid      string
	jwks     []byte
	tokenTTL time.Duration
	upstream UpstreamFederator
	store    *store
	log      *slog.Logger

	// now is the clock, swappable in tests.
	now func() time.Time
}

// New builds a Server from configuration. upstream may be nil, which selects
// local auto-approval; construct one with NewOIDCFederator to federate.
func New(cfg config.AuthServer, upstream UpstreamFederator) (*Server, error) {
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	if issuer == "" {
		return nil, fmt.Errorf("auth server issuer is required")
	}

	key, err := loadOrCreateKey(cfg.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	kid, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive key id: %w", err)
	}
	set, err := publicJWKS(&key.PublicKey, kid)
	if err != nil {
		return nil, fmt.Errorf("build JWKS: %w", err)
	}
	jwksBytes, err := marshalJWKS(set)
	if err != nil {
		return nil, err
	}

	ttl := cfg.AccessTokenTTL
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}

	s := &Server{
		issuer:   issuer,
		key:      key,
		kid:      kid,
		jwks:     jwksBytes,
		tokenTTL: ttl,
		upstream: upstream,
		store:    newStore(),
		log:      slog.Default().With("component", "authserver"),
		now:      time.Now,
	}
	if cfg.SigningKeyFile == "" {
		s.log.Warn("auth server signing key is ephemeral; set signing_key_file to survive restarts")
	}
	return s, nil
}

// Issuer returns the external URL clients see this server as.
func (s *Server) Issuer() string { return s.issuer }

// Routes returns the OAuth endpoints. Mount it at the gateway's root: the
// paths are fixed because RFC 8414 pins the well-known locations and clients
// read the rest out of the metadata document.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /callback", s.handleCallback)
	mux.HandleFunc("POST /token", s.handleToken)
	return mux
}

// metadata is the RFC 8414 authorization server metadata document.
type metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, metadata{
		Issuer:                s.issuer,
		AuthorizationEndpoint: s.issuer + "/authorize",
		TokenEndpoint:         s.issuer + "/token",
		RegistrationEndpoint:  s.issuer + "/register",
		JWKSURI:               s.issuer + "/.well-known/jwks.json",

		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		// S256 only. OAuth 2.1 forbids "plain", and every MCP client library
		// supports S256.
		CodeChallengeMethodsSupported: []string{"S256"},
		// "none": all our clients are public and authenticate with PKCE.
		TokenEndpointAuthMethodsSupported: []string{"none"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(s.jwks)
}

// registrationRequest is the RFC 7591 client metadata we read. Everything else
// in the document is accepted and ignored.
type registrationRequest struct {
	RedirectURIs  []string `json:"redirect_uris"`
	ClientName    string   `json:"client_name,omitempty"`
	GrantTypes    []string `json:"grant_types,omitempty"`
	ResponseTypes []string `json:"response_types,omitempty"`
}

// registrationResponse is the RFC 7591 §3.2.1 success body.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBody)

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	id, err := randomToken(24)
	if err != nil {
		s.log.Error("generate client id", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate client id")
		return
	}

	now := s.now()
	c := &client{
		ID:           id,
		RedirectURIs: req.RedirectURIs,
		Name:         req.ClientName,
		IssuedAt:     now,
	}
	s.store.putClient(c)
	s.log.Debug("registered client", "client_id", id, "client_name", req.ClientName)

	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:         id,
		ClientIDIssuedAt: now.Unix(),
		RedirectURIs:     req.RedirectURIs,
		ClientName:       req.ClientName,
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		ResponseTypes:    []string{"code"},
		// No secret is issued: see the client type's doc comment.
		TokenEndpointAuthMethod: "none",
	})
}

// ValidateToken verifies an access token this server minted and returns the
// caller's identity. It is the gateway's inbound IdentityResolver when
// auth_server is enabled; Resolver adapts it to that signature.
//
// The audience is deliberately not checked. `aud` holds the client id that
// obtained the token, and every such token is meant for exactly one resource
// — this gateway — so there is no second audience to confuse it with. Pinning
// it to a fixed value would instead break dynamic registration, where client
// ids are minted per client at runtime. Issuer and signature already bind the
// token to this server.
func (s *Server) ValidateToken(_ context.Context, raw string) (inspect.Identity, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if raw == "" {
		return inspect.Identity{}, errors.New("empty bearer token")
	}

	claims := jwt.MapClaims{}
	// Pinning ES256 is what stops the alg-confusion family of attacks: without
	// it a token claiming alg=none or alg=HS256 (keyed on our public key)
	// would be handed to a verifier that trusts the header.
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.now),
	).ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		return &s.key.PublicKey, nil
	})
	if err != nil {
		return inspect.Identity{}, fmt.Errorf("invalid access token: %w", err)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return inspect.Identity{}, errors.New("access token has no sub claim")
	}
	email, _ := claims["email"].(string)
	return inspect.Identity{Subject: sub, Email: email, Claims: claims}, nil
}

// Resolver adapts ValidateToken to the gateway's IdentityResolver shape.
func (s *Server) Resolver(r *http.Request) (inspect.Identity, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return inspect.Identity{}, errors.New("missing Authorization header")
	}
	return s.ValidateToken(r.Context(), h)
}

// UpstreamTokens returns the upstream IdP tokens held for a subject. Absent
// when no upstream is configured or the user has not logged in since the last
// restart.
func (s *Server) UpstreamTokens(subject string) (*outbound.Token, bool) {
	t, ok := s.store.getUpstream(subject)
	return t, ok
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Debug("authserver: encode response", "error", err)
	}
}

// oauthError is the RFC 6749 §5.2 error body, also used for RFC 7591 errors.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, oauthError{Error: code, Description: desc})
}
