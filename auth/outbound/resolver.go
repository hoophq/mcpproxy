package outbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/hoophq/mcpproxy/auth/outbound/oauth"
	"github.com/hoophq/mcpproxy/config"
)

// Deps carries the process-wide collaborators [Resolve] needs. All fields are
// optional; a mode that requires one reports a clear error when it is absent
// rather than failing later on the request path.
type Deps struct {
	// Store persists OAuth grants. Defaults to an in-memory store, which means
	// every restart forces a re-authorization.
	Store TokenStore

	// Authorizer drives the interactive half of the authorization-code flow.
	// Without it, an oauth backend with no stored grant reports that
	// re-authorization is required instead of hanging on a browser that will
	// never open.
	Authorizer oauth.Authorizer

	// ClientStore persists dynamically registered clients, keyed by issuer.
	ClientStore oauth.ClientStore

	// InboundToken yields the caller's own bearer token for RFC 8693 exchange.
	// Defaults to reading the value the gateway middleware put on the context.
	InboundToken func(ctx context.Context) (string, error)

	// UpstreamSwap, when set, supersedes the configured OAuth mode: the
	// embedded auth server already federated the user to the upstream IdP and
	// hands back an upstream credential directly, so re-running a flow here
	// would prompt the same user twice.
	UpstreamSwap TokenSource

	// HTTPClient is used for every OAuth HTTP call.
	HTTPClient *http.Client

	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Resolve builds the outbound token source for one backend.
//
// It is called once per backend at startup, so discovery and dynamic client
// registration happen here rather than on the first tool call; a
// misconfiguration surfaces as a boot failure instead of a mystery 401
// minutes later.
func Resolve(ctx context.Context, backendName string, cfg config.Backend, deps Deps) (TokenSource, error) {
	// stdio backends run as a local subprocess; there is no HTTP request to
	// attach a credential to, and auth for them is the process environment.
	if cfg.Transport == "stdio" {
		return NewNone(), nil
	}

	switch mode := strings.ToLower(strings.TrimSpace(cfg.Auth)); mode {
	case "", "none":
		return NewNone(), nil

	case "static":
		// The secret rides in Headers so it can be named per provider
		// (Authorization, X-Api-Key, ...); an explicit Authorization header is
		// promoted to the token source so the transport applies it uniformly.
		return NewStatic(TrimBearer(cfg.Headers["Authorization"])), nil

	case "passthrough":
		return NewPassthrough(), nil

	case "oauth":
		return resolveOAuth(ctx, backendName, cfg, deps)

	default:
		return nil, fmt.Errorf("outbound: backend %s: unknown auth mode %q", backendName, cfg.Auth)
	}
}

func resolveOAuth(ctx context.Context, backendName string, cfg config.Backend, deps Deps) (TokenSource, error) {
	oc := cfg.OAuth
	if oc == nil {
		oc = &config.OAuthClient{}
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// The embedded auth server owns the upstream relationship when it is
	// federating; running our own flow on top would double-prompt.
	if deps.UpstreamSwap != nil {
		return deps.UpstreamSwap, nil
	}

	md, err := discoverAS(ctx, backendName, cfg, oc, deps)
	if err != nil {
		return nil, err
	}

	client, err := resolveClient(ctx, oc, md, deps)
	if err != nil {
		return nil, err
	}

	clientCfg := oauth.ClientConfig{
		ClientID:      client.ClientID,
		ClientSecret:  client.ClientSecret,
		AuthEndpoint:  md.AuthorizationEndpoint,
		TokenEndpoint: md.TokenEndpoint,
		Scopes:        oc.Scopes,
		Audience:      cfg.URL,
		HTTPClient:    deps.HTTPClient,
	}

	if oc.TokenExchange {
		subject := deps.InboundToken
		if subject == nil {
			subject = inboundTokenFromContext
		}
		return oauth.NewExchangeSource(oauth.ExchangeConfig{
			TokenEndpoint: md.TokenEndpoint,
			ClientID:      client.ClientID,
			ClientSecret:  client.ClientSecret,
			SubjectToken:  subject,
			Audience:      cfg.URL,
			Scopes:        oc.Scopes,
			HTTPClient:    deps.HTTPClient,
		}), nil
	}

	store := deps.Store
	if store == nil {
		store = NewMemoryStore()
	}

	// Per-user backends need one source per caller, so the key is resolved on
	// each request; shared backends resolve it once and reuse the source (and
	// with it the refresh singleflight and the cached token).
	if oc.PerUser {
		return newPerUserSource(backendName, store, clientCfg, deps.Authorizer, logger), nil
	}

	key := GrantKey{Backend: backendName}
	return withAuthorization(store, key, clientCfg, deps.Authorizer, logger), nil
}

// discoverAS resolves the authorization server metadata for a backend, from
// the configured issuer when there is one and from the MCP server's RFC 9728
// resource metadata otherwise.
func discoverAS(
	ctx context.Context,
	backendName string,
	cfg config.Backend,
	oc *config.OAuthClient,
	deps Deps,
) (*oauth.ASMetadata, error) {
	if oc.Issuer != "" {
		md, err := oauth.FetchASMetadata(ctx, oc.Issuer, deps.HTTPClient)
		if err != nil {
			return nil, fmt.Errorf("outbound: backend %s: %w", backendName, err)
		}
		return md, nil
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("outbound: backend %s: oauth requires either an issuer or a backend url", backendName)
	}
	rm, err := oauth.FetchResourceMetadata(ctx, cfg.URL, deps.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("outbound: backend %s: %w", backendName, err)
	}
	if len(rm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf(
			"outbound: backend %s: resource metadata lists no authorization_servers; set oauth.issuer explicitly",
			backendName)
	}

	// Try each advertised server: the first is the resource's preference, but
	// a server that fails discovery is no use to us.
	var lastErr error
	for _, issuer := range rm.AuthorizationServers {
		md, err := oauth.FetchASMetadata(ctx, issuer, deps.HTTPClient)
		if err != nil {
			lastErr = err
			continue
		}
		return md, nil
	}
	return nil, fmt.Errorf("outbound: backend %s: no usable authorization server: %w", backendName, lastErr)
}

// resolveClient returns the manually configured client, or registers one via
// RFC 7591 dynamic client registration.
func resolveClient(
	ctx context.Context,
	oc *config.OAuthClient,
	md *oauth.ASMetadata,
	deps Deps,
) (*oauth.Client, error) {
	if oc.ClientID != "" {
		return &oauth.Client{ClientID: oc.ClientID, ClientSecret: oc.ClientSecret}, nil
	}
	if md.RegistrationEndpoint == "" {
		return nil, fmt.Errorf(
			"outbound: %s advertises no registration_endpoint and no client_id is configured", md.Issuer)
	}
	if !md.SupportsS256() {
		return nil, fmt.Errorf(
			"outbound: %s does not advertise S256 PKCE; refusing to register a public client without it", md.Issuer)
	}

	// The redirect URI registered here is a placeholder loopback: the actual
	// port is chosen when the flow runs. Servers that require an exact match
	// need a manually configured client, which is why the config exposes one.
	return oauth.EnsureClient(ctx, deps.ClientStore, md.Issuer, md.RegistrationEndpoint,
		[]string{"http://127.0.0.1/callback"}, oc.Scopes,
		oauth.RegisterOptions{ClientName: "mcpproxy", HTTPClient: deps.HTTPClient})
}

// withAuthorization wraps a refreshing source so a missing or dead grant
// triggers the interactive flow once, instead of failing every request until
// an operator intervenes.
func withAuthorization(
	store TokenStore,
	key GrantKey,
	clientCfg oauth.ClientConfig,
	az oauth.Authorizer,
	logger *slog.Logger,
) TokenSource {
	refresh := oauth.NewRefreshingSource(store, key, oauth.RefreshConfig{Client: clientCfg})

	return func(ctx context.Context) (string, error) {
		tok, err := refresh(ctx)
		if err == nil {
			return tok, nil
		}
		var reauth *oauth.ErrReauthorize
		if !errors.As(err, &reauth) {
			return "", err
		}
		if az == nil {
			return "", err
		}

		logger.Info("running outbound authorization flow",
			"backend", key.Backend, "user", key.User, "reason", reauth.Reason)
		fresh, err := oauth.Authorize(ctx, clientCfg, az)
		if err != nil {
			return "", err
		}
		if err := store.Put(ctx, key, fresh); err != nil {
			return "", fmt.Errorf("outbound: persist grant for %s: %w", key.Backend, err)
		}
		return fresh.AccessToken, nil
	}
}

// perUserSource lazily builds one authorizing source per user, so each user's
// grant gets its own refresh singleflight and cached token.
type perUserSource struct {
	backend   string
	store     TokenStore
	clientCfg oauth.ClientConfig
	az        oauth.Authorizer
	logger    *slog.Logger

	mu     sync.Mutex
	byUser map[string]TokenSource
}

func newPerUserSource(
	backend string,
	store TokenStore,
	clientCfg oauth.ClientConfig,
	az oauth.Authorizer,
	logger *slog.Logger,
) TokenSource {
	s := &perUserSource{
		backend:   backend,
		store:     store,
		clientCfg: clientCfg,
		az:        az,
		logger:    logger,
		byUser:    make(map[string]TokenSource),
	}
	return s.token
}

func (s *perUserSource) token(ctx context.Context) (string, error) {
	user, ok := UserFrom(ctx)
	if !ok {
		return "", fmt.Errorf(
			"outbound: backend %s is configured per_user but the request carries no authenticated user", s.backend)
	}

	s.mu.Lock()
	src, ok := s.byUser[user]
	if !ok {
		src = withAuthorization(s.store, GrantKey{Backend: s.backend, User: user}, s.clientCfg, s.az, s.logger)
		s.byUser[user] = src
	}
	s.mu.Unlock()

	return src(ctx)
}

// inboundTokenFromContext is the default subject-token source for RFC 8693:
// whatever the gateway middleware recorded from the inbound Authorization
// header.
func inboundTokenFromContext(ctx context.Context) (string, error) {
	tok, ok := InboundTokenFrom(ctx)
	if !ok {
		return "", fmt.Errorf("outbound: token exchange needs the caller's bearer token, but none is on the request")
	}
	return tok, nil
}

// NewLoopbackAuthorizer returns an [oauth.Authorizer] that completes the flow
// through a local listener on 127.0.0.1, logging the URL for the operator to
// open.
func NewLoopbackAuthorizer(logger *slog.Logger) oauth.Authorizer {
	return &oauth.LoopbackAuthorizer{Logger: logger}
}
