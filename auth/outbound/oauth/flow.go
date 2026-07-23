package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hoophq/mcpproxy/auth/outbound/internal/core"
)

// ClientConfig describes an OAuth client and the endpoints it talks to.
type ClientConfig struct {
	ClientID      string
	ClientSecret  string // empty = public client
	AuthEndpoint  string
	TokenEndpoint string
	Scopes        []string
	// Audience, when set, is sent as the RFC 8707 resource indicator so the
	// authorization server mints a token scoped to this MCP server rather than
	// one valid everywhere.
	Audience   string
	HTTPClient *http.Client
}

// AuthorizeRequest is what an [Authorizer] must get in front of the user.
type AuthorizeRequest struct {
	// URL is the fully built authorization URL.
	URL string
	// State is the CSRF value embedded in URL; the authorizer must reject a
	// callback carrying anything else.
	State string
	// RedirectURI is the redirect the URL was built with.
	RedirectURI string
}

// Authorizer obtains an authorization code for a built authorization URL.
//
// This is the seam between the protocol (which is fixed) and how a deployment
// actually gets a human to a browser: a CLI opens a loopback listener, a hosted
// gateway hands the URL to its own UI and waits for the callback it already
// owns. Returning the redirect URI along with the code lets an authorizer pick
// its own (e.g. an ephemeral loopback port) while the caller still sends the
// matching value on the token request, as RFC 6749 §4.1.3 requires.
type Authorizer interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (code string, redirectURI string, err error)
}

// AuthorizerFunc adapts a function to [Authorizer].
type AuthorizerFunc func(ctx context.Context, req AuthorizeRequest) (string, string, error)

// Authorize implements [Authorizer].
func (f AuthorizerFunc) Authorize(ctx context.Context, req AuthorizeRequest) (string, string, error) {
	return f(ctx, req)
}

// RedirectURIProvider is an optional [Authorizer] extension: an authorizer that
// must be reached at a specific URL (a loopback listener on an ephemeral port)
// declares it before the authorization URL is built, so the URL carries the
// right redirect_uri.
type RedirectURIProvider interface {
	RedirectURI(ctx context.Context) (string, error)
}

// pkce is a generated code verifier and its S256 challenge.
type pkce struct {
	Verifier  string
	Challenge string
}

// newPKCE generates a 32-byte verifier (RFC 7636 §4.1 allows 43-128 chars;
// base64url of 32 random bytes lands at 43) and its S256 challenge.
func newPKCE() (pkce, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return pkce{}, fmt.Errorf("oauth: generate pkce verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return pkce{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// BuildAuthorizeURL assembles an authorization-code request URL with an S256
// PKCE challenge.
func BuildAuthorizeURL(cfg ClientConfig, redirectURI, state, challenge string) (string, error) {
	if cfg.AuthEndpoint == "" {
		return "", errors.New("oauth: authorization endpoint is empty")
	}
	u, err := url.Parse(cfg.AuthEndpoint)
	if err != nil {
		return "", fmt.Errorf("oauth: parse authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.Audience != "" {
		q.Set("resource", cfg.Audience)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Authorize runs the full PKCE authorization-code flow and returns the granted
// token.
func Authorize(ctx context.Context, cfg ClientConfig, az Authorizer) (*core.Token, error) {
	if az == nil {
		return nil, errors.New("oauth: no authorizer configured for this backend")
	}
	p, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomState()
	if err != nil {
		return nil, err
	}

	redirectURI := ""
	if rp, ok := az.(RedirectURIProvider); ok {
		if redirectURI, err = rp.RedirectURI(ctx); err != nil {
			return nil, err
		}
	}

	authURL, err := BuildAuthorizeURL(cfg, redirectURI, state, p.Challenge)
	if err != nil {
		return nil, err
	}

	code, gotRedirect, err := az.Authorize(ctx, AuthorizeRequest{
		URL: authURL, State: state, RedirectURI: redirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: authorization failed: %w", err)
	}
	if code == "" {
		return nil, errors.New("oauth: authorizer returned an empty authorization code")
	}
	if gotRedirect != "" {
		redirectURI = gotRedirect
	}

	return ExchangeCode(ctx, cfg, code, redirectURI, p.Verifier)
}

// tokenResponse is the RFC 6749 §5.1 token endpoint body. Extra fields are
// captured separately so provider-specific values (notably id_token) survive.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// standardTokenFields are lifted into outbound.Token proper; anything else in
// the response lands in Token.Extra.
var standardTokenFields = map[string]bool{
	"access_token": true, "token_type": true, "expires_in": true,
	"refresh_token": true, "error": true, "error_description": true,
}

// ExchangeCode redeems an authorization code at the token endpoint.
// A non-empty verifier adds the PKCE code_verifier.
func ExchangeCode(ctx context.Context, cfg ClientConfig, code, redirectURI, verifier string) (*core.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if cfg.Audience != "" {
		form.Set("resource", cfg.Audience)
	}
	return postToken(ctx, cfg, form)
}

// Refresh runs the refresh-token grant.
func Refresh(ctx context.Context, cfg ClientConfig, refreshToken string) (*core.Token, error) {
	if refreshToken == "" {
		return nil, errors.New("oauth: refresh called with an empty refresh token")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.Audience != "" {
		form.Set("resource", cfg.Audience)
	}
	tok, err := postToken(ctx, cfg, form)
	if err != nil {
		return nil, err
	}
	// Servers that do not rotate refresh tokens omit the field; dropping it
	// would make the next refresh impossible.
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return tok, nil
}

// postToken performs a token-endpoint request and decodes the result.
//
// Confidential clients authenticate with HTTP Basic (the RFC 6749 §2.3.1
// SHOULD-support method); public clients send client_id in the body, because
// strict OAuth 2.1 servers reject Basic for token_endpoint_auth_method=none and
// burn the single-use code doing it.
func postToken(ctx context.Context, cfg ClientConfig, form url.Values) (*core.Token, error) {
	if cfg.TokenEndpoint == "" {
		return nil, errors.New("oauth: token endpoint is empty")
	}
	if cfg.ClientSecret == "" && cfg.ClientID != "" {
		form.Set("client_id", cfg.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}

	resp, err := client(cfg.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: token request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return nil, fmt.Errorf("oauth: read token response: %w", err)
	}
	return decodeToken(raw, resp.StatusCode)
}

func decodeToken(raw []byte, status int) (*core.Token, error) {
	var tr tokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("oauth: decode token response (status %d): %w", status, err)
	}
	if tr.Error != "" {
		return nil, &TokenError{Code: tr.Error, Description: tr.ErrorDescription, Status: status}
	}
	if status != http.StatusOK {
		return nil, &TokenError{Code: "http_error", Description: fmt.Sprintf("status %d", status), Status: status}
	}
	if tr.AccessToken == "" {
		return nil, errors.New("oauth: token response contained no access_token")
	}

	tok := &core.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	// Keep provider extras (id_token, issued_token_type, scope, ...): callers
	// such as the embedded auth server need the id_token, and re-fetching it is
	// impossible once the code is burned.
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err == nil {
		for k, v := range all {
			if standardTokenFields[k] {
				continue
			}
			if s, ok := jsonScalar(v); ok {
				if tok.Extra == nil {
					tok.Extra = make(map[string]string, len(all))
				}
				tok.Extra[k] = s
			}
		}
	}
	return tok, nil
}

// jsonScalar renders a JSON value as a string when it is a scalar, so Extra
// stays a flat map instead of carrying nested provider payloads nobody reads.
func jsonScalar(v json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s, true
	}
	var f float64
	if err := json.Unmarshal(v, &f); err == nil {
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", f), "0"), "."), true
	}
	var b bool
	if err := json.Unmarshal(v, &b); err == nil {
		return fmt.Sprintf("%t", b), true
	}
	return "", false
}

// TokenError is an RFC 6749 §5.2 error response from a token endpoint.
type TokenError struct {
	Code        string
	Description string
	Status      int
}

func (e *TokenError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth: token endpoint returned %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("oauth: token endpoint returned %s", e.Code)
}

// InvalidGrant reports whether the server rejected the grant itself — an
// expired or revoked refresh token — which means re-authorization rather than
// retry.
func (e *TokenError) InvalidGrant() bool {
	return e.Code == "invalid_grant"
}

// LoopbackAuthorizer completes the flow through a loopback HTTP listener, per
// RFC 8252 §7.3 (native app redirection).
//
// The listener binds 127.0.0.1:0 and is opened by [LoopbackAuthorizer.RedirectURI]
// before the authorization URL is built, so the URL carries the real port. The
// zero value is usable; Logger defaults to slog.Default().
type LoopbackAuthorizer struct {
	// Prompt receives the authorization URL. Default: log it at info level.
	Prompt func(url string)
	// Timeout bounds the wait for the user to finish. Default 3 minutes.
	Timeout time.Duration
	// Logger is used for the default prompt and for callback diagnostics.
	Logger *slog.Logger

	ln   net.Listener
	addr string
}

// RedirectURI opens the loopback listener and returns its callback URL. It
// implements [RedirectURIProvider]; calling it twice reuses the same listener.
func (a *LoopbackAuthorizer) RedirectURI(context.Context) (string, error) {
	if a.ln != nil {
		return a.addr, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("oauth: open loopback listener: %w", err)
	}
	a.ln = ln
	a.addr = fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	return a.addr, nil
}

// Authorize implements [Authorizer]: it prompts with the URL, serves the
// redirect, and returns the code.
func (a *LoopbackAuthorizer) Authorize(ctx context.Context, req AuthorizeRequest) (string, string, error) {
	redirectURI, err := a.RedirectURI(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = a.ln.Close()
		a.ln, a.addr = nil, ""
	}()

	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}

	// Buffered: the handler must never block if the wait below has already
	// given up on a timeout.
	resultCh := make(chan callbackResult, 1)

	srv := &http.Server{
		Handler:           http.HandlerFunc(a.handleCallback(req.State, resultCh)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.Serve(a.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("oauth: callback server: %w", err)}:
			default:
			}
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if a.Prompt != nil {
		a.Prompt(req.URL)
	} else {
		logger.Info("open this URL to authorize the backend", "url", req.URL)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-resultCh:
		if r.err != nil {
			return "", "", r.err
		}
		return r.code, redirectURI, nil
	case <-ctx.Done():
		return "", "", fmt.Errorf("oauth: authorization canceled: %w", ctx.Err())
	case <-timer.C:
		return "", "", fmt.Errorf("oauth: timed out after %s waiting for the authorization callback", timeout)
	}
}

// callbackResult carries whichever of code/err the redirect handler produced.
type callbackResult struct {
	code string
	err  error
}

func (a *LoopbackAuthorizer) handleCallback(wantState string, resultCh chan<- callbackResult) http.HandlerFunc {
	deliver := func(r callbackResult) {
		select {
		case resultCh <- r:
		default: // already resolved; a duplicate callback changes nothing
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errCode := q.Get("error"); errCode != "" {
			desc := q.Get("error_description")
			http.Error(w, "authorization failed: "+errCode, http.StatusBadRequest)
			deliver(callbackResult{err: &TokenError{Code: errCode, Description: desc, Status: http.StatusBadRequest}})
			return
		}
		// State check before the code is read: an attacker-supplied callback
		// would otherwise inject their own authorization code into our session
		// (RFC 6749 §10.12).
		if got := q.Get("state"); got != wantState {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			deliver(callbackResult{err: errors.New("oauth: callback state mismatch")})
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			deliver(callbackResult{err: errors.New("oauth: callback carried no authorization code")})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Authorization complete. You can close this window.")
		deliver(callbackResult{code: code})
	}
}
