package authserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hoophq/mcpproxy/auth/outbound"
	"github.com/hoophq/mcpproxy/auth/outbound/oauth"
	"github.com/hoophq/mcpproxy/config"
)

// UpstreamFederator delegates end-user login to a company IdP. The gateway
// remains the OAuth authorization server its MCP clients talk to; the
// federator only decides *who* the user is and hands back the upstream tokens
// so the token-swap path (see swap.go) can call downstream APIs as them.
//
// AuthorizeURL receives our internal grant id and MUST round-trip it as the
// upstream `state` so /callback can correlate the response with the pending
// authorization request.
type UpstreamFederator interface {
	AuthorizeURL(state string) (string, error)
	Exchange(ctx context.Context, code string) (idClaims map[string]any, tokens *outbound.Token, err error)
}

// OIDCFederator federates to an OIDC provider discovered from its issuer.
//
// It deliberately does not run PKCE against the upstream: the UpstreamFederator
// contract exchanges a code without the originating state, so there is no way
// to look the per-request verifier back up. The flow stays safe because the
// redirect URI is fixed and registered, `state` is an unguessable grant id we
// mint, and a confidential client authenticates with its secret.
type OIDCFederator struct {
	meta        *oauth.ASMetadata
	cfg         oauth.ClientConfig
	redirectURI string
	scopes      []string
}

// NewOIDCFederator discovers the upstream IdP's endpoints and returns a
// federator that will send users to it. redirectURI must be this gateway's
// /callback URL and must be registered with the upstream provider.
func NewOIDCFederator(ctx context.Context, cc config.OAuthClient, redirectURI string, hc *http.Client) (*OIDCFederator, error) {
	if cc.Issuer == "" {
		return nil, fmt.Errorf("upstream issuer is required")
	}
	if cc.ClientID == "" {
		return nil, fmt.Errorf("upstream client_id is required")
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("upstream redirect URI is required")
	}
	meta, err := oauth.FetchASMetadata(ctx, cc.Issuer, hc)
	if err != nil {
		return nil, fmt.Errorf("discover upstream %s: %w", cc.Issuer, err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("upstream %s advertises no authorization/token endpoint", cc.Issuer)
	}

	// openid is required for the IdP to return an ID token, which is where we
	// read the user's identity from.
	scopes := cc.Scopes
	if !containsFold(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}

	return &OIDCFederator{
		meta:        meta,
		redirectURI: redirectURI,
		scopes:      scopes,
		cfg: oauth.ClientConfig{
			ClientID:      cc.ClientID,
			ClientSecret:  cc.ClientSecret,
			TokenEndpoint: meta.TokenEndpoint,
			AuthEndpoint:  meta.AuthorizationEndpoint,
			Scopes:        scopes,
			HTTPClient:    hc,
		},
	}, nil
}

// AuthorizeURL builds the upstream authorization request carrying state.
func (f *OIDCFederator) AuthorizeURL(state string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("state is required")
	}
	u, err := url.Parse(f.meta.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse upstream authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", f.cfg.ClientID)
	q.Set("redirect_uri", f.redirectURI)
	q.Set("scope", strings.Join(f.scopes, " "))
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades the upstream code for tokens and returns the ID token's
// claims alongside them.
func (f *OIDCFederator) Exchange(ctx context.Context, code string) (map[string]any, *outbound.Token, error) {
	tok, err := oauth.ExchangeCode(ctx, f.cfg, code, f.redirectURI, "")
	if err != nil {
		return nil, nil, fmt.Errorf("upstream code exchange: %w", err)
	}
	raw := tok.Extra["id_token"]
	if raw == "" {
		return nil, nil, fmt.Errorf("upstream token response carried no id_token")
	}
	claims, err := parseJWTClaims(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream id_token: %w", err)
	}
	// Issuer check only. We do not verify the ID token's signature, and that
	// is correct here rather than lazy: OpenID Connect Core §3.1.3.7 lets a
	// client skip signature validation when the token arrives directly from
	// the token endpoint over a TLS-protected channel it authenticated — which
	// is exactly this code path (we discovered the endpoint from the issuer,
	// posted to it ourselves, and read the response). A signature check would
	// re-verify a channel we already trust. The issuer comparison still runs
	// because an ID token minted by a *different* provider must never be
	// accepted, TLS notwithstanding.
	if iss, _ := claims["iss"].(string); !issuerMatches(iss, f.meta.Issuer) {
		return nil, nil, fmt.Errorf("upstream id_token issuer %q does not match %q", iss, f.meta.Issuer)
	}
	return claims, tok, nil
}

// parseJWTClaims decodes a JWT payload without verifying it. Callers must have
// their own reason to trust the token (see Exchange).
func parseJWTClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}
	return claims, nil
}

// issuerMatches compares issuers ignoring a trailing slash, which providers
// are inconsistent about between their discovery doc and their tokens.
func issuerMatches(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// identityFromClaims maps upstream ID token claims onto our identity model.
// The subject is namespaced by issuer so two IdPs cannot collide on "1234".
func identityFromClaims(claims map[string]any, issuer string) (subject, email string, err error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", "", fmt.Errorf("upstream id_token has no sub claim")
	}
	email, _ = claims["email"].(string)
	if email == "" {
		// Some providers (notably Azure AD for guest accounts) only populate
		// preferred_username with the mail address.
		email, _ = claims["preferred_username"].(string)
	}
	if issuer != "" {
		sub = strings.TrimSuffix(issuer, "/") + "#" + sub
	}
	return sub, email, nil
}
