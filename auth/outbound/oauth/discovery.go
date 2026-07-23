// Package oauth implements the outbound OAuth machinery: RFC 9728/8414
// metadata discovery, RFC 7591 dynamic client registration, the PKCE
// authorization-code flow, refresh-token renewal, and RFC 8693 token exchange.
//
// Every entry point is stdlib-only and takes an explicit *http.Client so tests
// can point the whole stack at an httptest server.
//
// Portions adapted from ToolHive (github.com/stacklok/toolhive), Apache-2.0.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Well-known metadata paths.
const (
	// WellKnownResourcePath is the RFC 9728 protected-resource metadata path.
	WellKnownResourcePath = "/.well-known/oauth-protected-resource"
	// WellKnownASPath is the RFC 8414 authorization-server metadata path.
	WellKnownASPath = "/.well-known/oauth-authorization-server"
	// WellKnownOIDCPath is the OIDC Discovery 1.0 configuration path.
	WellKnownOIDCPath = "/.well-known/openid-configuration"
)

// maxMetadataBytes caps a metadata response. Discovery URLs come from a remote
// server we do not yet trust, so an unbounded read is a free memory-exhaustion
// vector. Real documents are a few kilobytes.
const maxMetadataBytes = 1 << 20

// Challenge is a parsed WWW-Authenticate header.
type Challenge struct {
	// Scheme is the auth scheme as sent, e.g. "Bearer".
	Scheme string
	// Realm is the realm parameter, often the issuer URL.
	Realm string
	// ResourceMetadataURL is the RFC 9728 resource_metadata parameter: the
	// server telling us exactly where its protected-resource metadata lives.
	ResourceMetadataURL string
	// Scope is the space-delimited scope parameter, if present.
	Scope string
	// Error and ErrorDescription carry RFC 6750 error details.
	Error            string
	ErrorDescription string
	// Params holds every parsed parameter, including the ones above.
	Params map[string]string
}

// ParseWWWAuthenticate parses a WWW-Authenticate header value.
//
// Only the token-based schemes matter here: a Basic or Digest challenge from an
// MCP server means the operator configured the wrong auth mode, and reporting
// that plainly beats a vague parse failure.
//
// Portions adapted from ToolHive (github.com/stacklok/toolhive), Apache-2.0.
func ParseWWWAuthenticate(header string) (*Challenge, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, errors.New("oauth: empty WWW-Authenticate header")
	}

	scheme, rest, _ := strings.Cut(header, " ")
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		scheme = "Bearer"
	case strings.EqualFold(scheme, "OAuth"):
		scheme = "OAuth"
	default:
		return nil, fmt.Errorf("oauth: unsupported authentication scheme %q", scheme)
	}

	c := &Challenge{Scheme: scheme, Params: parseAuthParams(rest)}
	c.Realm = c.Params["realm"]
	c.ResourceMetadataURL = c.Params["resource_metadata"]
	c.Scope = c.Params["scope"]
	c.Error = c.Params["error"]
	c.ErrorDescription = c.Params["error_description"]
	return c, nil
}

// parseAuthParams splits a challenge's `name=value` list.
//
// It scans character by character instead of splitting on commas because
// quoted values legitimately contain commas (a scope list, an error
// description) and a naive split truncates them mid-value.
func parseAuthParams(s string) map[string]string {
	params := make(map[string]string)
	i, n := 0, len(s)
	for i < n {
		// Skip separators before the next name.
		for i < n && (s[i] == ',' || s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < n && s[i] != '=' && s[i] != ',' {
			i++
		}
		if i >= n || s[i] != '=' {
			// A bare token (e.g. a base64 credential) carries no name; skip it.
			continue
		}
		name := strings.TrimSpace(s[start:i])
		i++ // consume '='

		var value string
		if i < n && s[i] == '"' {
			i++
			var b strings.Builder
			for i < n {
				if s[i] == '\\' && i+1 < n {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			value = b.String()
		} else {
			start = i
			for i < n && s[i] != ',' {
				i++
			}
			value = strings.TrimSpace(s[start:i])
		}
		if name != "" {
			params[name] = value
		}
	}
	return params
}

// ResourceMetadata is RFC 9728 protected-resource metadata.
type ResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	JWKSURI                string   `json:"jwks_uri,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

// ASMetadata is RFC 8414 authorization-server metadata (a superset of the OIDC
// discovery fields this package needs).
type ASMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	JWKSURI                       string   `json:"jwks_uri,omitempty"`
	UserinfoEndpoint              string   `json:"userinfo_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// SupportsS256 reports whether the server advertises S256 PKCE. A server that
// advertises no methods at all predates RFC 8414's capability fields; we assume
// S256 there rather than refusing to talk to it, since sending a challenge to a
// server that ignores PKCE is harmless.
func (m *ASMetadata) SupportsS256() bool {
	if len(m.CodeChallengeMethodsSupported) == 0 {
		return true
	}
	for _, v := range m.CodeChallengeMethodsSupported {
		if v == "S256" {
			return true
		}
	}
	return false
}

// FetchResourceMetadata retrieves RFC 9728 metadata for a protected resource.
//
// resourceURL may be either the resource itself (whose base and path are turned
// into well-known candidates) or a resource_metadata URL handed to us in a
// WWW-Authenticate challenge, in which case it is tried verbatim first.
//
// Per RFC 9728 §3.1 the path-suffixed form is tried before the root form: a
// host serving several MCP endpoints publishes per-endpoint metadata, and the
// root document (if any) describes something else.
func FetchResourceMetadata(ctx context.Context, resourceURL string, hc *http.Client) (*ResourceMetadata, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("oauth: parse resource url %q: %w", resourceURL, err)
	}
	if err := checkTransportSecurity(u); err != nil {
		return nil, err
	}

	candidates := make([]string, 0, 3)
	if strings.HasPrefix(u.Path, WellKnownResourcePath) {
		candidates = append(candidates, u.String())
	} else {
		base := url.URL{Scheme: u.Scheme, Host: u.Host}
		if p := strings.Trim(u.Path, "/"); p != "" {
			withPath := base
			withPath.Path = WellKnownResourcePath + "/" + p
			candidates = append(candidates, withPath.String())
		}
		root := base
		root.Path = WellKnownResourcePath
		candidates = append(candidates, root.String())
	}

	var lastErr error
	for _, c := range candidates {
		var md ResourceMetadata
		if err := fetchJSON(ctx, hc, c, &md); err != nil {
			lastErr = err
			continue
		}
		if md.Resource == "" && len(md.AuthorizationServers) == 0 {
			lastErr = fmt.Errorf("oauth: %s returned an empty resource metadata document", c)
			continue
		}
		return &md, nil
	}
	return nil, fmt.Errorf("oauth: no protected resource metadata for %s: %w", resourceURL, lastErr)
}

// FetchASMetadata retrieves authorization-server metadata for an issuer.
//
// Candidates, in order: RFC 8414 path-insertion
// ({host}/.well-known/oauth-authorization-server{/path}), then OIDC Discovery
// ({issuer}/.well-known/openid-configuration). The RFC 8414 form comes first
// because an issuer with a path component publishes there, and the OIDC
// suffix form would 404 or — worse — return a different tenant's document.
//
// An issuer mismatch is tolerated: the document's own issuer wins. Real
// deployments host metadata on a different origin than the issuer identifier
// (Stripe being the canonical example), and refusing them would break the
// gateway for no security gain, since every endpoint we then use comes from
// that same document.
func FetchASMetadata(ctx context.Context, issuer string, hc *http.Client) (*ASMetadata, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: parse issuer %q: %w", issuer, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("oauth: issuer %q has no host", issuer)
	}
	if err := checkTransportSecurity(u); err != nil {
		return nil, err
	}

	base := url.URL{Scheme: u.Scheme, Host: u.Host}
	candidates := make([]string, 0, 2)

	rfc8414 := base
	if p := strings.Trim(u.Path, "/"); p != "" {
		rfc8414.Path = WellKnownASPath + "/" + p
	} else {
		rfc8414.Path = WellKnownASPath
	}
	candidates = append(candidates, rfc8414.String())

	oidc := *u
	oidc.Path = strings.TrimSuffix(u.Path, "/") + WellKnownOIDCPath
	oidc.RawQuery, oidc.Fragment = "", ""
	candidates = append(candidates, oidc.String())

	var lastErr error
	for _, c := range candidates {
		var md ASMetadata
		if err := fetchJSON(ctx, hc, c, &md); err != nil {
			lastErr = err
			continue
		}
		if md.TokenEndpoint == "" {
			lastErr = fmt.Errorf("oauth: %s returned metadata without a token_endpoint", c)
			continue
		}
		if md.Issuer == "" {
			md.Issuer = strings.TrimSuffix(issuer, "/")
		}
		return &md, nil
	}
	return nil, fmt.Errorf("oauth: no authorization server metadata for %s: %w", issuer, lastErr)
}

func fetchJSON(ctx context.Context, hc *http.Client, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("oauth: build request for %s: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client(hc).Do(req)
	if err != nil {
		return fmt.Errorf("oauth: fetch %s: %w", rawURL, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMetadataBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth: fetch %s: status %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return fmt.Errorf("oauth: read %s: %w", rawURL, err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("oauth: decode %s: %w", rawURL, err)
	}
	return nil
}

// checkTransportSecurity enforces HTTPS for metadata fetches.
//
// Plain HTTP is allowed only for loopback, which is what local development and
// every httptest server in this package uses; anywhere else it would let a
// network attacker rewrite the endpoints we are about to send credentials to.
func checkTransportSecurity(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && IsLoopback(u.Host) {
		return nil
	}
	return fmt.Errorf("oauth: %s must use https (plain http is allowed only on loopback)", u.Redacted())
}

// IsLoopback reports whether host (optionally "host:port") addresses the local
// machine.
func IsLoopback(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func client(hc *http.Client) *http.Client {
	if hc != nil {
		return hc
	}
	return http.DefaultClient
}
