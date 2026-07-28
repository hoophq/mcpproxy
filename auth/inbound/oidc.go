package inbound

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/hoophq/mcpproxy/inspect"
)

// OIDCOptions configures JWT validation against an OpenID Connect issuer.
type OIDCOptions struct {
	// Issuer is the OIDC issuer URL. Discovery hits
	// <Issuer>/.well-known/openid-configuration.
	Issuer string
	// Audience, when set, must appear in the token's aud claim. Empty skips
	// the check, which fits an issuer dedicated to this gateway; against a
	// shared issuer it accepts any token that issuer mints.
	Audience string
	// Scopes, when set, must all be present in the token's space-delimited
	// scope claim (falling back to the "scp" array some issuers emit).
	Scopes []string
	// HTTPClient overrides the client used for discovery and JWKS fetches.
	// Tests point this at an httptest server; production leaves it nil.
	HTTPClient *http.Client
}

// oidcVerifier lazily builds and caches an *oidc.IDTokenVerifier.
//
// Discovery waits for the first request by design: an IdP that is slow or
// down at daemon startup must not stop the gateway from booting and serving
// its health endpoint. Once discovery succeeds the verifier stays cached for
// the process lifetime; oidc.RemoteKeySet handles JWKS refresh and key
// rotation.
type oidcVerifier struct {
	opts OIDCOptions

	mu  sync.Mutex
	v   *oidc.IDTokenVerifier
	ctx context.Context
}

// get returns the cached verifier, running discovery once if needed.
//
// A failed discovery stays out of the cache: the IdP may have been
// restarting, and a retry on the next request lets the gateway recover
// without an operator bouncing it.
func (o *oidcVerifier) get(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.v != nil {
		return o.v, nil
	}

	// The key set outlives this request, so it must not hold the request's
	// context: cancelling one request would poison JWKS refreshes for every
	// later request. o.ctx carries the HTTP client override and nothing else.
	discoverCtx := o.ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		discoverCtx, cancel = context.WithDeadline(o.ctx, deadline)
		defer cancel()
	}

	provider, err := oidc.NewProvider(discoverCtx, o.opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("inbound oidc: discovery for issuer %q: %w", o.opts.Issuer, err)
	}
	o.v = provider.VerifierContext(o.ctx, &oidc.Config{
		ClientID:          o.opts.Audience,
		SkipClientIDCheck: o.opts.Audience == "",
	})
	return o.v, nil
}

// OIDC validates a bearer JWT against an OIDC issuer's published keys.
func OIDC(opts OIDCOptions) (Resolver, error) {
	if opts.Issuer == "" {
		return nil, fmt.Errorf("inbound oidc: issuer is required")
	}

	base := context.Background()
	if opts.HTTPClient != nil {
		base = oidc.ClientContext(base, opts.HTTPClient)
	}
	ov := &oidcVerifier{opts: opts, ctx: base}

	// Copy the required scopes so a caller mutating the config slice after
	// construction cannot change the policy this resolver enforces.
	required := append([]string(nil), opts.Scopes...)

	return func(r *http.Request) (inspect.Identity, error) {
		raw, err := bearerToken(r)
		if err != nil {
			return inspect.Identity{}, err
		}
		verifier, err := ov.get(r.Context())
		if err != nil {
			return inspect.Identity{}, err
		}
		tok, err := verifier.Verify(r.Context(), raw)
		if err != nil {
			return inspect.Identity{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
		}

		claims := map[string]any{}
		if err := tok.Claims(&claims); err != nil {
			return inspect.Identity{}, fmt.Errorf("inbound oidc: decoding claims: %w", err)
		}
		if err := requireScopes(claims, required); err != nil {
			return inspect.Identity{}, err
		}

		email, _ := claims["email"].(string)
		return inspect.Identity{
			Subject: tok.Subject,
			Email:   email,
			Claims:  claims,
		}, nil
	}, nil
}

// requireScopes checks that the token grants every scope in want.
func requireScopes(claims map[string]any, want []string) error {
	if len(want) == 0 {
		return nil
	}
	granted := tokenScopes(claims)
	for _, s := range want {
		if _, ok := granted[s]; !ok {
			return fmt.Errorf("%w: token is missing required scope %q", ErrUnauthenticated, s)
		}
	}
	return nil
}

// tokenScopes reads the granted scopes from the two shapes issuers emit: RFC
// 8693's space-delimited "scope" string, and Azure AD's "scp", which arrives
// as either a string or an array.
func tokenScopes(claims map[string]any) map[string]struct{} {
	out := make(map[string]struct{})
	add := func(v any) {
		switch t := v.(type) {
		case string:
			for _, s := range strings.Fields(t) {
				out[s] = struct{}{}
			}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					out[s] = struct{}{}
				}
			}
		}
	}
	add(claims["scope"])
	add(claims["scp"])
	return out
}
