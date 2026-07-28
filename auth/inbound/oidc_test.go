package inbound

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIssuer is a minimal OIDC provider: discovery document, JWKS, and a
// token minter signing with its own RSA key. It puts the OIDC resolver
// through real signature verification rather than a stubbed verifier.
type fakeIssuer struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	jwksHits atomic.Int64
	discHits atomic.Int64
	// discDown makes the discovery endpoint fail, standing in for an IdP outage.
	discDown atomic.Bool
	// jwksDown makes the JWKS endpoint fail once discovery has succeeded.
	jwksDown atomic.Bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	fi := &fakeIssuer{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fi.discHits.Add(1)
		if fi.discDown.Load() {
			http.Error(w, "issuer down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                fi.srv.URL,
			"jwks_uri":                              fi.srv.URL + "/jwks",
			"authorization_endpoint":                fi.srv.URL + "/authorize",
			"token_endpoint":                        fi.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fi.jwksHits.Add(1)
		if fi.jwksDown.Load() {
			http.Error(w, "jwks down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{fi.jwk()}})
	})

	fi.srv = httptest.NewServer(mux)
	t.Cleanup(fi.srv.Close)
	return fi
}

// jwk renders the public key as a JWK. go-jose needs n and e base64url-encoded
// without padding.
func (fi *fakeIssuer) jwk() map[string]any {
	pub := fi.key.Public().(*rsa.PublicKey)
	return map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": fi.kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// mint signs a token with the issuer's key, applying defaults for iss/exp/iat
// so each test only states the claim it cares about.
func (fi *fakeIssuer) mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = fi.srv.URL
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Add(-time.Minute).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = fi.kid
	signed, err := tok.SignedString(fi.key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func TestOIDCValidToken(t *testing.T) {
	fi := newFakeIssuer(t)
	res, err := OIDC(OIDCOptions{
		Issuer:     fi.srv.URL,
		Audience:   "mcpproxy",
		HTTPClient: fi.srv.Client(),
	})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}

	tok := fi.mint(t, jwt.MapClaims{
		"sub":    "user-42",
		"aud":    "mcpproxy",
		"email":  "alice@example.com",
		"groups": []string{"eng", "oncall"},
	})
	id, err := res(req(tok))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.Subject != "user-42" {
		t.Errorf("subject = %q, want user-42", id.Subject)
	}
	if id.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", id.Email)
	}
	// Claims must carry the whole token, beyond the fields the resolver
	// reads: downstream policy checks match on arbitrary claims.
	groups, ok := id.Claims["groups"].([]any)
	if !ok || len(groups) != 2 {
		t.Errorf("groups claim = %#v, want a 2-element list", id.Claims["groups"])
	}
	if id.Claims["iss"] != fi.srv.URL {
		t.Errorf("iss claim = %v, want %q", id.Claims["iss"], fi.srv.URL)
	}
}

func TestOIDCRejections(t *testing.T) {
	fi := newFakeIssuer(t)
	other := newFakeIssuer(t)

	res, err := OIDC(OIDCOptions{
		Issuer:     fi.srv.URL,
		Audience:   "mcpproxy",
		Scopes:     []string{"mcp:invoke"},
		HTTPClient: fi.srv.Client(),
	})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}

	valid := jwt.MapClaims{"sub": "u", "aud": "mcpproxy", "scope": "mcp:invoke mcp:read"}

	cases := []struct {
		name  string
		token string
	}{
		{"expired", fi.mint(t, jwt.MapClaims{
			"sub": "u", "aud": "mcpproxy", "scope": "mcp:invoke",
			"exp": time.Now().Add(-time.Minute).Unix(),
		})},
		{"wrong audience", fi.mint(t, jwt.MapClaims{
			"sub": "u", "aud": "some-other-api", "scope": "mcp:invoke",
		})},
		{"missing required scope", fi.mint(t, jwt.MapClaims{
			"sub": "u", "aud": "mcpproxy", "scope": "mcp:read",
		})},
		{"no scope claim at all", fi.mint(t, jwt.MapClaims{
			"sub": "u", "aud": "mcpproxy",
		})},
		{"signed by another issuer's key", other.mint(t, jwt.MapClaims{
			"sub": "u", "aud": "mcpproxy", "scope": "mcp:invoke", "iss": fi.srv.URL,
		})},
		{"wrong iss claim", fi.mint(t, jwt.MapClaims{
			"sub": "u", "aud": "mcpproxy", "scope": "mcp:invoke", "iss": "https://evil.example",
		})},
		{"not a jwt", "not-a-jwt"},
		{"tampered payload", tamper(fi.mint(t, valid))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := res(req(tc.token)); err == nil {
				t.Fatal("want rejection, got success")
			}
		})
	}

	// The valid control must pass, showing the property under test drives
	// the rejections above rather than a broken fixture.
	t.Run("control token is accepted", func(t *testing.T) {
		if _, err := res(req(fi.mint(t, valid))); err != nil {
			t.Fatalf("control token rejected: %v", err)
		}
	})
}

// tamper flips a character in the JWT payload, invalidating the signature
// while keeping the token structurally parseable.
func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	b := []byte(parts[1])
	if b[0] == 'e' {
		b[0] = 'f'
	} else {
		b[0] = 'e'
	}
	parts[1] = string(b)
	return strings.Join(parts, ".")
}

func TestOIDCEmptyAudienceSkipsCheck(t *testing.T) {
	// With no configured audience, any aud must pass, so an issuer that omits
	// aud stays usable.
	fi := newFakeIssuer(t)
	res, err := OIDC(OIDCOptions{Issuer: fi.srv.URL, HTTPClient: fi.srv.Client()})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	for _, claims := range []jwt.MapClaims{
		{"sub": "u", "aud": "whatever"},
		{"sub": "u"},
	} {
		if _, err := res(req(fi.mint(t, claims))); err != nil {
			t.Errorf("token %v rejected: %v", claims, err)
		}
	}
}

func TestOIDCScopeClaimShapes(t *testing.T) {
	// Issuers disagree on how they encode scopes; every shape seen in the
	// wild must satisfy the same requirement.
	fi := newFakeIssuer(t)
	res, err := OIDC(OIDCOptions{
		Issuer:     fi.srv.URL,
		Scopes:     []string{"mcp:invoke"},
		HTTPClient: fi.srv.Client(),
	})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	cases := []struct {
		name   string
		claims jwt.MapClaims
		ok     bool
	}{
		{"space-delimited scope", jwt.MapClaims{"sub": "u", "scope": "a mcp:invoke b"}, true},
		{"scp array", jwt.MapClaims{"sub": "u", "scp": []string{"a", "mcp:invoke"}}, true},
		{"scp string", jwt.MapClaims{"sub": "u", "scp": "mcp:invoke"}, true},
		{"unrelated scopes", jwt.MapClaims{"sub": "u", "scope": "a b"}, false},
		{"substring is not a scope", jwt.MapClaims{"sub": "u", "scope": "mcp:invoker"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := res(req(fi.mint(t, tc.claims)))
			if tc.ok && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want rejected, got success")
			}
		})
	}
}

func TestOIDCDiscoveryHappensOnceAndRetriesAfterFailure(t *testing.T) {
	fi := newFakeIssuer(t)
	res, err := OIDC(OIDCOptions{Issuer: fi.srv.URL, HTTPClient: fi.srv.Client()})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	if got := fi.discHits.Load(); got != 0 {
		t.Fatalf("discovery ran %d times at construction, want 0", got)
	}

	tok := fi.mint(t, jwt.MapClaims{"sub": "u"})
	for range 3 {
		if _, err := res(req(tok)); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	// A per-request discovery fetch would charge every MCP message an extra
	// round trip to the IdP.
	if got := fi.discHits.Load(); got != 1 {
		t.Errorf("discovery ran %d times across 3 requests, want 1", got)
	}
	// The remote key set caches the JWKS the same way.
	if got := fi.jwksHits.Load(); got > 1 {
		t.Errorf("jwks fetched %d times, want at most 1", got)
	}
}

func TestOIDCFailedDiscoveryIsNotCached(t *testing.T) {
	// An IdP down for a moment must not break the gateway for good: caching a
	// discovery failure would keep rejecting every request until a restart.
	fi := newFakeIssuer(t)
	fi.discDown.Store(true)

	res, err := OIDC(OIDCOptions{Issuer: fi.srv.URL, HTTPClient: fi.srv.Client()})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	tok := fi.mint(t, jwt.MapClaims{"sub": "u"})

	if _, err := res(req(tok)); err == nil {
		t.Fatal("want failure while the issuer is down")
	}
	fi.discDown.Store(false)
	id, err := res(req(tok))
	if err != nil {
		t.Fatalf("resolver did not recover after the issuer came back: %v", err)
	}
	if id.Subject != "u" {
		t.Errorf("subject = %q, want u", id.Subject)
	}
}

func TestOIDCRequiresIssuer(t *testing.T) {
	if _, err := OIDC(OIDCOptions{}); err == nil {
		t.Fatal("want error when issuer is empty")
	}
}

func TestOIDCMissingCredential(t *testing.T) {
	fi := newFakeIssuer(t)
	res, err := OIDC(OIDCOptions{Issuer: fi.srv.URL, HTTPClient: fi.srv.Client()})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	_, err = res(req(""))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error %v does not wrap ErrUnauthenticated", err)
	}
	// No credential means no reason to talk to the IdP.
	if got := fi.discHits.Load(); got != 0 {
		t.Errorf("discovery ran %d times for a credential-less request, want 0", got)
	}
}

func TestOIDCJWKSOutageFailsClosed(t *testing.T) {
	// Discovery succeeds but the key set is unreachable. With no key to check
	// the signature against, the gateway must reject the request instead of
	// admitting it on unverified claims.
	fi := newFakeIssuer(t)
	fi.jwksDown.Store(true)

	res, err := OIDC(OIDCOptions{Issuer: fi.srv.URL, HTTPClient: fi.srv.Client()})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	tok := fi.mint(t, jwt.MapClaims{"sub": "u"})
	if _, err := res(req(tok)); err == nil {
		t.Fatal("want rejection while the JWKS endpoint is down")
	}

	fi.jwksDown.Store(false)
	if _, err := res(req(tok)); err != nil {
		t.Fatalf("resolver did not recover after the JWKS endpoint came back: %v", err)
	}
}

func TestOIDCConcurrentFirstRequests(t *testing.T) {
	// Lazy discovery means the first burst of requests races to initialize
	// the verifier. Exactly one discovery must happen, and every request must
	// still get a correct answer. Run under -race.
	fi := newFakeIssuer(t)
	res, err := OIDC(OIDCOptions{Issuer: fi.srv.URL, HTTPClient: fi.srv.Client()})
	if err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	tok := fi.mint(t, jwt.MapClaims{"sub": "u"})

	const workers = 16
	errs := make(chan error, workers)
	start := make(chan struct{})
	for range workers {
		go func() {
			<-start
			id, err := res(req(tok))
			if err == nil && id.Subject != "u" {
				err = errors.New("wrong subject " + id.Subject)
			}
			errs <- err
		}()
	}
	close(start)
	for range workers {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if got := fi.discHits.Load(); got != 1 {
		t.Errorf("discovery ran %d times for a concurrent first burst, want 1", got)
	}
}
