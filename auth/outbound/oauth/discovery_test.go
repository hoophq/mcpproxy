package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		wantScheme  string
		wantRealm   string
		wantMeta    string
		wantErrCode string
		wantErrDesc string
		wantScope   string
		wantErr     bool
	}{
		{
			name:       "bare bearer",
			header:     "Bearer",
			wantScheme: "Bearer",
		},
		{
			name:       "realm only",
			header:     `Bearer realm="https://auth.example.com"`,
			wantScheme: "Bearer",
			wantRealm:  "https://auth.example.com",
		},
		{
			name:       "resource metadata",
			header:     `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`,
			wantScheme: "Bearer",
			wantMeta:   "https://mcp.example.com/.well-known/oauth-protected-resource",
		},
		{
			name:       "realm and resource metadata",
			header:     `Bearer realm="https://auth.example.com", resource_metadata="https://r.example.com/.well-known/oauth-protected-resource"`,
			wantScheme: "Bearer",
			wantRealm:  "https://auth.example.com",
			wantMeta:   "https://r.example.com/.well-known/oauth-protected-resource",
		},
		{
			// Quoted values contain commas of their own; a comma-split parser
			// truncates them.
			name:        "quoted value containing commas",
			header:      `Bearer error="invalid_token", error_description="expired, please re-authenticate", scope="a b c"`,
			wantScheme:  "Bearer",
			wantErrCode: "invalid_token",
			wantErrDesc: "expired, please re-authenticate",
			wantScope:   "a b c",
		},
		{
			name:        "unquoted values",
			header:      `Bearer realm=https://auth.example.com, error=invalid_request`,
			wantScheme:  "Bearer",
			wantRealm:   "https://auth.example.com",
			wantErrCode: "invalid_request",
		},
		{
			name:        "escaped quote inside value",
			header:      `Bearer error_description="failed to parse \"token\", reason"`,
			wantScheme:  "Bearer",
			wantErrDesc: `failed to parse "token", reason`,
		},
		{
			name:       "oauth scheme",
			header:     `OAuth realm="https://auth.example.com"`,
			wantScheme: "OAuth",
			wantRealm:  "https://auth.example.com",
		},
		{
			name:       "scheme case is normalized",
			header:     `bearer realm="https://auth.example.com"`,
			wantScheme: "Bearer",
			wantRealm:  "https://auth.example.com",
		},
		{name: "empty header", header: "", wantErr: true},
		{name: "whitespace only", header: "   ", wantErr: true},
		{name: "basic scheme rejected", header: `Basic realm="x"`, wantErr: true},
		{name: "digest scheme rejected", header: `Digest realm="x"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseWWWAuthenticate(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %+v", tt.header, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
			if got.Realm != tt.wantRealm {
				t.Errorf("realm = %q, want %q", got.Realm, tt.wantRealm)
			}
			if got.ResourceMetadataURL != tt.wantMeta {
				t.Errorf("resource_metadata = %q, want %q", got.ResourceMetadataURL, tt.wantMeta)
			}
			if got.Error != tt.wantErrCode {
				t.Errorf("error = %q, want %q", got.Error, tt.wantErrCode)
			}
			if got.ErrorDescription != tt.wantErrDesc {
				t.Errorf("error_description = %q, want %q", got.ErrorDescription, tt.wantErrDesc)
			}
			if got.Scope != tt.wantScope {
				t.Errorf("scope = %q, want %q", got.Scope, tt.wantScope)
			}
		})
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestFetchResourceMetadata_PathSpecificPreferred(t *testing.T) {
	// A host serving several MCP endpoints publishes per-endpoint metadata.
	// The root document describes something else and must not win.
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case WellKnownResourcePath + "/mcp":
			writeJSON(t, w, ResourceMetadata{
				Resource:             "https://example.com/mcp",
				AuthorizationServers: []string{"https://auth.example.com"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	md, err := FetchResourceMetadata(context.Background(), srv.URL+"/mcp", srv.Client())
	if err != nil {
		t.Fatalf("FetchResourceMetadata: %v", err)
	}
	if md.Resource != "https://example.com/mcp" {
		t.Errorf("resource = %q", md.Resource)
	}
	if paths[0] != WellKnownResourcePath+"/mcp" {
		t.Errorf("first candidate = %q, want the path-specific form", paths[0])
	}
}

func TestFetchResourceMetadata_FallsBackToRoot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownResourcePath {
			writeJSON(t, w, ResourceMetadata{
				Resource:             "https://example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	md, err := FetchResourceMetadata(context.Background(), srv.URL+"/mcp", srv.Client())
	if err != nil {
		t.Fatalf("FetchResourceMetadata: %v", err)
	}
	if len(md.AuthorizationServers) != 1 {
		t.Fatalf("authorization_servers = %v", md.AuthorizationServers)
	}
}

func TestFetchResourceMetadata_AcceptsExplicitWellKnownURL(t *testing.T) {
	// The URL from a WWW-Authenticate resource_metadata param already points at
	// the document, so the fetch must use it verbatim rather than re-derive it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownResourcePath+"/deep/path" {
			t.Errorf("unexpected fetch of %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, ResourceMetadata{Resource: "https://example.com/deep/path"})
	}))
	defer srv.Close()

	md, err := FetchResourceMetadata(context.Background(), srv.URL+WellKnownResourcePath+"/deep/path", srv.Client())
	if err != nil {
		t.Fatalf("FetchResourceMetadata: %v", err)
	}
	if md.Resource != "https://example.com/deep/path" {
		t.Errorf("resource = %q", md.Resource)
	}
}

func TestFetchResourceMetadata_AllCandidates404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := FetchResourceMetadata(context.Background(), srv.URL+"/mcp", srv.Client()); err == nil {
		t.Fatal("expected an error when no metadata document exists")
	}
}

func TestFetchASMetadata_RFC8414First(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == WellKnownASPath {
			writeJSON(t, w, ASMetadata{
				Issuer:                "ISSUER",
				AuthorizationEndpoint: "https://auth.example.com/authorize",
				TokenEndpoint:         "https://auth.example.com/token",
				RegistrationEndpoint:  "https://auth.example.com/register",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	md, err := FetchASMetadata(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("FetchASMetadata: %v", err)
	}
	if md.TokenEndpoint != "https://auth.example.com/token" {
		t.Errorf("token_endpoint = %q", md.TokenEndpoint)
	}
	if md.RegistrationEndpoint != "https://auth.example.com/register" {
		t.Errorf("registration_endpoint = %q", md.RegistrationEndpoint)
	}
	if len(paths) != 1 || paths[0] != WellKnownASPath {
		t.Errorf("fetched %v, want only the RFC 8414 path", paths)
	}
}

func TestFetchASMetadata_PathInsertionForIssuerWithPath(t *testing.T) {
	// RFC 8414 §3.1 inserts the issuer path after the well-known segment.
	// Getting this wrong reaches a different tenant's document.
	want := WellKnownASPath + "/tenant/one"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, ASMetadata{Issuer: "https://as.example.com/tenant/one", TokenEndpoint: "https://as.example.com/t"})
	}))
	defer srv.Close()

	md, err := FetchASMetadata(context.Background(), srv.URL+"/tenant/one", srv.Client())
	if err != nil {
		t.Fatalf("FetchASMetadata: %v", err)
	}
	if md.Issuer != "https://as.example.com/tenant/one" {
		t.Errorf("issuer = %q", md.Issuer)
	}
}

func TestFetchASMetadata_OIDCFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, WellKnownOIDCPath) {
			writeJSON(t, w, ASMetadata{
				Issuer:                "https://oidc.example.com",
				AuthorizationEndpoint: "https://oidc.example.com/authorize",
				TokenEndpoint:         "https://oidc.example.com/token",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	md, err := FetchASMetadata(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("FetchASMetadata: %v", err)
	}
	if md.Issuer != "https://oidc.example.com" {
		t.Errorf("issuer = %q", md.Issuer)
	}
}

func TestFetchASMetadata_TrustsDocumentIssuerOnMismatch(t *testing.T) {
	// Real deployments host metadata on a different origin than the issuer
	// identifier (Stripe). Refusing them would break the gateway for no gain.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownASPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, ASMetadata{
			Issuer:        "https://marketplace.example.com",
			TokenEndpoint: "https://marketplace.example.com/token",
		})
	}))
	defer srv.Close()

	md, err := FetchASMetadata(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("FetchASMetadata: %v", err)
	}
	if md.Issuer != "https://marketplace.example.com" {
		t.Errorf("issuer = %q, want the document's own issuer", md.Issuer)
	}
}

func TestFetchASMetadata_RejectsDocumentWithoutTokenEndpoint(t *testing.T) {
	// A document with no token_endpoint is unusable. Falling through to the
	// next candidate beats returning a half-built config.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownASPath {
			writeJSON(t, w, map[string]string{"issuer": "https://as.example.com"})
			return
		}
		writeJSON(t, w, ASMetadata{Issuer: "https://as.example.com", TokenEndpoint: "https://as.example.com/token"})
	}))
	defer srv.Close()

	md, err := FetchASMetadata(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("FetchASMetadata: %v", err)
	}
	if md.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("token_endpoint = %q, want the OIDC fallback document", md.TokenEndpoint)
	}
}

func TestFetchASMetadata_RequiresHTTPSOffLoopback(t *testing.T) {
	_, err := FetchASMetadata(context.Background(), "http://as.example.com", nil)
	if err == nil {
		t.Fatal("expected plain http off loopback to be refused")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https, got %v", err)
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"localhost", true},
		{"LocalHost:1234", true},
		{"[::1]:9000", true},
		{"::1", true},
		{"example.com", false},
		{"10.0.0.1", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsLoopback(tt.host); got != tt.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestSupportsS256(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    bool
	}{
		{"advertises S256", []string{"plain", "S256"}, true},
		{"plain only", []string{"plain"}, false},
		// No advertisement predates RFC 8414's capability fields, and sending
		// a challenge to a server that ignores PKCE costs nothing.
		{"no advertisement", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := &ASMetadata{CodeChallengeMethodsSupported: tt.methods}
			if got := md.SupportsS256(); got != tt.want {
				t.Errorf("SupportsS256() = %v, want %v", got, tt.want)
			}
		})
	}
}
