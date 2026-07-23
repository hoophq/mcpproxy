package inbound

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWellKnownHandlerServesRFC9728Metadata(t *testing.T) {
	const (
		resource = "https://gateway.example/mcp"
		as       = "https://gateway.example/oauth"
	)
	h := WellKnownHandler(resource, as)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, WellKnownPath, nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var got struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body %q: %v", rr.Body.String(), err)
	}
	if got.Resource != resource {
		t.Errorf("resource = %q, want %q", got.Resource, resource)
	}
	// A client that cannot find the authorization server here has no way to
	// start the OAuth flow, which is the entire point of the endpoint.
	if len(got.AuthorizationServers) != 1 || got.AuthorizationServers[0] != as {
		t.Errorf("authorization_servers = %v, want [%q]", got.AuthorizationServers, as)
	}
}

func TestWellKnownHandlerAcceptsResourceSuffixedPaths(t *testing.T) {
	// RFC 9728 §3.1 lets a client append the resource path, so a gateway
	// serving /mcp will be asked for .../oauth-protected-resource/mcp. All of
	// them describe the same resource.
	h := WellKnownHandler("https://gateway.example/mcp", "https://gateway.example/oauth")
	for _, path := range []string{
		WellKnownPath,
		WellKnownPath + "/mcp",
		WellKnownPath + "/deep/nested/path",
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, rr.Code)
		}
	}
}

func TestWellKnownHandlerRejectsOtherPaths(t *testing.T) {
	h := WellKnownHandler("https://gateway.example/mcp", "https://gateway.example/oauth")
	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resourceX",
		"/mcp",
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404", path, rr.Code)
		}
		// OAuth discovery clients parse the error body as JSON; an HTML error
		// page breaks their error handling.
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("GET %s: content-type = %q, want application/json", path, ct)
		}
	}
}

func TestWellKnownHandlerMethods(t *testing.T) {
	h := WellKnownHandler("https://gateway.example/mcp", "https://gateway.example/oauth")

	t.Run("HEAD returns headers without a body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodHead, WellKnownPath, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if rr.Body.Len() != 0 {
			t.Errorf("HEAD returned a %d-byte body, want none", rr.Body.Len())
		}
	})

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(m+" is rejected", func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(m, WellKnownPath, nil))
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", rr.Code)
			}
			if allow := rr.Header().Get("Allow"); allow == "" {
				t.Error("405 response carries no Allow header")
			}
		})
	}
}

func TestWellKnownHandlerNeedsNoCredential(t *testing.T) {
	// Requiring a token to learn how to obtain a token is a deadlock: an
	// unauthenticated client must be able to read this document.
	h := WellKnownHandler("https://gateway.example/mcp", "https://gateway.example/oauth")
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, WellKnownPath, nil)
	// No Authorization header at all.
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestWellKnownHandlerMountsUnderServeMux(t *testing.T) {
	// The handler is meant to be registered as a prefix route; this proves the
	// intended wiring works end to end rather than only under direct calls.
	mux := http.NewServeMux()
	mux.Handle(WellKnownPath, WellKnownHandler("https://gw/mcp", "https://gw/oauth"))
	mux.Handle(WellKnownPath+"/", WellKnownHandler("https://gw/mcp", "https://gw/oauth"))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{WellKnownPath, WellKnownPath + "/mcp"} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body := make(map[string]any)
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, resp.StatusCode)
		}
		if body["resource"] != "https://gw/mcp" {
			t.Errorf("GET %s: resource = %v", path, body["resource"])
		}
	}
}
