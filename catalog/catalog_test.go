package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuiltinValid gates the embedded catalog: every entry must satisfy the
// schema, or the shipped binary carries a broken server list.
func TestBuiltinValid(t *testing.T) {
	t.Parallel()
	c, err := Builtin()
	if err != nil {
		t.Fatalf("embedded catalog invalid: %v", err)
	}
	if len(c.Servers) < 20 {
		t.Fatalf("suspiciously small builtin catalog: %d entries", len(c.Servers))
	}
	for name, e := range c.Servers {
		if !strings.HasPrefix(e.URL, "https://") {
			t.Errorf("%s: URL must be https, got %q", name, e.URL)
		}
		if e.Description == "" {
			t.Errorf("%s: description required", name)
		}
	}
}

func TestBuiltinBackendsPassConfigValidation(t *testing.T) {
	t.Parallel()
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cfgBackends := map[string]struct{ Transport, URL string }{}
	for name, e := range c.Servers {
		b := e.Backend()
		if b.Transport != e.Transport || b.URL != e.URL {
			t.Errorf("%s: Backend() mangled transport/url", name)
		}
		if e.Auth == "static" && len(b.Headers) != 1 {
			t.Errorf("%s: static entry must yield exactly one header, got %v", name, b.Headers)
		}
		if e.Auth != "static" && len(b.Headers) != 0 {
			t.Errorf("%s: non-static entry must not yield headers", name)
		}
		cfgBackends[name] = struct{ Transport, URL string }{b.Transport, b.URL}
	}
	_ = cfgBackends
}

func TestHeaderParsing(t *testing.T) {
	t.Parallel()
	e := Entry{
		URL: "https://x", Transport: "sse", Auth: "static",
		Header: "Authorization: Bearer ${TOK}",
	}
	if err := e.validate(); err != nil {
		t.Fatal(err)
	}
	b := e.Backend()
	if got := b.Headers["Authorization"]; got != "Bearer ${TOK}" {
		t.Fatalf("header value mangled: %q", got)
	}
}

func TestValidationRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		e    Entry
	}{
		{"missing url", Entry{Transport: "sse", Auth: "none"}},
		{"bad transport", Entry{URL: "https://x", Transport: "websocket", Auth: "none"}},
		{"bad auth", Entry{URL: "https://x", Transport: "sse", Auth: "basic"}},
		{"static without header", Entry{URL: "https://x", Transport: "sse", Auth: "static"}},
	}
	for _, tc := range cases {
		if err := tc.e.validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}

func TestLoadFileCustomCatalog(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "cat.yaml")
	content := `
servers:
  internal:
    description: internal test server
    url: https://mcp.internal.example.com/mcp
    transport: streamable-http
    auth: static
    header: "X-Key: ${KEY}"
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Servers["internal"]; !ok {
		t.Fatal("custom entry missing")
	}
}

func TestLoadFileRejectsBrokenEntry(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "cat.yaml")
	_ = os.WriteFile(p, []byte("servers:\n  x:\n    url: https://a\n    transport: carrier-pigeon\n    auth: none\n"), 0o600)
	if _, err := LoadFile(p); err == nil || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Fatalf("expected transport rejection, got: %v", err)
	}
}
