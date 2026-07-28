// Package catalog ships a built-in list of publicly hosted remote MCP
// servers and converts entries into gateway backend configurations.
//
// The data lives in catalog.yaml, embedded at build time. Operators can also
// load their own catalog file with the same schema, so an organization can
// curate an internal server list without forking the code.
package catalog

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hoophq/mcpproxy/config"
)

//go:embed catalog.yaml
var builtinYAML []byte

// Entry describes one remote MCP server.
type Entry struct {
	Description string `yaml:"description"`
	URL         string `yaml:"url"`
	Transport   string `yaml:"transport"`        // streamable-http | sse
	Auth        string `yaml:"auth"`             // none | static | oauth
	Header      string `yaml:"header,omitempty"` // static: "Name: value template"
	Notes       string `yaml:"notes,omitempty"`
}

// Catalog is a named set of entries.
type Catalog struct {
	Servers map[string]Entry `yaml:"servers"`
}

// Builtin returns the embedded catalog. Tests validate the embedded data, so
// a failure here means a broken build rather than bad user input.
func Builtin() (*Catalog, error) {
	return parse(builtinYAML)
}

// LoadFile reads a catalog with the same schema from disk.
func LoadFile(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

func parse(b []byte) (*Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parsing catalog: %w", err)
	}
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("catalog has no servers")
	}
	for name, e := range c.Servers {
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("catalog entry %q: %w", name, err)
		}
	}
	return &c, nil
}

func (e Entry) validate() error {
	if e.URL == "" {
		return fmt.Errorf("url is required")
	}
	switch e.Transport {
	case "streamable-http", "sse":
	default:
		return fmt.Errorf("unknown transport %q", e.Transport)
	}
	switch e.Auth {
	case "none", "static", "oauth":
	default:
		return fmt.Errorf("unknown auth %q", e.Auth)
	}
	if e.Auth == "static" && !strings.Contains(e.Header, ":") {
		return fmt.Errorf(`auth "static" requires header as "Name: value"`)
	}
	return nil
}

// Names returns entry names, sorted.
func (c *Catalog) Names() []string {
	names := make([]string, 0, len(c.Servers))
	for n := range c.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Backend converts an entry into a gateway backend configuration.
// Static-auth entries carry their header template verbatim; ${ENV}
// placeholders resolve when the daemon loads the final config.
func (e Entry) Backend() config.Backend {
	b := config.Backend{
		Transport: e.Transport,
		URL:       e.URL,
		Auth:      e.Auth,
	}
	if e.Auth == "static" && e.Header != "" {
		name, value, _ := strings.Cut(e.Header, ":")
		b.Headers = map[string]string{
			strings.TrimSpace(name): strings.TrimSpace(value),
		}
	}
	return b
}
