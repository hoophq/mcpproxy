// Command import-catalog generates mcpproxyd backend configuration from a
// catalog of remote MCP servers.
//
// Sources, in order of precedence:
//
//	(default)        the catalog built into mcpproxy (catalog package)
//	-catalog <file>  a custom YAML catalog with the same schema
//	-dir <dir>       a directory tree of MCP-registry server.json files
//	                 (the upstream MCP ServerJSON schema)
//
// Examples:
//
//	import-catalog -list                       # show the built-in catalog
//	import-catalog linear notion stripe        # emit config for these
//	import-catalog -all > backends.yaml        # emit everything
//	import-catalog -catalog internal.yaml -all # custom catalog
//	import-catalog -dir path/to/registry/servers linear
//
// The output is a reviewable fragment: listen + inbound scaffold plus one
// backend stanza per server. Static-auth entries reference ${ENV}
// placeholders so secrets stay out of the file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hoophq/mcpproxy/catalog"
)

// item is one emittable backend, normalized from either source.
type item struct {
	Name        string
	Description string
	Transport   string
	URL         string
	Auth        string // none | static | oauth
	Header      string // static: "Name: value template"
	Notes       string
}

func main() {
	dir := flag.String("dir", "", "scan a directory tree of MCP-registry server.json files instead of the built-in catalog")
	catFile := flag.String("catalog", "", "load a custom YAML catalog instead of the built-in one")
	all := flag.Bool("all", false, "emit every entry instead of the named ones")
	list := flag.Bool("list", false, "list available entries and exit")
	flag.Parse()

	items, err := load(*dir, *catFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *list {
		for _, it := range items {
			fmt.Printf("%-18s %-16s auth=%-7s %s\n", it.Name, it.Transport, it.Auth, it.Description)
		}
		return
	}

	selected := items
	if !*all {
		names := flag.Args()
		if len(names) == 0 {
			fmt.Fprintln(os.Stderr, "no server names given (or use -all / -list)")
			os.Exit(2)
		}
		want := map[string]bool{}
		for _, n := range names {
			want[strings.ToLower(n)] = true
		}
		selected = nil
		for _, it := range items {
			base := strings.TrimSuffix(it.Name, "-remote")
			if want[strings.ToLower(it.Name)] || want[strings.ToLower(base)] {
				selected = append(selected, it)
			}
		}
		if len(selected) == 0 {
			fmt.Fprintln(os.Stderr, "no matching entries; try -list")
			os.Exit(1)
		}
	}

	emit(os.Stdout, selected)
}

// load resolves the source selection into a normalized, sorted item list.
func load(dir, catFile string) ([]item, error) {
	switch {
	case dir != "" && catFile != "":
		return nil, fmt.Errorf("-dir and -catalog are mutually exclusive")
	case dir != "":
		return scanServerJSON(dir)
	case catFile != "":
		c, err := catalog.LoadFile(catFile)
		if err != nil {
			return nil, err
		}
		return fromCatalog(c), nil
	default:
		c, err := catalog.Builtin()
		if err != nil {
			return nil, err
		}
		return fromCatalog(c), nil
	}
}

func fromCatalog(c *catalog.Catalog) []item {
	items := make([]item, 0, len(c.Servers))
	for _, name := range c.Names() {
		e := c.Servers[name]
		items = append(items, item{
			Name:        name,
			Description: e.Description,
			Transport:   e.Transport,
			URL:         e.URL,
			Auth:        e.Auth,
			Header:      e.Header,
			Notes:       e.Notes,
		})
	}
	return items
}

// serverJSON is the subset of the upstream ServerJSON schema we consume.
type serverJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Remotes     []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"remotes"`
	Meta map[string]json.RawMessage `json:"_meta"`
}

// scanServerJSON walks dir for server.json files and extracts remote
// entries. The schema has no machine-readable auth field, so auth is a
// heuristic: "oauth" anywhere in publisher metadata selects oauth,
// otherwise none (the operator upgrades to static after the first 401).
func scanServerJSON(dir string) ([]item, error) {
	var out []item
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "server.json" {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var sj serverJSON
		if err := json.Unmarshal(raw, &sj); err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
			return nil
		}
		if len(sj.Remotes) == 0 {
			return nil
		}
		short := sj.Name
		if i := strings.LastIndexByte(short, '/'); i >= 0 {
			short = short[i+1:]
		}
		meta, _ := json.Marshal(sj.Meta)
		auth := "none"
		if strings.Contains(strings.ToLower(string(meta)), "oauth") {
			auth = "oauth"
		}
		for _, r := range sj.Remotes {
			if r.Type != "sse" && r.Type != "streamable-http" {
				fmt.Fprintf(os.Stderr, "skipping %s: unsupported remote type %q\n", short, r.Type)
				continue
			}
			out = append(out, item{
				Name:        short,
				Description: sj.Description,
				Transport:   r.Type,
				URL:         r.URL,
				Auth:        auth,
			})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// emit writes a reviewable config fragment.
func emit(w *os.File, items []item) {
	fmt.Fprintln(w, "# Generated by import-catalog — review before use.")
	fmt.Fprintln(w, "listen: 127.0.0.1:8000")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "inbound:")
	fmt.Fprintln(w, "  mode: anonymous   # set a real mode before exposing beyond localhost")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "backends:")
	for _, it := range items {
		name := sanitize(it.Name)
		if it.Description != "" {
			fmt.Fprintf(w, "  # %s\n", it.Description)
		}
		if it.Notes != "" {
			fmt.Fprintf(w, "  # NOTE: %s\n", it.Notes)
		}
		fmt.Fprintf(w, "  %s:\n", name)
		fmt.Fprintf(w, "    transport: %s\n", it.Transport)
		fmt.Fprintf(w, "    url: %s\n", it.URL)
		switch it.Auth {
		case "oauth":
			fmt.Fprintf(w, "    auth: oauth   # discovery + DCR + PKCE on first use\n")
		case "static":
			fmt.Fprintf(w, "    auth: static\n")
			fmt.Fprintf(w, "    headers:\n")
			if hname, hval, ok := strings.Cut(it.Header, ":"); ok {
				fmt.Fprintf(w, "      %s: %s\n", strings.TrimSpace(hname), strings.TrimSpace(hval))
			} else {
				fmt.Fprintf(w, "      Authorization: Bearer ${%s_TOKEN}\n", strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
			}
		default:
			fmt.Fprintf(w, "    auth: none    # if the provider needs an API key:\n")
			fmt.Fprintf(w, "    # auth: static\n")
			fmt.Fprintf(w, "    # headers:\n")
			fmt.Fprintf(w, "    #   Authorization: Bearer ${%s_TOKEN}\n", strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
		}
		fmt.Fprintln(w, "")
	}
}

// sanitize makes a catalog name a valid backend key (it becomes a tool
// prefix under aggregation, so keep it short and word-like).
func sanitize(name string) string {
	name = strings.TrimSuffix(name, "-remote")
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, name)
}
