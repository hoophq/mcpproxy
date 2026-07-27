// Command configcheck validates mcpproxyd configuration files without
// starting the daemon: YAML syntax, ${ENV} expansion, and structural
// invariants (config.Validate). Exit status 1 if any file fails.
//
// Usage:
//
//	configcheck config.yaml [more.yaml ...]
package main

import (
	"fmt"
	"os"

	"github.com/hoophq/mcpproxy/config"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: configcheck <config.yaml> [...]")
		os.Exit(2)
	}
	bad := 0
	for _, p := range os.Args[1:] {
		if _, err := config.Load(p); err != nil {
			fmt.Printf("FAIL %s: %v\n", p, err)
			bad++
		} else {
			fmt.Printf("ok   %s\n", p)
		}
	}
	if bad > 0 {
		os.Exit(1)
	}
}
