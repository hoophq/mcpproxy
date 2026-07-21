// Command testmcp runs the testmcp server as a real stdio MCP binary, so
// tests can exercise the full spawn path (`go run ./internal/testmcp/cmd`)
// instead of only in-process pipes.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hoophq/mcpproxy/internal/testmcp"
)

func main() {
	// A line on stderr proves the backend's stderr pump is wired up.
	fmt.Fprintln(os.Stderr, "testmcp: ready")
	if err := testmcp.New().ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "testmcp:", err)
		os.Exit(1)
	}
}
