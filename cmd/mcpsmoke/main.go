// Command mcpsmoke is a scripted MCP client for smoke-testing the gateway:
// it runs initialize → tools/list → tools/call against a streamable-HTTP
// endpoint and prints each exchange.
//
// Usage:
//
//	mcpsmoke -url http://127.0.0.1:8000/mcp -tool echo -args '{"message":"hi"}'
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8000/mcp", "gateway MCP endpoint")
	bearer := flag.String("bearer", "", "bearer token for inbound auth")
	tool := flag.String("tool", "echo", "tool to call")
	args := flag.String("args", `{"message":"hello from mcpsmoke"}`, "tool arguments JSON")
	listOnly := flag.Bool("list-only", false, "stop after tools/list")
	flag.Parse()

	c := &client{url: *url, bearer: *bearer}

	init := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"clientInfo":      map[string]any{"name": "mcpsmoke", "version": "0.1"},
			"capabilities":    map[string]any{},
		},
	}
	resp, err := c.post(init)
	fatal(err, "initialize")
	fmt.Printf("== initialize ==\n%s\n\n", pretty(resp))

	notif := map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
	_, err = c.post(notif)
	fatal(err, "initialized notification")

	list := map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}}
	resp, err = c.post(list)
	fatal(err, "tools/list")
	fmt.Printf("== tools/list ==\n%s\n\n", pretty(resp))

	if *listOnly {
		return
	}

	var argsRaw json.RawMessage
	fatal(json.Unmarshal([]byte(*args), &argsRaw), "parsing -args")
	call := map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": *tool, "arguments": argsRaw},
	}
	resp, err = c.post(call)
	fatal(err, "tools/call")
	fmt.Printf("== tools/call %s ==\n%s\n", *tool, pretty(resp))
}

type client struct {
	url    string
	bearer string
	sid    string
}

func (c *client) post(msg map[string]any) ([]byte, error) {
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sid = sid
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func pretty(b []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return string(b)
	}
	return buf.String()
}

func fatal(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}
