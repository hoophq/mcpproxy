package testmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

func handle(t *testing.T, s *Server, raw string) *jsonrpc.Message {
	t.Helper()
	out := s.Handle(context.Background(), []byte(raw))
	if out == nil {
		return nil
	}
	m, err := jsonrpc.Parse(out)
	if err != nil {
		t.Fatalf("parsing response %q: %v", out, err)
	}
	return m
}

func TestInitializeAndInitializedNotification(t *testing.T) {
	s := New()
	resp := handle(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if resp == nil || resp.Error != nil {
		t.Fatalf("initialize failed: %+v", resp)
	}
	var res mcp.InitializeResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("decoding initialize result: %v", err)
	}
	if res.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", res.ProtocolVersion, ProtocolVersion)
	}
	if res.ServerInfo.Name != "testmcp" {
		t.Errorf("serverInfo.name = %q", res.ServerInfo.Name)
	}

	if s.Initialized() {
		t.Fatal("Initialized true before the notification")
	}
	if got := handle(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); got != nil {
		t.Errorf("notification produced a response: %+v", got)
	}
	if !s.Initialized() {
		t.Error("Initialized false after notifications/initialized")
	}
}

func TestToolsListReflectsSetTools(t *testing.T) {
	s := New()
	names := listToolNames(t, s)
	if len(names) != 3 {
		t.Fatalf("default catalog = %v, want 3 tools", names)
	}

	s.SetTools([]mcp.Tool{{Name: "only", Description: "d"}})
	if got := listToolNames(t, s); len(got) != 1 || got[0] != "only" {
		t.Errorf("after SetTools got %v, want [only]", got)
	}
}

func listToolNames(t *testing.T, s *Server) []string {
	t.Helper()
	resp := handle(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp == nil || resp.Error != nil {
		t.Fatalf("tools/list failed: %+v", resp)
	}
	var res mcp.ToolsListResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("decoding tools/list: %v", err)
	}
	var names []string
	for _, raw := range res.Tools {
		var tool mcp.Tool
		if err := json.Unmarshal(raw, &tool); err != nil {
			t.Fatalf("decoding tool entry: %v", err)
		}
		names = append(names, tool.Name)
	}
	return names
}

func TestToolsCall(t *testing.T) {
	s := New()
	tests := []struct {
		name   string
		req    string
		verify func(t *testing.T, text string, isError bool)
	}{
		{
			name: "echo returns arguments verbatim",
			req:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"a":1}}}`,
			verify: func(t *testing.T, text string, isError bool) {
				if isError {
					t.Fatal("echo reported isError")
				}
				if text != `{"a":1}` {
					t.Errorf("echo text = %q", text)
				}
			},
		},
		{
			name: "slow honours ms argument",
			req:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{"ms":1}}}`,
			verify: func(t *testing.T, text string, _ bool) {
				if !strings.HasPrefix(text, "slept ") {
					t.Errorf("slow text = %q", text)
				}
			},
		},
		{
			name: "big returns kb kilobytes",
			req:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"big","arguments":{"kb":3}}}`,
			verify: func(t *testing.T, text string, _ bool) {
				if len(text) != 3*1024 {
					t.Errorf("big len = %d, want %d", len(text), 3*1024)
				}
			},
		},
		{
			name: "unknown tool is a tool error not a protocol error",
			req:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`,
			verify: func(t *testing.T, text string, isError bool) {
				if !isError {
					t.Error("isError = false for unknown tool")
				}
				if !strings.Contains(text, "nope") {
					t.Errorf("text = %q, want the tool name", text)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := handle(t, s, tc.req)
			if resp == nil || resp.Error != nil {
				t.Fatalf("tools/call failed: %+v", resp)
			}
			var res struct {
				Content []mcp.ContentItem `json:"content"`
				IsError bool              `json:"isError"`
			}
			if err := json.Unmarshal(resp.Result, &res); err != nil {
				t.Fatalf("decoding result: %v", err)
			}
			if len(res.Content) != 1 {
				t.Fatalf("content = %v, want 1 item", res.Content)
			}
			tc.verify(t, res.Content[0].Text, res.IsError)
		})
	}
}

func TestUnknownMethodAndClientResponse(t *testing.T) {
	s := New()
	resp := handle(t, s, `{"jsonrpc":"2.0","id":9,"method":"resources/list"}`)
	if resp == nil || resp.Error == nil {
		t.Fatalf("unknown method should error, got %+v", resp)
	}
	if resp.Error.Code != jsonrpc.CodeMethodNotFound {
		t.Errorf("code = %d, want %d", resp.Error.Code, jsonrpc.CodeMethodNotFound)
	}
	// The server must stay quiet when a client answers one of its requests.
	if got := handle(t, s, `{"jsonrpc":"2.0","id":"srv-1","result":{}}`); got != nil {
		t.Errorf("client response drew a reply: %+v", got)
	}
}
