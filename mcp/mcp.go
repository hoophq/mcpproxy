// Package mcp holds the minimal MCP protocol vocabulary the gateway
// inspects. Anything not modeled here passes through opaquely.
package mcp

import "encoding/json"

// Method names the gateway dispatches on.
const (
	MethodInitialize            = "initialize"
	MethodInitialized           = "notifications/initialized"
	MethodToolsList             = "tools/list"
	MethodToolsCall             = "tools/call"
	MethodToolsListChanged      = "notifications/tools/list_changed"
	MethodResourcesList         = "resources/list"
	MethodResourcesRead         = "resources/read"
	MethodPromptsList           = "prompts/list"
	MethodPromptsGet            = "prompts/get"
	MethodSamplingCreateMessage = "sampling/createMessage"
	MethodElicitationCreate     = "elicitation/create"
	MethodPing                  = "ping"
	MethodLoggingMessage        = "notifications/message"
	MethodProgress              = "notifications/progress"
)

// InitializeParams is the client's initialize request payload (subset).
type InitializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	ClientInfo      Implementation `json:"clientInfo"`
}

// InitializeResult is the server's initialize response payload (subset).
type InitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	ServerInfo      Implementation  `json:"serverInfo"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	Instructions    string          `json:"instructions,omitempty"`
}

// Implementation identifies a client or server.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool is a tool descriptor from tools/list (subset; extra fields preserved
// by keeping the raw entry alongside).
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// ToolsListResult is the tools/list response payload.
type ToolsListResult struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// ToolsCallParams is the tools/call request payload.
type ToolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ContentItem is one entry of a tool result's content array. Only text
// content is redacted; other kinds pass through.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
