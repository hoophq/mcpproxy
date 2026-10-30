// Package testmcp is a minimal, controllable MCP server for tests. The same
// Server serves either transport:
//
//	srv := testmcp.New()
//	hs := httptest.NewServer(srv.HTTPHandler()) // streamable-http
//	go srv.ServeStdio(clientOut, clientIn)      // newline-delimited stdio
//
// It implements initialize, notifications/initialized, tools/list and
// tools/call over three built-in tools (echo, slow, big). Your test drives
// server-initiated traffic with SetTools plus NotifyToolsChanged for
// rug-pull scenarios, or RequestSampling for a server→client request.
package testmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// ProtocolVersion is the version this server reports from initialize.
const ProtocolVersion = "2025-06-18"

// Built-in tool names. The default catalog carries all three.
const (
	// ToolEcho returns its arguments as JSON text content.
	ToolEcho = "echo"
	// ToolSlow sleeps for arguments.ms milliseconds (default 50) before
	// answering. Use it to exercise timeouts and cancellation.
	ToolSlow = "slow"
	// ToolBig returns arguments.kb kilobytes of filler text (default 1).
	// Use it to exercise large-frame handling.
	ToolBig = "big"
	// ToolChatty sends arguments.count (default 10) notifications/message
	// log notifications on the response stream, then answers. Use it to
	// exercise server-to-client traffic related to one request.
	ToolChatty = "chatty"
)

// Server is a scriptable MCP server. The zero value is not usable; call New.
// All exported methods are safe for concurrent use.
type Server struct {
	// Name goes out as serverInfo.name.
	Name string

	mu          sync.Mutex
	tools       []mcp.Tool
	initialized bool
	nextID      int
	sse         bool   // POST responses framed as text/event-stream
	session     string // Mcp-Session-Id, assigned on the first exchange

	// out fans server-initiated messages to whichever transport is live.
	// The buffer lets a test queue notifications before a client attaches.
	out chan []byte
}

// New builds a server with the default catalog (echo, slow, big).
func New() *Server {
	return &Server{
		Name:  "testmcp",
		tools: DefaultTools(),
		out:   make(chan []byte, 64),
	}
}

// DefaultTools returns the built-in catalog as a fresh slice, so callers can
// amend it before handing it to SetTools.
func DefaultTools() []mcp.Tool {
	return []mcp.Tool{
		{
			Name:        ToolEcho,
			Description: "Echo the arguments back as text.",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":true}`),
		},
		{
			Name:        ToolSlow,
			Description: "Sleep for `ms` milliseconds, then answer.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"ms":{"type":"integer"}}}`),
		},
		{
			Name:        ToolBig,
			Description: "Return `kb` kilobytes of filler text.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"kb":{"type":"integer"}}}`),
		},
		{
			Name:        ToolChatty,
			Description: "Send `count` log notifications, then answer.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"}}}`),
		},
	}
}

// SetTools replaces the advertised catalog. It does not notify clients; call
// NotifyToolsChanged for that. Swap a tool's description between two
// tools/list calls to exercise rug-pull detection.
func (s *Server) SetTools(tools []mcp.Tool) {
	cp := make([]mcp.Tool, len(tools))
	copy(cp, tools)
	s.mu.Lock()
	s.tools = cp
	s.mu.Unlock()
}

// Tools returns a copy of the current catalog.
func (s *Server) Tools() []mcp.Tool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]mcp.Tool, len(s.tools))
	copy(cp, s.tools)
	return cp
}

// Initialized reports whether the client sent notifications/initialized.
func (s *Server) Initialized() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialized
}

// NotifyToolsChanged emits notifications/tools/list_changed to the client.
func (s *Server) NotifyToolsChanged() {
	s.emit(&jsonrpc.Message{JSONRPC: "2.0", Method: mcp.MethodToolsListChanged})
}

// Notify emits an arbitrary server-initiated notification.
func (s *Server) Notify(method string, params any) {
	s.emit(&jsonrpc.Message{JSONRPC: "2.0", Method: method, Params: mustJSON(params)})
}

// RequestSampling emits a server-initiated sampling/createMessage request
// carrying prompt as the sole user message, and returns the request id so the
// test can match the client's response. The server drops the reply; use this
// to exercise the gateway's S2C request path.
func (s *Server) RequestSampling(prompt string) jsonrpc.ID {
	s.mu.Lock()
	s.nextID++
	id := jsonrpc.ID{Raw: json.RawMessage(`"srv-` + strconv.Itoa(s.nextID) + `"`)}
	s.mu.Unlock()
	s.emit(&jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      id,
		Method:  mcp.MethodSamplingCreateMessage,
		Params: mustJSON(map[string]any{
			"maxTokens": 64,
			"messages": []map[string]any{{
				"role":    "user",
				"content": map[string]string{"type": "text", "text": prompt},
			}},
		}),
	})
	return id
}

// emit queues a server-initiated message and drops it when the queue is full
// with no transport draining. Assert on what arrives if delivery matters.
func (s *Server) emit(m *jsonrpc.Message) {
	b, err := m.Marshal()
	if err != nil {
		return
	}
	select {
	case s.out <- b:
	default:
	}
}

// Handle processes one client message and returns the response, or nil for a
// notification. Both transports call it. Messages a tool sends while it runs
// go to the GET queue.
func (s *Server) Handle(ctx context.Context, raw []byte) []byte {
	return s.HandleStream(ctx, raw, s.emit)
}

// HandleStream is Handle with the messages a tool sends while it runs handed
// to related, so a transport can put them on the response stream.
func (s *Server) HandleStream(ctx context.Context, raw []byte, related func(*jsonrpc.Message)) []byte {
	env, err := jsonrpc.Parse(raw)
	if err != nil {
		return marshal(jsonrpc.NewError(jsonrpc.ID{}, jsonrpc.CodeParseError, err.Error()))
	}
	if env.IsResponse() {
		return nil // a client answering one of our server-initiated requests
	}
	resp := s.dispatch(ctx, env, related)
	if resp == nil {
		return nil
	}
	return marshal(resp)
}

func (s *Server) dispatch(ctx context.Context, env *jsonrpc.Message, related func(*jsonrpc.Message)) *jsonrpc.Message {
	switch env.Method {
	case mcp.MethodInitialize:
		res, err := jsonrpc.NewResult(env.ID, mcp.InitializeResult{
			ProtocolVersion: ProtocolVersion,
			ServerInfo:      mcp.Implementation{Name: s.Name, Version: "0.0.1"},
			Capabilities:    json.RawMessage(`{"tools":{"listChanged":true}}`),
		})
		if err != nil {
			return jsonrpc.NewError(env.ID, jsonrpc.CodeInternalError, err.Error())
		}
		return res

	case mcp.MethodInitialized:
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
		return nil

	case mcp.MethodPing:
		res, _ := jsonrpc.NewResult(env.ID, struct{}{})
		return res

	case mcp.MethodToolsList:
		tools := s.Tools()
		raw := make([]json.RawMessage, 0, len(tools))
		for _, t := range tools {
			raw = append(raw, mustJSON(t))
		}
		res, err := jsonrpc.NewResult(env.ID, mcp.ToolsListResult{Tools: raw})
		if err != nil {
			return jsonrpc.NewError(env.ID, jsonrpc.CodeInternalError, err.Error())
		}
		return res

	case mcp.MethodToolsCall:
		return s.callTool(ctx, env, related)

	default:
		if env.IsNotification() {
			return nil
		}
		return jsonrpc.NewError(env.ID, jsonrpc.CodeMethodNotFound, "unknown method "+env.Method)
	}
}

func (s *Server) callTool(ctx context.Context, env *jsonrpc.Message, related func(*jsonrpc.Message)) *jsonrpc.Message {
	var p mcp.ToolsCallParams
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &p); err != nil {
			return jsonrpc.NewError(env.ID, jsonrpc.CodeInvalidRequest, "bad params: "+err.Error())
		}
	}
	var text string
	switch p.Name {
	case ToolEcho:
		if len(p.Arguments) == 0 {
			text = "{}"
		} else {
			text = string(p.Arguments)
		}

	case ToolSlow:
		d := time.Duration(argInt(p.Arguments, "ms", 50)) * time.Millisecond
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return jsonrpc.NewError(env.ID, jsonrpc.CodeInternalError, ctx.Err().Error())
		}
		text = "slept " + d.String()

	case ToolBig:
		kb := argInt(p.Arguments, "kb", 1)
		if kb < 0 {
			kb = 0
		}
		text = strings.Repeat("x", kb*1024)

	case ToolChatty:
		n := argInt(p.Arguments, "count", 10)
		for i := range n {
			related(&jsonrpc.Message{JSONRPC: "2.0", Method: "notifications/message",
				Params: mustJSON(map[string]any{"level": "info", "data": fmt.Sprintf("chatter %d", i+1)})})
		}
		text = fmt.Sprintf("chattered %d", n)

	default:
		// MCP spells an unknown tool as a tool error in the result
		// payload, so the caller reads isError instead of a
		// JSON-RPC error frame.
		res, _ := jsonrpc.NewResult(env.ID, map[string]any{
			"content": []mcp.ContentItem{{Type: "text", Text: "unknown tool " + p.Name}},
			"isError": true,
		})
		return res
	}
	res, err := jsonrpc.NewResult(env.ID, map[string]any{
		"content": []mcp.ContentItem{{Type: "text", Text: text}},
	})
	if err != nil {
		return jsonrpc.NewError(env.ID, jsonrpc.CodeInternalError, err.Error())
	}
	return res
}

// ServeStdio reads newline-delimited JSON-RPC from in and writes responses
// (plus any server-initiated messages) to out. It returns when in reaches EOF
// or the caller cancels ctx. The same loop backs an in-process io.Pipe and a
// real stdio binary's main.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wmu sync.Mutex
	writeLine := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		if _, err := out.Write(append(bytes.TrimRight(b, "\r\n"), '\n')); err != nil {
			return err
		}
		if f, ok := out.(interface{ Flush() error }); ok {
			return f.Flush()
		}
		return nil
	}

	var pump sync.WaitGroup
	pump.Add(1)
	go func() {
		defer pump.Done()
		for {
			select {
			case b := <-s.out:
				if writeLine(b) != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		req := make([]byte, len(line))
		copy(req, line)
		if resp := s.Handle(ctx, req); resp != nil {
			if err := writeLine(resp); err != nil {
				cancel()
				pump.Wait()
				return err
			}
		}
	}
	cancel()
	pump.Wait()
	return sc.Err()
}

// HTTPHandler serves the streamable-HTTP transport: POST carries one client
// message, GET opens the SSE stream of server-initiated traffic, DELETE ends
// the session. It answers POSTs with application/json until SSEResponses
// switches the framing.
func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serve)
	return mux
}

// SSEResponses frames POST responses as a text/event-stream carrying one
// event, instead of application/json. Streamable-HTTP permits both shapes,
// so a client has to handle each.
func (s *Server) SSEResponses(on bool) {
	s.mu.Lock()
	s.sse = on
	s.mu.Unlock()
}

func (s *Server) sseResponses() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sse
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.servePost(w, r)
	case http.MethodGet:
		s.serveSSE(w, r)
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) servePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Assign a session id on the first exchange, as a real server does.
	w.Header().Set("Mcp-Session-Id", s.sessionID())

	if s.sseResponses() {
		started := false
		event := func(b []byte) {
			if !started {
				started = true
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		resp := s.HandleStream(r.Context(), bytes.TrimSpace(body), func(m *jsonrpc.Message) {
			if b, err := m.Marshal(); err == nil {
				event(b)
			}
		})
		switch {
		case resp != nil:
			event(resp)
		case !started:
			w.WriteHeader(http.StatusAccepted)
		}
		return
	}
	resp := s.Handle(r.Context(), bytes.TrimSpace(body))
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (s *Server) serveSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	for {
		select {
		case b := <-s.out:
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) sessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == "" {
		s.session = "testmcp-session"
	}
	return s.session
}

func argInt(args json.RawMessage, key string, def int) int {
	if len(args) == 0 {
		return def
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i
		}
	}
	return def
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
}

func marshal(m *jsonrpc.Message) []byte {
	b, err := m.Marshal()
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"marshal failed"}}`)
	}
	return b
}
