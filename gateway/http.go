package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

const sessionHeader = "Mcp-Session-Id"

// maxBodyBytes bounds a single JSON-RPC request body (16 MiB).
const maxBodyBytes = 16 << 20

// Handler returns the streamable-HTTP front: POST = one JSON-RPC message,
// GET = SSE stream of server-initiated messages, DELETE = end session.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", g.serveMCP)
	return mux
}

func (g *Gateway) resolveIdentity(r *http.Request) (inspect.Identity, error) {
	if g.opts.Resolver == nil {
		return inspect.Identity{Subject: "anonymous"}, nil
	}
	return g.opts.Resolver(r)
}

func (g *Gateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	identity, err := g.resolveIdentity(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if identity.Subject == "" {
		identity.Subject = "anonymous"
	}
	switch r.Method {
	case http.MethodPost:
		g.handlePost(w, r, identity)
	case http.MethodGet:
		g.handleSSE(w, r, identity)
	case http.MethodDelete:
		if sid := r.Header.Get(sessionHeader); sid != "" && g.sessionFor(sid, identity) != nil {
			g.dropSession(sid, nil)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// sessionFor returns the session sid when identity opened it. Another caller
// gets nil, as for an unknown id: the id alone must not let anyone use or
// end a session, and the refusal is audited. Callers the resolver cannot
// tell apart share one identity and so share sessions; binding them needs
// inbound auth.
func (g *Gateway) sessionFor(sid string, identity inspect.Identity) *conn {
	c := g.getSession(sid)
	if c == nil || sameCaller(c.state.Identity(), identity) {
		return c
	}
	g.log.Warn("session used by another caller", "sid", sid,
		"owner", c.state.Identity().Subject, "caller", identity.Subject)
	g.sink.Emit(context.Background(), audit.Event{
		Time: time.Now(), Type: audit.EventSessionRefused, Session: sid,
		User: identity.Subject, Reason: "session opened by another caller",
	})
	return nil
}

// sameCaller compares the subject and, when the resolver sets one, the
// stable key of the account (a GitHub login can be renamed and reclaimed,
// its id cannot). A caller whose login or key changed starts a new session,
// so one session is always audited under one login. An email can change
// during a session and is not compared.
func sameCaller(a, b inspect.Identity) bool {
	return a.Subject == b.Subject && a.Key == b.Key
}

// handlePost processes one client JSON-RPC message.
func (g *Gateway) handlePost(w http.ResponseWriter, r *http.Request, identity inspect.Identity) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		http.Error(w, "body too large or unreadable", http.StatusBadRequest)
		return
	}
	env, err := jsonrpc.Parse(body)
	if err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewError(jsonrpc.ID{}, jsonrpc.CodeParseError, err.Error()))
		return
	}

	// Decide the protocol era before touching session state: a Modern
	// request carries no session id and must not be measured against the
	// Legacy front door's rules.
	rev, protoErr := classify(r, env)
	if protoErr != nil {
		writeJSON(w, http.StatusBadRequest, protoErr)
		return
	}
	if rev == mcp.RevisionModern {
		g.refuseModern(w, env)
		return
	}

	sid := r.Header.Get(sessionHeader)
	var c *conn
	if env.Method == mcp.MethodInitialize {
		c, err = g.startSession(r.Context(), identity)
		if err != nil {
			http.Error(w, "failed to start session: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set(sessionHeader, c.state.ID())
	} else {
		if sid == "" {
			http.Error(w, "missing "+sessionHeader, http.StatusBadRequest)
			return
		}
		c = g.sessionFor(sid, identity)
		if c == nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		if msg := checkEchoedVersion(r, env, c.state.ProtocolVersion()); msg != nil {
			writeJSON(w, http.StatusBadRequest, msg)
			return
		}
	}
	c.touch()

	ctx, cancel := context.WithTimeout(r.Context(), g.opts.RequestTimeout)
	defer cancel()

	resp, err := c.handleC2S(ctx, env)
	if err != nil {
		g.log.Warn("c2s handling failed", "sid", c.state.ID(), "method", env.Method, "err", err)
		if env.IsRequest() {
			writeJSON(w, http.StatusOK, jsonrpc.NewError(env.ID, jsonrpc.CodeInternalError, err.Error()))
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if resp == nil { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleC2S routes one client message through the pipeline and to backends.
func (c *conn) handleC2S(ctx context.Context, env *jsonrpc.Message) (*jsonrpc.Message, error) {
	// Resolve routing before inspection so checks see backend + bare tool.
	var bc *backendConn
	bareEnv := env
	toolName := ""
	switch env.Method {
	case mcp.MethodToolsCall:
		full := inspect.RawTool(env.Params)
		var bare string
		var err error
		bc, bare, err = c.routeTool(full)
		if err != nil {
			return jsonrpc.NewError(env.ID, jsonrpc.CodeMethodNotFound, err.Error()), nil
		}
		toolName = bare
		if bare != full {
			bareEnv = rewriteToolName(env, bare)
		}
	case mcp.MethodInitialize, mcp.MethodToolsList:
		// fanned out below
	default:
		bc = c.anyBackend()
	}

	m := &inspect.Msg{Dir: inspect.C2S, Env: bareEnv}
	if bc != nil {
		m.Backend = bc.name
	}
	dec := c.runPipeline(ctx, m)
	switch dec.Verdict {
	case inspect.Deny:
		c.auditDeny(ctx, m, dec, toolName)
		if env.IsRequest() {
			return dec.Reply, nil
		}
		return nil, nil
	case inspect.Kill:
		c.kill(dec.Reason)
		if env.IsRequest() {
			return jsonrpc.NewError(env.ID, jsonrpc.CodePolicyDenied, dec.Reason), nil
		}
		return nil, nil
	case inspect.Hold:
		resp, err := c.holdForApproval(ctx, m, dec, toolName)
		if resp != nil || err != nil {
			return resp, err
		}
		// approved: fall through to forwarding
	}

	// Forward.
	switch bareEnv.Method {
	case mcp.MethodInitialize:
		return c.fanoutInitialize(ctx, bareEnv)
	case mcp.MethodToolsList:
		resp, err := c.fanoutToolsList(ctx, bareEnv)
		if err != nil {
			return nil, err
		}
		return c.inspectResponse(ctx, "", bareEnv, resp)
	default:
		if bareEnv.IsNotification() {
			return nil, c.notifyAll(ctx, bareEnv)
		}
		if bc == nil {
			bc = c.anyBackend()
		}
		c.state.TrackRequest(bareEnv.ID, bc.name, bareEnv.Method, toolName)
		start := time.Now()
		resp, err := c.roundTrip(ctx, bc, bareEnv)
		if err != nil {
			c.state.DropPending(bareEnv.ID)
			return nil, err
		}
		if bareEnv.Method == mcp.MethodToolsCall {
			c.auditToolResult(ctx, bc.name, toolName, resp, time.Since(start))
		}
		return c.inspectResponse(ctx, bc.name, bareEnv, resp)
	}
}

// inspectResponse runs the S2C pipeline over a response before returning it
// to the client (redaction, budget, rug-pull on tools/list).
func (c *conn) inspectResponse(ctx context.Context, backendName string, req, resp *jsonrpc.Message) (*jsonrpc.Message, error) {
	p, _ := c.state.ResolveResponse(resp.ID)
	m := &inspect.Msg{
		Dir: inspect.S2C, Backend: backendName, Env: resp,
		CorrelatedMethod: req.Method, CorrelatedTool: p.Tool,
	}
	if m.CorrelatedMethod == "" {
		m.CorrelatedMethod = p.Method
	}
	dec := c.runPipeline(ctx, m)
	switch dec.Verdict {
	case inspect.Deny:
		return jsonrpc.NewError(req.ID, jsonrpc.CodePolicyDenied, dec.Reason), nil
	case inspect.Kill:
		c.kill(dec.Reason)
		return jsonrpc.NewError(req.ID, jsonrpc.CodePolicyDenied, dec.Reason), nil
	}
	return resp, nil
}

// holdForApproval parks a tool call until a reviewer resolves it. Returns
// (resp, err) to short-circuit, or (nil, nil) when approved.
func (c *conn) holdForApproval(ctx context.Context, m *inspect.Msg, dec inspect.Decision, tool string) (*jsonrpc.Message, error) {
	held := c.g.opts.Held
	if held == nil {
		return jsonrpc.NewError(m.Env.ID, jsonrpc.CodePolicyDenied,
			"approval required but no approval store configured"), nil
	}
	id, resolved, err := held.Hold(ctx, HeldCall{
		Session: c.state.ID(), User: c.state.Identity().Subject,
		Backend: m.Backend, Tool: tool, Args: m.Env.Params, Rule: dec.Rule,
	})
	if err != nil {
		return nil, err
	}
	c.g.sink.Emit(ctx, audit.Event{
		Time: time.Now(), Type: audit.EventApprovalPending, Session: c.state.ID(),
		User: c.state.Identity().Subject, Backend: m.Backend, Tool: tool,
		Rule: dec.Rule, Fields: map[string]any{"approval_id": id},
	})
	select {
	case ok := <-resolved:
		c.g.sink.Emit(ctx, audit.Event{
			Time: time.Now(), Type: audit.EventApprovalResolved, Session: c.state.ID(),
			Backend: m.Backend, Tool: tool,
			Fields: map[string]any{"approval_id": id, "approved": ok},
		})
		if !ok {
			return jsonrpc.NewError(m.Env.ID, jsonrpc.CodeApprovalRejected,
				fmt.Sprintf("tool call %q rejected by reviewer", tool)), nil
		}
		return nil, nil // approved → caller forwards
	case <-ctx.Done():
		return jsonrpc.NewError(m.Env.ID, jsonrpc.CodeApprovalRejected,
			"approval timed out"), nil
	}
}

func (c *conn) auditDeny(ctx context.Context, m *inspect.Msg, dec inspect.Decision, tool string) {
	typ := audit.EventToolDenied
	if m.Env.Method == mcp.MethodSamplingCreateMessage || m.Env.Method == mcp.MethodElicitationCreate {
		typ = audit.EventServerReqDenied
	}
	c.g.sink.Emit(ctx, audit.Event{
		Time: time.Now(), Type: typ, Session: c.state.ID(),
		User: c.state.Identity().Subject, Backend: m.Backend,
		Tool: tool, Rule: dec.Rule, Reason: dec.Reason,
	})
}

func (c *conn) auditToolResult(ctx context.Context, backendName, tool string, resp *jsonrpc.Message, dur time.Duration) {
	fields := map[string]any{"duration_ms": dur.Milliseconds()}
	if resp.Result != nil {
		fields["result_bytes"] = len(resp.Result)
	}
	if resp.Error != nil {
		fields["error_code"] = resp.Error.Code
	}
	c.g.sink.Emit(ctx, audit.Event{
		Time: time.Now(), Type: audit.EventToolResult, Session: c.state.ID(),
		User: c.state.Identity().Subject, Backend: backendName, Tool: tool,
		Fields: fields,
	})
}

// handleSSE serves the S2C stream (server-initiated requests/notifications).
func (g *Gateway) handleSSE(w http.ResponseWriter, r *http.Request, identity inspect.Identity) {
	sid := r.Header.Get(sessionHeader)
	if sid == "" {
		http.Error(w, "missing "+sessionHeader, http.StatusBadRequest)
		return
	}
	c := g.sessionFor(sid, identity)
	if c == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	for {
		select {
		case msg := <-c.s2c:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", msg.raw); err != nil {
				return
			}
			fl.Flush()
			c.touch()
		case <-c.done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// rewriteToolName clones env with params.name set to bare, dropping the
// aggregation prefix before the backend sees the call.
func rewriteToolName(env *jsonrpc.Message, bare string) *jsonrpc.Message {
	var params map[string]json.RawMessage
	if err := json.Unmarshal(env.Params, &params); err != nil {
		return env
	}
	nb, _ := json.Marshal(bare)
	params["name"] = nb
	pb, err := json.Marshal(params)
	if err != nil {
		return env
	}
	clone := *env
	clone.Params = pb
	return &clone
}

func writeJSON(w http.ResponseWriter, status int, msg *jsonrpc.Message) {
	b, err := msg.Marshal()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
