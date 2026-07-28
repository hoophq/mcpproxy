package backend

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// ErrUnauthorized reports a 401 from a remote backend. Callers unwrap it to
// read the WWW-Authenticate challenge, which carries the resource-metadata
// URL that drives OAuth discovery (RFC 9728).
type ErrUnauthorized struct {
	// Backend is the configured backend name.
	Backend string
	// Challenge is the verbatim WWW-Authenticate header ("" if absent).
	Challenge string
	// Body is a bounded excerpt of the response body, for diagnostics.
	Body string
}

func (e *ErrUnauthorized) Error() string {
	if e.Challenge != "" {
		return fmt.Sprintf("backend %s: unauthorized (401): %s", e.Backend, e.Challenge)
	}
	return fmt.Sprintf("backend %s: unauthorized (401)", e.Backend)
}

// mcpSessionHeader is the streamable-HTTP session correlator. The remote
// assigns it on the initialize response; every later request must echo it.
const mcpSessionHeader = "Mcp-Session-Id"

// maxErrorBody bounds how much of an error response we quote back.
const maxErrorBody = 2 << 10

// RemoteBackend speaks MCP streamable-HTTP: every client message is POSTed to
// a single endpoint, and the remote answers with one JSON object or with an
// SSE stream carrying several messages. Send normalizes both shapes into the
// Recv channel, so callers cannot tell them apart.
type RemoteBackend struct {
	// TokenSource, when non-nil, mints the outbound bearer token for each
	// request. Passthrough and OAuth outbound auth plug in here, and the
	// minted token overrides any Authorization in the static headers.
	TokenSource func(ctx context.Context) (string, error)

	// Client overrides the per-instance HTTP client. Set before Start.
	Client *http.Client

	name    string
	url     string
	headers map[string]string
	log     *slog.Logger

	recv chan []byte
	done chan struct{}
	// stop is closed by Close and aborts in-flight response streaming.
	stop chan struct{}

	// inflight counts Sends and background SSE readers. Close waits for it
	// to drain before closing recv, because a send on a closed channel
	// panics the whole gateway.
	inflight sync.WaitGroup

	mu      sync.Mutex
	started bool
	closed  bool
	session string // Mcp-Session-Id assigned by the remote

	closeOnce sync.Once
}

// NewRemote builds an unstarted streamable-HTTP backend. cfg.URL must be set;
// cfg.Headers are sent verbatim on every request.
func NewRemote(name string, cfg config.Backend, log *slog.Logger) *RemoteBackend {
	if log == nil {
		log = slog.Default()
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	return &RemoteBackend{
		name:    name,
		url:     cfg.URL,
		headers: headers,
		log:     log,
		recv:    make(chan []byte, recvBuffer),
		done:    make(chan struct{}),
		stop:    make(chan struct{}),
	}
}

func (b *RemoteBackend) Name() string { return b.name }

// Start validates configuration and prepares the HTTP client. It issues no
// request: streamable-HTTP has no handshake of its own, so the first POST
// (the client's initialize) doubles as the connection probe.
func (b *RemoteBackend) Start(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started {
		return fmt.Errorf("remote backend %s: already started", b.name)
	}
	if b.url == "" {
		return fmt.Errorf("remote backend %s: empty url", b.name)
	}
	if b.Client == nil {
		// Per-instance client so one backend's connection pool, timeouts
		// and (later) TLS settings never leak into another's. No overall
		// Timeout: an SSE response body is long-lived by design, so
		// request deadlines ride on the context instead.
		b.Client = &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		}
	}
	b.started = true
	return nil
}

// Send POSTs one JSON-RPC message and routes whatever comes back into Recv.
// It returns once it has read the response headers and, for JSON responses,
// consumed the body. A background goroutine drains SSE bodies so a long tool
// call does not block the caller.
func (b *RemoteBackend) Send(ctx context.Context, msg []byte) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	if !b.started {
		b.mu.Unlock()
		return fmt.Errorf("remote backend %s: not started", b.name)
	}
	client, session := b.Client, b.session
	// Register before releasing the lock: Close observes closed==true and
	// this counter, so a send can never slip past both and reach a closed
	// recv channel.
	b.inflight.Add(1)
	b.mu.Unlock()
	defer b.inflight.Done()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("remote backend %s: building request: %w", b.name, err)
	}
	// Static headers go first. The protocol Content-Type and Accept set
	// below take precedence, and TokenSource wins over both.
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set(mcpSessionHeader, session)
	}
	if b.TokenSource != nil {
		tok, err := b.TokenSource(ctx)
		if err != nil {
			return fmt.Errorf("remote backend %s: token source: %w", b.name, err)
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("remote backend %s: post: %w", b.name, err)
	}

	// Adopt the session id from the first response that carries one.
	if sid := resp.Header.Get(mcpSessionHeader); sid != "" {
		b.mu.Lock()
		if b.session == "" {
			b.session = sid
		}
		b.mu.Unlock()
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		defer resp.Body.Close()
		return &ErrUnauthorized{
			Backend:   b.name,
			Challenge: resp.Header.Get("WWW-Authenticate"),
			Body:      readExcerpt(resp.Body),
		}
	case resp.StatusCode == http.StatusAccepted, resp.StatusCode == http.StatusNoContent:
		// Notifications and responses carry no payload.
		resp.Body.Close()
		return nil
	case resp.StatusCode >= 300:
		defer resp.Body.Close()
		return fmt.Errorf("remote backend %s: http %d: %s", b.name, resp.StatusCode, readExcerpt(resp.Body))
	}

	switch mediaType(resp.Header.Get("Content-Type")) {
	case "text/event-stream":
		// Hand our in-flight hold to the reader: the stream outlives
		// this call, and Close must wait for it before closing recv.
		b.inflight.Add(1)
		go func() {
			defer b.inflight.Done()
			defer resp.Body.Close()
			b.readSSE(resp.Body)
		}()
		return nil
	case "application/json", "":
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxLineBytes))
		if err != nil {
			return fmt.Errorf("remote backend %s: reading response: %w", b.name, err)
		}
		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			return nil
		}
		if !b.deliver(body) {
			return ErrClosed
		}
		return nil
	default:
		resp.Body.Close()
		return fmt.Errorf("remote backend %s: unexpected content-type %q", b.name, resp.Header.Get("Content-Type"))
	}
}

// readSSE parses text/event-stream framing and forwards each data payload as
// one JSON-RPC message. It joins multi-line data fields with newlines per the
// SSE spec and skips comments (":..."), ids and event names, because MCP
// carries everything in data.
func (b *RemoteBackend) readSSE(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	var data []byte
	flush := func() bool {
		if len(data) == 0 {
			return true
		}
		payload := bytes.TrimSpace(data)
		data = nil
		if len(payload) == 0 {
			return true
		}
		return b.deliver(payload)
	}
	for sc.Scan() {
		line := bytes.TrimRight(sc.Bytes(), "\r")
		if len(line) == 0 { // event boundary
			if !flush() {
				return
			}
			continue
		}
		if line[0] == ':' {
			continue
		}
		field, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue // field with no value carries nothing for MCP
		}
		if !bytes.Equal(field, []byte("data")) {
			continue
		}
		value = bytes.TrimPrefix(value, []byte(" "))
		if len(data) > 0 {
			data = append(data, '\n')
		}
		data = append(data, value...)
	}
	// A stream ending without a blank line still holds a complete event.
	flush()
	if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
		b.log.Debug("remote backend sse read", "backend", b.name, "err", err)
	}
}

// deliver hands one message to the consumer. It reports false once the
// backend is closing so callers stop producing.
func (b *RemoteBackend) deliver(msg []byte) bool {
	out := make([]byte, len(msg))
	copy(out, msg)
	select {
	case b.recv <- out:
		return true
	case <-b.stop:
		return false
	}
}

func (b *RemoteBackend) Recv() <-chan []byte { return b.recv }

func (b *RemoteBackend) Done() <-chan struct{} { return b.done }

// Err always returns nil. A remote backend has no asynchronous failure mode
// of its own: transport errors surface from Send, and only Close closes
// Done.
func (b *RemoteBackend) Err() error { return nil }

// Close stops accepting new traffic, aborts in-flight streams and closes
// Recv. Idempotent.
func (b *RemoteBackend) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		client := b.Client
		b.mu.Unlock()

		// stop first so parked deliveries give up, then drain. Past
		// this Wait no goroutine can still hold recv.
		close(b.stop)
		b.inflight.Wait()
		close(b.recv)
		close(b.done)
		if client != nil {
			client.CloseIdleConnections()
		}
	})
	return nil
}

// SessionID exposes the remote-assigned Mcp-Session-Id, for tests and logs.
func (b *RemoteBackend) SessionID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.session
}

// mediaType strips parameters from a Content-Type value.
func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

func readExcerpt(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, maxErrorBody))
	return string(bytes.TrimSpace(b))
}
