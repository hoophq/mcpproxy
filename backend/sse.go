package backend

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// SSEBackend speaks the legacy MCP HTTP+SSE transport (protocol revision
// 2024-11-05), still used by several hosted servers (Atlassian, Monday,
// Square, Replicate, …):
//
//	GET  <url>            → long-lived text/event-stream
//	  event: endpoint     → data carries the URL to POST messages to
//	  event: message      → data carries one JSON-RPC message
//	POST <endpoint URL>   → one JSON-RPC message; responses arrive on the
//	                        GET stream, not in the POST body (usually 202)
//
// The newer streamable-HTTP transport (RemoteBackend) replaced this design;
// keep new integrations there and use SSEBackend only when the remote
// offers nothing else.
type SSEBackend struct {
	// TokenSource, when non-nil, mints the outbound bearer token for each
	// request (stream GET and message POSTs alike). Overrides any
	// Authorization in the static headers.
	TokenSource func(ctx context.Context) (string, error)

	// Client overrides the per-instance HTTP client. Set before Start.
	Client *http.Client

	name    string
	url     string
	headers map[string]string
	log     *slog.Logger

	recv chan []byte
	done chan struct{}
	stop chan struct{}

	// endpointReady closes once the endpoint event arrived; Send blocks on
	// it because the POST target is unknown until then.
	endpointReady chan struct{}

	mu       sync.Mutex
	started  bool
	closed   bool
	endpoint string // resolved POST target from the endpoint event
	err      error  // stream failure cause, reported via Err

	// cancelStream aborts the GET stream request on Close.
	cancelStream context.CancelFunc

	closeOnce sync.Once
}

// endpointWait bounds how long Send waits for the server's endpoint event
// before giving up. The event is the first thing a healthy server emits, so
// this only triggers against broken or misidentified endpoints.
const endpointWait = 30 * time.Second

// NewSSE builds an unstarted legacy HTTP+SSE backend. cfg.URL is the SSE
// stream URL; cfg.Headers are sent on every request.
func NewSSE(name string, cfg config.Backend, log *slog.Logger) *SSEBackend {
	if log == nil {
		log = slog.Default()
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	return &SSEBackend{
		name:          name,
		url:           cfg.URL,
		headers:       headers,
		log:           log,
		recv:          make(chan []byte, recvBuffer),
		done:          make(chan struct{}),
		stop:          make(chan struct{}),
		endpointReady: make(chan struct{}),
	}
}

// Name implements Backend.
func (b *SSEBackend) Name() string { return b.name }

// Start opens the SSE stream and waits for it to be established (headers
// received). The endpoint event may arrive slightly later; Send waits for
// it separately.
func (b *SSEBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return fmt.Errorf("sse backend %s: already started", b.name)
	}
	if b.url == "" {
		b.mu.Unlock()
		return fmt.Errorf("sse backend %s: url is required", b.name)
	}
	if b.Client == nil {
		// No overall timeout: the stream is long-lived by design.
		b.Client = &http.Client{}
	}
	b.started = true
	b.mu.Unlock()

	// The stream must outlive Start's ctx (it lives for the session);
	// Close aborts it explicitly.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	b.mu.Lock()
	b.cancelStream = cancel
	b.mu.Unlock()

	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, b.url, nil)
	if err != nil {
		cancel()
		return fmt.Errorf("sse backend %s: building stream request: %w", b.name, err)
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if err := b.authorize(ctx, req); err != nil {
		cancel()
		return err
	}

	resp, err := b.Client.Do(req)
	if err != nil {
		cancel()
		return fmt.Errorf("sse backend %s: opening stream: %w", b.name, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		defer resp.Body.Close()
		cancel()
		return &ErrUnauthorized{
			Backend:   b.name,
			Challenge: resp.Header.Get("WWW-Authenticate"),
			Body:      readExcerpt(resp.Body),
		}
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		cancel()
		return fmt.Errorf("sse backend %s: stream http %d: %s", b.name, resp.StatusCode, readExcerpt(resp.Body))
	}
	if mt := mediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		resp.Body.Close()
		cancel()
		return fmt.Errorf("sse backend %s: expected text/event-stream, got %q — endpoint is likely streamable-http, use transport: streamable-http", b.name, mt)
	}

	go b.readStream(resp.Body)
	return nil
}

// readStream consumes the long-lived SSE stream: the endpoint event unlocks
// Send, message events go to Recv, stream end terminates the backend (the
// session dies with it — MCP sessions cannot survive their event stream).
func (b *SSEBackend) readStream(body io.ReadCloser) {
	defer body.Close()

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	var event string
	var data []string
	flush := func() {
		kind := event
		payload := strings.Join(data, "\n")
		event, data = "", nil
		if payload == "" {
			return
		}
		switch kind {
		case "endpoint":
			b.setEndpoint(payload)
		case "", "message":
			// Per spec message events carry the event name; tolerate
			// servers that omit it.
			if !b.deliver([]byte(payload)) {
				return
			}
		default:
			// Unknown event kinds (ping, keepalive…) are not protocol.
			b.log.Debug("sse backend: ignoring event", "backend", b.name, "event", kind)
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
			// comment/keepalive
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		// id: and retry: fields are irrelevant to MCP; ignored.
	}
	flush()

	// Stream ended: terminate the backend so the session is torn down
	// rather than silently losing all server→client traffic.
	err := sc.Err()
	b.closeOnce.Do(func() {
		b.mu.Lock()
		userClosed := b.closed // Close sets this before aborting the stream
		b.closed = true
		if err != nil && !userClosed {
			b.err = fmt.Errorf("sse backend %s: stream error: %w", b.name, err)
		} else if !userClosed {
			b.err = fmt.Errorf("sse backend %s: server closed the event stream", b.name)
		}
		cancel := b.cancelStream
		b.mu.Unlock()
		close(b.stop)
		if cancel != nil {
			cancel()
		}
		close(b.recv)
		close(b.done)
	})
}

// setEndpoint resolves the endpoint event's URL (may be relative) against
// the stream URL and unlocks Send.
func (b *SSEBackend) setEndpoint(raw string) {
	base, err := url.Parse(b.url)
	if err != nil {
		b.log.Warn("sse backend: unparseable stream url", "backend", b.name, "err", err)
		return
	}
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		b.log.Warn("sse backend: unparseable endpoint event", "backend", b.name, "data", raw, "err", err)
		return
	}
	resolved := base.ResolveReference(ref).String()

	b.mu.Lock()
	first := b.endpoint == ""
	b.endpoint = resolved
	b.mu.Unlock()
	if first {
		close(b.endpointReady)
		b.log.Debug("sse backend: endpoint established", "backend", b.name, "endpoint", resolved)
	}
}

// Send POSTs one JSON-RPC message to the endpoint URL. Responses do NOT
// come back in the POST body — they arrive on the event stream — so any
// 2xx is success here.
func (b *SSEBackend) Send(ctx context.Context, msg []byte) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	if !b.started {
		b.mu.Unlock()
		return fmt.Errorf("sse backend %s: not started", b.name)
	}
	client := b.Client
	b.mu.Unlock()

	// The endpoint event races the first Send (initialize); wait for it.
	select {
	case <-b.endpointReady:
	case <-b.stop:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(endpointWait):
		return fmt.Errorf("sse backend %s: no endpoint event within %s", b.name, endpointWait)
	}

	b.mu.Lock()
	endpoint := b.endpoint
	b.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("sse backend %s: building request: %w", b.name, err)
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := b.authorize(ctx, req); err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sse backend %s: post: %w", b.name, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return &ErrUnauthorized{
			Backend:   b.name,
			Challenge: resp.Header.Get("WWW-Authenticate"),
			Body:      readExcerpt(resp.Body),
		}
	case resp.StatusCode >= 300:
		return fmt.Errorf("sse backend %s: http %d: %s", b.name, resp.StatusCode, readExcerpt(resp.Body))
	}
	// Some servers echo the response in the POST body instead of (or in
	// addition to) the stream. The spec says stream-only; tolerate the
	// echo shape by delivering a JSON body when present, since dropping it
	// would hang the waiter if the server never mirrors it to the stream.
	if mediaType(resp.Header.Get("Content-Type")) == "application/json" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxLineBytes))
		if err == nil {
			if body = bytes.TrimSpace(body); len(body) > 0 {
				b.deliver(body)
			}
		}
	}
	return nil
}

// authorize applies the TokenSource bearer, if any.
func (b *SSEBackend) authorize(ctx context.Context, req *http.Request) error {
	if b.TokenSource == nil {
		return nil
	}
	tok, err := b.TokenSource(ctx)
	if err != nil {
		return fmt.Errorf("sse backend %s: token source: %w", b.name, err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return nil
}

// deliver hands one message to the consumer; false once closing.
func (b *SSEBackend) deliver(msg []byte) bool {
	out := make([]byte, len(msg))
	copy(out, msg)
	select {
	case b.recv <- out:
		return true
	case <-b.stop:
		return false
	}
}

// Recv implements Backend.
func (b *SSEBackend) Recv() <-chan []byte { return b.recv }

// Done implements Backend.
func (b *SSEBackend) Done() <-chan struct{} { return b.done }

// Err reports why the stream terminated; nil on clean Close.
func (b *SSEBackend) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// Close aborts the stream and releases resources. Idempotent. The stream
// reader observes the aborted body and finishes the teardown (closing recv
// and done), so Close never races it on the channels.
func (b *SSEBackend) Close() error {
	b.mu.Lock()
	if !b.started {
		// Never started: complete the lifecycle directly.
		b.mu.Unlock()
		b.closeOnce.Do(func() {
			b.mu.Lock()
			b.closed = true
			b.mu.Unlock()
			close(b.stop)
			close(b.recv)
			close(b.done)
		})
		return nil
	}
	b.closed = true
	cancel := b.cancelStream
	b.mu.Unlock()
	if cancel != nil {
		cancel() // aborts the GET body; readStream finishes teardown
	}
	select {
	case <-b.done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("sse backend %s: stream reader did not stop", b.name)
	}
	return nil
}
