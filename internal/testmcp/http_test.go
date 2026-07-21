package testmcp

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/mcp"
)

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	return resp
}

func TestHTTPPostJSONResponse(t *testing.T) {
	hs := httptest.NewServer(New().HTTPHandler())
	defer hs.Close()

	resp := post(t, hs.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if resp.Header.Get("Mcp-Session-Id") == "" {
		t.Error("no Mcp-Session-Id assigned")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), ProtocolVersion) {
		t.Errorf("body = %s", body)
	}
}

func TestHTTPPostSSEResponse(t *testing.T) {
	s := New()
	s.SSEResponses(true)
	hs := httptest.NewServer(s.HTTPHandler())
	defer hs.Close()

	resp := post(t, hs.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "event: message\ndata: {") {
		t.Errorf("body = %q, want SSE framing", body)
	}
	if !strings.HasSuffix(string(body), "\n\n") {
		t.Errorf("body = %q, want a terminating blank line", body)
	}
}

// TestHTTPPostNotificationIs202: a notification has no response, so the
// server must say 202 with no payload rather than send an empty body.
func TestHTTPPostNotificationIs202(t *testing.T) {
	hs := httptest.NewServer(New().HTTPHandler())
	defer hs.Close()

	resp := post(t, hs.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body = %q, want empty", body)
	}
}

// TestHTTPGetStreamsServerInitiated covers the S2C channel other slices need
// for rug-pull and sampling tests.
func TestHTTPGetStreamsServerInitiated(t *testing.T) {
	s := New()
	hs := httptest.NewServer(s.HTTPHandler())
	defer hs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, hs.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}

	lines := make(chan string, 8)
	var read sync.WaitGroup
	read.Add(1)
	go func() {
		defer read.Done()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				lines <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	s.NotifyToolsChanged()
	s.RequestSampling("hi")

	want := []string{mcp.MethodToolsListChanged, mcp.MethodSamplingCreateMessage}
	for _, method := range want {
		select {
		case got := <-lines:
			if !strings.Contains(got, method) {
				t.Errorf("event = %s, want method %s", got, method)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s", method)
		}
	}
	cancel()
	read.Wait()
}

func TestHTTPDeleteEndsSession(t *testing.T) {
	hs := httptest.NewServer(New().HTTPHandler())
	defer hs.Close()

	req, _ := http.NewRequest(http.MethodDelete, hs.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

// TestServeStdioReturnsOnEOF: the stdio loop must terminate when its input
// closes, or a spawned testmcp binary would never exit.
func TestServeStdioReturnsOnEOF(t *testing.T) {
	in, inw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- New().ServeStdio(context.Background(), in, out) }()

	if _, err := io.WriteString(inw, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), `"id":1`) {
		if time.Now().After(deadline) {
			t.Fatalf("no response written; got %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = inw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeStdio = %v, want nil on EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeStdio did not return on EOF")
	}
}

// syncBuffer lets the test poll output that ServeStdio writes concurrently.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
