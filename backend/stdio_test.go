package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/internal/testmcp"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// The tests here exercise the exact framing code StdioBackend runs — against
// a real testmcp server over in-process pipes, so no subprocess is involved.
// Spawn behaviour lives in stdio_exec_unix_test.go.

// pipeServer wires a lineConn to an in-process testmcp over two io.Pipes.
func pipeServer(t *testing.T) (*lineConn, *testmcp.Server) {
	t.Helper()
	srv := testmcp.New()
	toSrv, fromClient := io.Pipe()
	fromSrv, toClient := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	var served sync.WaitGroup
	served.Add(1)
	go func() {
		defer served.Done()
		_ = srv.ServeStdio(ctx, toSrv, toClient)
		_ = toClient.Close()
	}()

	c := newLineConn("pipe", nil)
	c.attach(fromClient)
	var pumped sync.WaitGroup
	pumped.Add(1)
	go func() { defer pumped.Done(); c.pump(fromSrv) }()

	t.Cleanup(func() {
		c.closeWrite() // EOF ends ServeStdio, which closes toClient
		cancel()
		served.Wait()
		close(c.stop)
		pumped.Wait()
	})
	return c, srv
}

func TestStdioFramingRoundTrip(t *testing.T) {
	c, _ := pipeServer(t)

	if err := c.send([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)); err != nil {
		t.Fatalf("send initialize: %v", err)
	}
	got := recvMessage(t, c.recv, 5*time.Second)
	var res mcp.InitializeResult
	if err := json.Unmarshal(got.Result, &res); err != nil {
		t.Fatalf("decoding initialize result: %v", err)
	}
	if res.ProtocolVersion != testmcp.ProtocolVersion {
		t.Errorf("protocolVersion = %q", res.ProtocolVersion)
	}

	// An envelope arriving with its own CRLF must not double-frame: a blank
	// line between messages desynchronizes a strict peer.
	if err := c.send([]byte("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\r\n")); err != nil {
		t.Fatalf("send tools/list: %v", err)
	}
	got = recvMessage(t, c.recv, 5*time.Second)
	if got.ID.Key() != "2" {
		t.Errorf("id = %s, want 2", got.ID)
	}
}

// TestStdioFramingLargeMessage defends the raised scanner limit: 512 KB is
// well past bufio's 64 KiB default and a routine size for tool output.
func TestStdioFramingLargeMessage(t *testing.T) {
	c, _ := pipeServer(t)
	if err := c.send([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"big","arguments":{"kb":512}}}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := recvMessage(t, c.recv, 20*time.Second)
	var res struct {
		Content []mcp.ContentItem `json:"content"`
	}
	if err := json.Unmarshal(got.Result, &res); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("content = %v, want 1 item", res.Content)
	}
	if got, want := len(res.Content[0].Text), 512*1024; got != want {
		t.Errorf("payload len = %d, want %d", got, want)
	}
}

// TestStdioFramingServerInitiated covers the S2C path: the server pushes a
// notification and a sampling request with no client message in flight.
func TestStdioFramingServerInitiated(t *testing.T) {
	c, srv := pipeServer(t)
	srv.NotifyToolsChanged()
	id := srv.RequestSampling("hello")

	got := recvMessage(t, c.recv, 5*time.Second)
	if got.Method != mcp.MethodToolsListChanged || !got.IsNotification() {
		t.Fatalf("first message = %+v, want the list_changed notification", got)
	}
	got = recvMessage(t, c.recv, 5*time.Second)
	if got.Method != mcp.MethodSamplingCreateMessage || !got.IsRequest() {
		t.Fatalf("second message = %+v, want a sampling request", got)
	}
	if got.ID.Key() != id.Key() {
		t.Errorf("sampling id = %s, want %s", got.ID, id)
	}
}

func TestStdioFramingSkipsNonProtocolStdout(t *testing.T) {
	c := newLineConn("noise", nil)
	r, w := io.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); c.pump(r) }()

	// npx-style banners on stdout must never reach the gateway.
	_, _ = io.WriteString(w, "npm WARN deprecated foo\n\n")
	_, _ = io.WriteString(w, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/ping\"}\r\n")
	_ = w.Close()

	select {
	case msg := <-c.recv:
		if !bytes.Contains(msg, []byte("notifications/ping")) {
			t.Fatalf("first delivered message = %s, want the JSON one", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the JSON line")
	}
	<-done
}

func TestLineConnSendAfterCloseWrite(t *testing.T) {
	c := newLineConn("closed", nil)
	c.attach(nopWriteCloser{io.Discard})
	if err := c.send([]byte(`{}`)); err != nil {
		t.Fatalf("send before close: %v", err)
	}
	c.closeWrite()
	if err := c.send([]byte(`{}`)); !errors.Is(err, ErrClosed) {
		t.Fatalf("send after closeWrite = %v, want ErrClosed", err)
	}
}

func TestLineConnDetectsShortWrite(t *testing.T) {
	c := newLineConn("short", nil)
	c.attach(nopWriteCloser{shortWriter{}})
	if err := c.send([]byte(`{"a":1}`)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("send = %v, want ErrShortWrite", err)
	}
}

func TestMergeEnvLayersOverParent(t *testing.T) {
	base := []string{"A=1", "B=2"}
	got := mergeEnv(base, map[string]string{"B": "override"})
	if len(got) != 3 || got[0] != "A=1" || got[1] != "B=2" || got[2] != "B=override" {
		t.Fatalf("mergeEnv = %v, want the override appended after the parent entries", got)
	}
	// The parent slice must not be mutated: it is os.Environ()'s result,
	// shared across every backend the factory builds.
	if len(base) != 2 {
		t.Errorf("base was mutated: %v", base)
	}
	if got := mergeEnv(base, nil); len(got) != 2 {
		t.Errorf("mergeEnv with no overrides = %v", got)
	}
}

// --- shared helpers -----------------------------------------------------

func recvMessage(t *testing.T, ch <-chan []byte, timeout time.Duration) *jsonrpc.Message {
	t.Helper()
	select {
	case raw, ok := <-ch:
		if !ok {
			t.Fatal("recv channel closed while awaiting a message")
		}
		m, err := jsonrpc.Parse(raw)
		if err != nil {
			t.Fatalf("parsing %s: %v", raw, err)
		}
		return m
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for a message", timeout)
		return nil
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// shortWriter accepts every write but reports one byte fewer, standing in for
// a pipe that fills mid-message.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}
