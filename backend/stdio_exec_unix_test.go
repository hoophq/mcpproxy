//go:build unix

package backend

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// These tests spawn real children. They are unix-only because they assert on
// process groups and POSIX shell behaviour.

// TestStdioBackendSpawnRoundTrip drives the full spawn path against the
// testmcp binary launched through `go run`, which makes the MCP server a
// *grandchild* — the same shape as `npx some-mcp-server`.
func TestStdioBackendSpawnRoundTrip(t *testing.T) {
	b := NewStdio("spawned", config.Backend{
		Transport: TransportStdio,
		Command:   goRunTestMCP(t),
	}, nil)
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if b.Name() != "spawned" {
		t.Errorf("Name = %q", b.Name())
	}
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)); err != nil {
		t.Fatalf("Send initialize: %v", err)
	}
	// `go run` compiles first, so the first response can take a while.
	got := recvMessage(t, b.Recv(), 120*time.Second)
	if got.Error != nil {
		t.Fatalf("initialize errored: %v", got.Error)
	}

	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"hi":true}}}`)); err != nil {
		t.Fatalf("Send echo: %v", err)
	}
	got = recvMessage(t, b.Recv(), 30*time.Second)
	if !bytes.Contains(got.Result, []byte(`{\"hi\":true}`)) {
		t.Errorf("echo result = %s, want the arguments echoed back", got.Result)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not close after Close")
	}
	if err := b.Err(); err != nil {
		t.Errorf("Err after a clean Close = %v, want nil", err)
	}
	if _, ok := <-b.Recv(); ok {
		t.Error("Recv still yields messages after Close")
	}
	if err := b.Send(context.Background(), []byte(`{}`)); !errors.Is(err, ErrClosed) {
		t.Errorf("Send after Close = %v, want ErrClosed", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

func TestStdioBackendReportsChildExit(t *testing.T) {
	b := NewStdio("dying", config.Backend{
		Transport: TransportStdio,
		Command:   []string{"sh", "-c", "exit 3"},
	}, nil)
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	select {
	case <-b.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done did not close after the child exited")
	}
	if _, ok := <-b.Recv(); ok {
		t.Error("Recv should be closed once the child is gone")
	}
	err := b.Err()
	if err == nil {
		t.Fatal("Err = nil, want the exit status")
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("Err = %v, want an *exec.ExitError in the chain", err)
	}
	if exit.ExitCode() != 3 {
		t.Errorf("exit code = %d, want 3", exit.ExitCode())
	}
	if err := b.Send(context.Background(), []byte(`{}`)); !errors.Is(err, ErrClosed) {
		t.Errorf("Send to a dead child = %v, want ErrClosed", err)
	}
}

// TestLineConnEPIPEIsErrClosed: when a child dies on its own, the next write
// gets EPIPE. The gateway must see the same ErrClosed it gets from an
// orderly Close, not a raw syscall error it would have to special-case.
func TestLineConnEPIPEIsErrClosed(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer w.Close()
	c := newLineConn("epipe", nil)
	c.attach(w)
	if err := r.Close(); err != nil { // the "child" goes away
		t.Fatalf("closing the read end: %v", err)
	}
	if err := c.send([]byte(`{"jsonrpc":"2.0","method":"n"}`)); !errors.Is(err, ErrClosed) {
		t.Fatalf("send to a broken pipe = %v, want ErrClosed", err)
	}
}

// TestStdioBackendKillsProcessGroup is the reason Start sets Setpgid: `sh`
// forks a `sleep` grandchild exactly like `npx` forks node. Signalling only
// the direct child would orphan the sleeper.
func TestStdioBackendKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	// The shell traps SIGTERM and ignores stdin EOF, so Close must escalate
	// all the way to SIGKILL — and the sleeper must die with the group.
	script := "trap '' TERM; sleep 100 & echo $! > " + pidFile + "; wait"
	b := NewStdio("group", config.Backend{
		Transport: TransportStdio,
		Command:   []string{"sh", "-c", script},
	}, nil)
	b.ShutdownGrace = 500 * time.Millisecond
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	pid := waitForPID(t, pidFile)
	if !processAlive(pid) {
		t.Fatalf("grandchild %d not running before Close", pid)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("grandchild %d survived Close", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStdioBackendClosesOnStdinEOF covers the polite path: a child that exits
// on EOF must be reaped without any signal, well inside politeGrace.
func TestStdioBackendClosesOnStdinEOF(t *testing.T) {
	b := NewStdio("polite", config.Backend{
		Transport: TransportStdio,
		Command:   []string{"cat"},
	}, nil)
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// cat echoes back, proving the pump is live before we shut down.
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := recvMessage(t, b.Recv(), 10*time.Second); got.Method != "ping" {
		t.Fatalf("echoed message = %+v", got)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Err(); err != nil {
		t.Errorf("Err = %v, want nil after a clean EOF exit", err)
	}
}

// TestStdioBackendPassesEnv proves cfg.Env is layered over the parent
// environment rather than replacing it.
func TestStdioBackendPassesEnv(t *testing.T) {
	t.Setenv("STDIO_PARENT_VAR", "parent")
	b := NewStdio("env", config.Backend{
		Transport: TransportStdio,
		Command:   []string{"sh", "-c", `printf '{"jsonrpc":"2.0","method":"n","params":{"a":"%s","b":"%s"}}\n' "$STDIO_PARENT_VAR" "$STDIO_CHILD_VAR"`},
		Env:       map[string]string{"STDIO_CHILD_VAR": "child"},
	}, nil)
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	got := recvMessage(t, b.Recv(), 10*time.Second)
	if want := `{"a":"parent","b":"child"}`; string(got.Params) != want {
		t.Errorf("params = %s, want %s", got.Params, want)
	}
}

func TestStdioBackendContextCancelTerminatesChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := NewStdio("ctx", config.Backend{
		Transport: TransportStdio,
		Command:   []string{"sh", "-c", "sleep 100"},
	}, nil)
	if err := b.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	cancel()
	select {
	case <-b.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("cancelling the start context did not terminate the child")
	}
}

func TestStdioBackendEmptyCommand(t *testing.T) {
	b := NewStdio("empty", config.Backend{Transport: TransportStdio}, nil)
	if err := b.Start(context.Background()); err == nil {
		t.Fatal("Start with no command should fail")
	}
	// Close must still release Recv and Done even though nothing spawned.
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-b.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed after Close on an unspawned backend")
	}
	if _, ok := <-b.Recv(); ok {
		t.Error("Recv not closed after Close on an unspawned backend")
	}
}

func TestStdioBackendStartTwice(t *testing.T) {
	b := NewStdio("twice", config.Backend{Transport: TransportStdio, Command: []string{"cat"}}, nil)
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Start(context.Background()); err == nil {
		t.Fatal("second Start should fail")
	}
}

func goRunTestMCP(t *testing.T) []string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	return []string{goBin, "run", "github.com/hoophq/mcpproxy/internal/testmcp/cmd"}
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild never wrote its pid to %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// processAlive reports whether pid still exists. Signal 0 performs the
// existence and permission checks without delivering anything.
func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
