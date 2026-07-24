package wal

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/audit"
)

var _ audit.Sink = (*WAL)(nil)

func newWAL(t *testing.T) *WAL {
	t.Helper()
	w, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	// Keep warnings out of test output; the logger is exercised explicitly in
	// TestWriteErrorWarnsOnce.
	return w.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRoundTrip(t *testing.T) {
	w := newWAL(t)
	ctx := context.Background()

	want := []audit.Event{
		{Time: time.Unix(1, 0).UTC(), Type: audit.EventSessionStart, Session: "s1", User: "ana"},
		{Time: time.Unix(2, 0).UTC(), Type: audit.EventToolCall, Session: "s1", Backend: "github", Tool: "list_issues"},
		{Time: time.Unix(3, 0).UTC(), Type: audit.EventToolDenied, Session: "s1", Tool: "rm", Rule: "policy", Reason: "denied",
			Fields: map[string]any{"count": float64(3)}},
		{Time: time.Unix(4, 0).UTC(), Type: audit.EventSessionEnd, Session: "s1"},
	}
	for _, ev := range want {
		w.Emit(ctx, ev)
	}

	got, err := w.Replay("s1")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("replayed %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Session != want[i].Session ||
			got[i].Tool != want[i].Tool || got[i].User != want[i].User ||
			got[i].Rule != want[i].Rule || got[i].Reason != want[i].Reason ||
			!got[i].Time.Equal(want[i].Time) {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if got[2].Fields["count"] != float64(3) {
		t.Errorf("Fields round-trip lost: %v", got[2].Fields)
	}
}

// session_end must durably close the file: the record has to survive even if
// the process dies immediately afterwards, so nothing may sit in the buffer.
func TestSessionEndFlushesAndCloses(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	w.Emit(ctx, audit.Event{Type: audit.EventSessionStart, Session: "s1"})
	w.Emit(ctx, audit.Event{Type: audit.EventSessionEnd, Session: "s1"})

	// Read the file directly, without going through Replay's flush.
	data, err := os.ReadFile(filepath.Join(dir, "s1.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n != 2 {
		t.Errorf("file has %d lines after session_end, want 2 (buffer not flushed)", n)
	}

	// The handle is released, so late events are dropped rather than
	// reopening and corrupting a sealed record.
	w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: "s1", Tool: "late"})
	got, err := w.Replay("s1")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("replayed %d events, want 2 (late event must not append)", len(got))
	}
}

func TestSessionKilledIsTerminal(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	w.Emit(ctx, audit.Event{Type: audit.EventSessionStart, Session: "k1"})
	w.Emit(ctx, audit.Event{Type: audit.EventSessionKilled, Session: "k1", Reason: "rug pull"})

	data, err := os.ReadFile(filepath.Join(dir, "k1.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "session_killed") {
		t.Error("killed event not durable on disk")
	}
	if n := strings.Count(string(data), "\n"); n != 2 {
		t.Errorf("%d lines on disk, want 2", n)
	}
}

// One file per session, no cross-contamination.
func TestSessionsAreIsolated(t *testing.T) {
	w := newWAL(t)
	ctx := context.Background()
	w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: "a", Tool: "ta"})
	w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: "b", Tool: "tb"})
	w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: "a", Tool: "ta2"})

	a, err := w.Replay("a")
	if err != nil {
		t.Fatalf("Replay(a): %v", err)
	}
	b, err := w.Replay("b")
	if err != nil {
		t.Fatalf("Replay(b): %v", err)
	}
	if len(a) != 2 || a[0].Tool != "ta" || a[1].Tool != "ta2" {
		t.Errorf("session a = %+v", a)
	}
	if len(b) != 1 || b[0].Tool != "tb" {
		t.Errorf("session b = %+v", b)
	}

	sessions, err := w.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("Sessions = %v, want 2 entries", sessions)
	}
}

// Every line must be independently parseable JSON: that is the whole point
// of JSONL, and downstream review tooling streams it line by line.
func TestFileIsValidJSONL(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	w.Emit(ctx, audit.Event{Type: audit.EventToolResult, Session: "j1",
		Reason: "has \"quotes\" and\nnewlines", Fields: map[string]any{"nested": map[string]any{"k": "v"}}})
	w.Emit(ctx, audit.Event{Type: audit.EventSessionEnd, Session: "j1"})

	data, err := os.ReadFile(filepath.Join(dir, "j1.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2 (an embedded newline broke the framing)", len(lines))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}
}

func TestConcurrentEmit(t *testing.T) {
	w := newWAL(t)
	ctx := context.Background()

	const sessions, perSession = 6, 40
	var wg sync.WaitGroup
	for s := range sessions {
		sid := string(rune('a' + s))
		// Two writers per session so the per-file mutex is actually contended,
		// plus distinct sessions so the map is contended too.
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range perSession {
					w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: sid, Tool: "t"})
				}
			}()
		}
	}
	wg.Wait()

	for s := range sessions {
		sid := string(rune('a' + s))
		got, err := w.Replay(sid)
		if err != nil {
			t.Fatalf("Replay(%s): %v", sid, err)
		}
		if len(got) != perSession*2 {
			t.Errorf("session %s: %d events, want %d", sid, len(got), perSession*2)
		}
	}
}

// A terminal event racing with ordinary writes must not lose or duplicate
// records, and must never panic on a closed file.
func TestConcurrentEmitWithTerminal(t *testing.T) {
	w := newWAL(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: "race", Tool: "t"})
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Emit(ctx, audit.Event{Type: audit.EventSessionEnd, Session: "race"})
	}()
	wg.Wait()

	// Whatever the interleaving, the file must replay cleanly.
	if _, err := w.Replay("race"); err != nil {
		t.Fatalf("Replay after racing terminal event: %v", err)
	}
}

func TestReplayUnknownSession(t *testing.T) {
	w := newWAL(t)
	if _, err := w.Replay("nope"); err == nil {
		t.Fatal("Replay of an unrecorded session returned nil error")
	}
	if !strings.Contains(mustErr(t, w, "nope"), "nope") {
		t.Error("error does not name the session")
	}
}

func mustErr(t *testing.T, w *WAL, sid string) string {
	t.Helper()
	_, err := w.Replay(sid)
	if err == nil {
		t.Fatal("expected error")
	}
	return err.Error()
}

// Session ids arrive in an HTTP header, so path traversal is a real input.
func TestRejectsTraversalSessionIDs(t *testing.T) {
	w := newWAL(t)
	ctx := context.Background()
	for _, sid := range []string{"../escape", "a/b", "..", ".", `x\y`} {
		if _, err := w.Replay(sid); err == nil {
			t.Errorf("Replay(%q) accepted a traversing id", sid)
		}
		// Emit must swallow it rather than write outside dir.
		w.Emit(ctx, audit.Event{Type: audit.EventToolCall, Session: sid})
	}
	sessions, err := w.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("traversing ids created files: %v", sessions)
	}
}

// Events with no session belong to no file and must be dropped silently.
func TestEmitWithoutSessionIsDropped(t *testing.T) {
	w := newWAL(t)
	w.Emit(context.Background(), audit.Event{Type: audit.EventError, Reason: "boom"})
	sessions, err := w.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("sessionless event created %v", sessions)
	}
}

// Auditing must never take down the gateway: a broken file yields one
// warning and continued no-op Emits, not an error return or a panic.
func TestWriteErrorWarnsOnce(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var buf syncBuf
	w.WithLogger(slog.New(slog.NewTextHandler(&buf, nil)))

	ctx := context.Background()
	w.Emit(ctx, audit.Event{Type: audit.EventSessionStart, Session: "broken"})

	// Close the underlying fd out from under the WAL to force write failures.
	w.mu.Lock()
	sf := w.files["broken"]
	w.mu.Unlock()
	sf.mu.Lock()
	_ = sf.w.Flush()
	_ = sf.f.Close()
	sf.mu.Unlock()

	// Enough events to overflow the buffer so writes actually reach the fd.
	big := strings.Repeat("x", 4096)
	for range 40 {
		w.Emit(ctx, audit.Event{Type: audit.EventToolResult, Session: "broken", Reason: big})
	}
	w.Emit(ctx, audit.Event{Type: audit.EventSessionEnd, Session: "broken"})

	if n := strings.Count(buf.String(), "wal write failed"); n != 1 {
		t.Errorf("logged %d warnings, want exactly 1 per session", n)
	}
}

// Flush makes an in-progress session readable without ending it.
func TestFlushExposesLiveSession(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	w.Emit(context.Background(), audit.Event{Type: audit.EventSessionStart, Session: "live"})
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "live.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "session_start") {
		t.Error("Flush did not push the buffered event to disk")
	}
}

// Close seals sessions that never sent a terminal event (gateway shutdown).
func TestCloseSealsOpenSessions(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w.Emit(context.Background(), audit.Event{Type: audit.EventSessionStart, Session: "orphan"})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "orphan.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "session_start") {
		t.Error("Close did not flush the open session")
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestNewRejectsEmptyDir(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New(\"\") returned nil error")
	}
}

// New must create a missing directory tree rather than requiring setup.
func TestNewCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "wal")
	w, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("dir not created: %v", err)
	}
}

// syncBuf is a race-safe io.Writer for slog output.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
