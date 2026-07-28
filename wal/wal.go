// Package wal persists the audit stream as one append-only JSONL file per
// MCP session, giving post-hoc session review a durable record even if the
// gateway crashes mid-session.
//
// It is an audit.Sink, so it inherits that contract: Emit must be safe for
// concurrent use and must not block. Writes go through a buffered writer
// under a per-session mutex. The WAL flushes and fsyncs that buffer once,
// when the session terminates, which is the only point where losing the tail
// costs anything and the only way to avoid an fsync per event.
package wal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hoophq/mcpproxy/audit"
)

// writeBufSize is large relative to a typical event of a few hundred bytes,
// so a busy session hits the write syscall rarely.
const writeBufSize = 32 * 1024

// maxSealed bounds the tombstone set for finished sessions. Each tombstone
// costs one session id and stops a late event from resurrecting a sealed
// record. Forgetting the oldest ones after this many sessions is safe:
// an event arriving that late signals a bug elsewhere.
const maxSealed = 4096

// WAL is a session-partitioned append-only audit log. The zero value is not
// usable; call New.
type WAL struct {
	dir string
	log *slog.Logger

	mu    sync.Mutex
	files map[string]*sessionFile
	// sealed marks sessions whose file the WAL has fsync'd and closed, with
	// sealedFIFO giving eviction order.
	sealed     map[string]struct{}
	sealedFIFO []string
}

// sessionFile owns one <sid>.jsonl. Its own mutex keeps two sessions from
// contending with each other; a session contends only with itself.
type sessionFile struct {
	mu     sync.Mutex
	f      *os.File
	w      *bufio.Writer
	closed bool
	// warned suppresses repeat log spam: a broken file stays broken, and one
	// warning per session carries the signal. Atomic because the marshal
	// failure path reports without holding mu.
	warned atomic.Bool
}

// New creates (or reuses) dir and returns a WAL rooted there.
func New(dir string) (*WAL, error) {
	if dir == "" {
		return nil, fmt.Errorf("wal: dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("wal: create dir %s: %w", dir, err)
	}
	return &WAL{
		dir:    dir,
		log:    slog.Default(),
		files:  make(map[string]*sessionFile),
		sealed: make(map[string]struct{}),
	}, nil
}

// WithLogger overrides the logger used for write-failure warnings.
func (w *WAL) WithLogger(l *slog.Logger) *WAL {
	if l != nil {
		w.log = l
	}
	return w
}

// Emit appends ev to its session's file, opening the file on first use. On a
// terminal event (session_end / session_killed) it flushes, fsyncs, and
// closes. Emit drops events carrying no session id, since they belong to no
// file.
//
// Emit never panics and never returns an error. It logs failures once per
// session, so auditing cannot take down the gateway.
func (w *WAL) Emit(_ context.Context, ev audit.Event) {
	if ev.Session == "" {
		return
	}
	sf, ok, err := w.fileFor(ev.Session)
	if err != nil {
		w.warnOnce(nil, ev.Session, err)
		return
	}
	if !ok {
		// The session already ended; its record is sealed.
		return
	}

	line, err := json.Marshal(ev)
	if err != nil {
		w.warnOnce(sf, ev.Session, fmt.Errorf("marshal event: %w", err))
		return
	}

	terminal := ev.Type == audit.EventSessionEnd || ev.Type == audit.EventSessionKilled

	sf.mu.Lock()
	defer sf.mu.Unlock()
	if sf.closed {
		// Raced with the terminal event on another goroutine. That record
		// is fsync'd and must not grow.
		return
	}
	// Two writes rather than append(line, '\n'): bufio copies into its own
	// buffer either way, so the append would add one reallocation.
	if _, err := sf.w.Write(line); err != nil {
		w.warnOnce(sf, ev.Session, fmt.Errorf("write event: %w", err))
		return
	}
	if err := sf.w.WriteByte('\n'); err != nil {
		w.warnOnce(sf, ev.Session, fmt.Errorf("write event: %w", err))
		return
	}
	if terminal {
		if err := sf.closeLocked(); err != nil {
			w.warnOnce(sf, ev.Session, err)
		}
		w.seal(ev.Session)
	}
}

// fileFor returns the session's file handle, opening it on first use. It
// returns ok=false for a session that has already been sealed.
func (w *WAL) fileFor(sid string) (*sessionFile, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, done := w.sealed[sid]; done {
		return nil, false, nil
	}
	if sf, ok := w.files[sid]; ok {
		return sf, true, nil
	}
	path, err := w.pathFor(sid)
	if err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open session log: %w", err)
	}
	sf := &sessionFile{f: f, w: bufio.NewWriterSize(f, writeBufSize)}
	w.files[sid] = sf
	return sf, true, nil
}

// seal releases the session's handle and tombstones the id, so a late event
// gets dropped instead of reopening a completed record.
func (w *WAL) seal(sid string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.files, sid)
	if _, ok := w.sealed[sid]; ok {
		return
	}
	w.sealed[sid] = struct{}{}
	w.sealedFIFO = append(w.sealedFIFO, sid)
	if len(w.sealedFIFO) > maxSealed {
		delete(w.sealed, w.sealedFIFO[0])
		w.sealedFIFO = w.sealedFIFO[1:]
	}
}

// closeLocked flushes, fsyncs, and closes. Caller holds sf.mu.
func (sf *sessionFile) closeLocked() error {
	if sf.closed {
		return nil
	}
	sf.closed = true
	var firstErr error
	if err := sf.w.Flush(); err != nil {
		firstErr = fmt.Errorf("flush session log: %w", err)
	}
	if err := sf.f.Sync(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("fsync session log: %w", err)
	}
	if err := sf.f.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("close session log: %w", err)
	}
	return firstErr
}

// warnOnce logs at most one warning per session file. sf may be nil when the
// failure predates a handle. Those are open and validation failures rather
// than a stuck write loop, so warnOnce logs every one of them.
func (w *WAL) warnOnce(sf *sessionFile, sid string, err error) {
	if sf != nil && !sf.warned.CompareAndSwap(false, true) {
		return
	}
	w.log.Warn("wal write failed", "sid", sid, "err", err)
}

// Close flushes and closes every open session file. Calling it while sessions
// are still live is safe; those sessions stop being recorded.
func (w *WAL) Close() error {
	w.mu.Lock()
	files := w.files
	w.files = make(map[string]*sessionFile)
	w.mu.Unlock()

	var firstErr error
	for sid, sf := range files {
		sf.mu.Lock()
		err := sf.closeLocked()
		sf.mu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("session %s: %w", sid, err)
		}
	}
	return firstErr
}

// Flush pushes buffered bytes for every open session to the OS without
// closing, which lets a caller tail an in-progress session.
func (w *WAL) Flush() error {
	w.mu.Lock()
	files := make([]*sessionFile, 0, len(w.files))
	for _, sf := range w.files {
		files = append(files, sf)
	}
	w.mu.Unlock()

	var firstErr error
	for _, sf := range files {
		sf.mu.Lock()
		if !sf.closed {
			if err := sf.w.Flush(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("flush: %w", err)
			}
		}
		sf.mu.Unlock()
	}
	return firstErr
}

// Replay reads a session's recorded events back in order. Buffered bytes for
// a still-open session are flushed first so a live session replays whole.
func (w *WAL) Replay(sid string) ([]audit.Event, error) {
	path, err := w.pathFor(sid)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	sf := w.files[sid]
	w.mu.Unlock()
	if sf != nil {
		sf.mu.Lock()
		if !sf.closed {
			_ = sf.w.Flush()
		}
		sf.mu.Unlock()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wal: replay session %s: %w", sid, err)
	}

	var events []audit.Event
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("wal: session %s line %d: %w", sid, i+1, err)
		}
		events = append(events, ev)
	}
	return events, nil
}

// Sessions lists the session ids with a recorded log.
func (w *WAL) Sessions() ([]string, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("wal: list sessions: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name, ok := strings.CutSuffix(e.Name(), ".jsonl"); ok {
			out = append(out, name)
		}
	}
	return out, nil
}

// pathFor maps a session id to its file, rejecting ids that would escape the
// directory. Session ids arrive over the wire in the Mcp-Session-Id header,
// so this check guards a trust boundary.
func (w *WAL) pathFor(sid string) (string, error) {
	if sid == "" || sid == "." || sid == ".." ||
		strings.ContainsAny(sid, `/\`) || strings.ContainsRune(sid, 0) {
		return "", fmt.Errorf("wal: invalid session id %q", sid)
	}
	return filepath.Join(w.dir, sid+".jsonl"), nil
}
