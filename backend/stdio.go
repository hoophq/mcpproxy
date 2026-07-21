package backend

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// defaultShutdownGrace bounds each step of the shutdown escalation.
const defaultShutdownGrace = 3 * time.Second

// politeGrace caps how long Close waits for the child to notice stdin EOF
// before it starts sending signals.
const politeGrace = 250 * time.Millisecond

// StdioBackend runs an MCP server as a child process and speaks
// newline-delimited JSON-RPC over its stdin/stdout. The child's stderr is
// logged at debug level: MCP servers habitually use it for human-readable
// diagnostics that are not protocol traffic.
//
// The child is placed in its own process group so Close reaps the whole tree.
// That matters because the common launcher (`npx some-mcp-server`) forks a
// node grandchild which would otherwise survive and keep holding the pipes.
type StdioBackend struct {
	// ShutdownGrace bounds each step of Close's escalation (stdin EOF →
	// SIGTERM → SIGKILL). Zero means defaultShutdownGrace.
	ShutdownGrace time.Duration

	name string
	cfg  config.Backend
	log  *slog.Logger

	conn *lineConn
	done chan struct{}

	cmd    *exec.Cmd
	stdout *os.File // parent read end of the child's stdout
	stderr *os.File // parent read end of the child's stderr

	mu      sync.Mutex
	started bool // Start was called
	spawned bool // a child exists and a reaper goroutine is running
	closing bool // Close initiated: a nonzero exit status is expected
	err     error

	closeOnce sync.Once
	closeErr  error
}

// NewStdio builds an unstarted stdio backend. cfg.Command must be non-empty;
// cfg.Env is layered over the parent environment.
func NewStdio(name string, cfg config.Backend, log *slog.Logger) *StdioBackend {
	if log == nil {
		log = slog.Default()
	}
	return &StdioBackend{
		name: name,
		cfg:  cfg,
		log:  log,
		conn: newLineConn(name, log),
		done: make(chan struct{}),
	}
}

func (b *StdioBackend) Name() string { return b.name }

// Start spawns the child. Cancelling ctx terminates the whole process group.
func (b *StdioBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return fmt.Errorf("stdio backend %s: already started", b.name)
	}
	b.started = true
	b.mu.Unlock()

	if len(b.cfg.Command) == 0 {
		return fmt.Errorf("stdio backend %s: empty command", b.name)
	}

	cmd := exec.CommandContext(ctx, b.cfg.Command[0], b.cfg.Command[1:]...)
	cmd.Env = mergeEnv(os.Environ(), b.cfg.Env)
	setProcGroup(cmd)
	// The default CommandContext cancel kills only the direct child; take
	// the whole group down instead so grandchildren cannot linger.
	cmd.Cancel = func() error { return signalGroup(cmd, sigTerm) }

	// Own the pipes as plain os.Files rather than using cmd.StdoutPipe:
	// exec's Wait refuses to return until those pipes hit EOF, which
	// deadlocks whenever a grandchild inherits stdout and outlives the
	// child. With our own files we can Wait first, then unblock the
	// readers by closing the read ends ourselves.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("stdio backend %s: stdin pipe: %w", b.name, err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		closeAll(stdinR, stdinW)
		return fmt.Errorf("stdio backend %s: stdout pipe: %w", b.name, err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		closeAll(stdinR, stdinW, stdoutR, stdoutW)
		return fmt.Errorf("stdio backend %s: stderr pipe: %w", b.name, err)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdinR, stdoutW, stderrW

	if err := cmd.Start(); err != nil {
		closeAll(stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW)
		return fmt.Errorf("stdio backend %s: starting %q: %w", b.name, b.cfg.Command[0], err)
	}
	// The child owns its ends now; holding them in the parent would keep
	// the pipes alive past child exit and defeat EOF detection.
	closeAll(stdinR, stdoutW, stderrW)

	b.mu.Lock()
	b.cmd = cmd
	b.spawned = true
	b.mu.Unlock()
	b.stdout, b.stderr = stdoutR, stderrR
	b.conn.attach(stdinW)

	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); b.conn.pump(stdoutR) }()
	go func() { defer readers.Done(); b.conn.logLines(stderrR) }()

	go b.reap(cmd, &readers)
	return nil
}

// reap waits for the child, releases the readers, then closes Recv and Done
// in that order so no send can race the close.
func (b *StdioBackend) reap(cmd *exec.Cmd, readers *sync.WaitGroup) {
	waitErr := cmd.Wait()
	// The child is gone; any grandchild still holding the write ends is no
	// longer our problem, so force the readers to EOF.
	closeAll(b.stdout, b.stderr)
	readers.Wait()
	close(b.conn.recv)
	b.mu.Lock()
	// A nonzero status during Close is our own SIGTERM/SIGKILL, not a
	// fault worth reporting.
	if !b.closing && waitErr != nil {
		b.err = fmt.Errorf("stdio backend %s exited: %w", b.name, waitErr)
	}
	b.mu.Unlock()
	close(b.done)
}

// Send writes one JSON-RPC message to the child's stdin.
func (b *StdioBackend) Send(_ context.Context, msg []byte) error {
	select {
	case <-b.done:
		return ErrClosed
	default:
	}
	if err := b.conn.send(msg); err != nil {
		if err == ErrClosed {
			return err
		}
		return fmt.Errorf("stdio backend %s: write: %w", b.name, err)
	}
	return nil
}

func (b *StdioBackend) Recv() <-chan []byte { return b.conn.recv }

func (b *StdioBackend) Done() <-chan struct{} { return b.done }

func (b *StdioBackend) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// Close shuts the child down by escalating: EOF on stdin (the polite exit
// signal for stdio MCP servers), then SIGTERM to the process group, then
// SIGKILL. Signals target the group rather than the pid, so an `npx`
// launcher's node grandchild dies with it. Close blocks until the child is
// reaped and is safe to call repeatedly.
func (b *StdioBackend) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.shutdown() })
	return b.closeErr
}

func (b *StdioBackend) shutdown() error {
	b.mu.Lock()
	spawned := b.spawned
	b.closing = true
	b.mu.Unlock()
	if !spawned {
		// No child was ever created. Honour the Backend contract anyway
		// so callers blocked on Recv or Done are released.
		close(b.conn.stop)
		close(b.conn.recv)
		close(b.done)
		return nil
	}
	// Release a pump blocked on a consumer that stopped draining, so the
	// reaper can finish even if nobody reads Recv again.
	defer close(b.conn.stop)

	grace := b.ShutdownGrace
	if grace <= 0 {
		grace = defaultShutdownGrace
	}

	b.conn.closeWrite()
	// A server that honours stdin EOF exits at once; don't burn the full
	// grace here before escalating.
	if b.waitExit(min(grace, politeGrace)) {
		return nil
	}
	if err := signalGroup(b.cmd, sigTerm); err != nil {
		b.log.Debug("stdio backend term", "backend", b.name, "err", err)
	}
	if b.waitExit(grace) {
		return nil
	}
	if err := signalGroup(b.cmd, sigKill); err != nil {
		b.log.Debug("stdio backend kill", "backend", b.name, "err", err)
	}
	if b.waitExit(grace) {
		return nil
	}
	return fmt.Errorf("stdio backend %s: child did not exit after SIGKILL", b.name)
}

func (b *StdioBackend) waitExit(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-b.done:
		return true
	case <-t.C:
		return false
	}
}

// mergeEnv layers overrides onto base ("KEY=VALUE" entries). Later entries
// win in exec, so appending is enough.
func mergeEnv(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	out := make([]string, len(base), len(base)+len(overrides))
	copy(out, base)
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
