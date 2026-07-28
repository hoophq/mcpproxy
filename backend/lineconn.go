package backend

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"
)

// maxLineBytes bounds one newline-delimited JSON-RPC message. Tool results
// (file dumps, base64 images) run to megabytes, so the 64 KiB bufio default
// truncates them; 16 MiB matches the gateway's inbound body limit.
const maxLineBytes = 16 << 20

// recvBuffer is the depth of the Recv channel. At this depth a burst of
// notifications does not stall the peer's stdout, and a wedged consumer
// applies backpressure instead of buffering without bound.
const recvBuffer = 64

// lineConn frames newline-delimited JSON-RPC over a byte stream: one message
// per line, tolerating CRLF. It is the transport half of StdioBackend, kept
// separate so tests can drive the framing over an in-process pipe without a
// subprocess in the way.
//
// send serializes writes and checks for short ones: a truncated envelope
// would desynchronize the peer's framing for the rest of the session.
type lineConn struct {
	name string
	log  *slog.Logger

	recv chan []byte
	// stop releases a pump blocked on a wedged consumer.
	stop chan struct{}

	wmu  sync.Mutex
	w    io.WriteCloser
	wbuf bytes.Buffer
	up   bool
}

func newLineConn(name string, log *slog.Logger) *lineConn {
	if log == nil {
		log = slog.Default()
	}
	return &lineConn{
		name: name,
		log:  log,
		recv: make(chan []byte, recvBuffer),
		stop: make(chan struct{}),
	}
}

// attach installs the write side. Until then, send reports ErrClosed.
func (c *lineConn) attach(w io.WriteCloser) {
	c.wmu.Lock()
	c.w = w
	c.up = true
	c.wmu.Unlock()
}

// pump reads framed messages from r and forwards them to recv. It returns
// when r hits EOF or stop closes.
func (c *lineConn) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Servers launched through npx/node print banners and progress
		// on stdout. A line that cannot open a JSON-RPC envelope is
		// diagnostics and must not reach the gateway.
		if line[0] != '{' && line[0] != '[' {
			c.log.Debug("backend non-json stdout", "backend", c.name, "line", string(line))
			continue
		}
		msg := make([]byte, len(line))
		copy(msg, line)
		select {
		case c.recv <- msg:
		case <-c.stop:
			return
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		c.log.Debug("backend stdout read", "backend", c.name, "err", err)
	}
}

// logLines drains a diagnostic stream (a child's stderr) to the debug log.
func (c *lineConn) logLines(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8*1024), maxLineBytes)
	for sc.Scan() {
		if line := bytes.TrimRight(sc.Bytes(), "\r"); len(line) > 0 {
			c.log.Debug("backend stderr", "backend", c.name, "line", string(line))
		}
	}
}

// send writes one message plus a trailing newline.
func (c *lineConn) send(msg []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.up {
		return ErrClosed
	}
	c.wbuf.Reset()
	c.wbuf.Grow(len(msg) + 1)
	c.wbuf.Write(bytes.TrimRight(msg, "\r\n"))
	c.wbuf.WriteByte('\n')
	out := c.wbuf.Bytes()
	n, err := c.w.Write(out)
	if err != nil {
		// A child that died on its own leaves EPIPE here, and a Send
		// racing Close sees ErrClosed/ErrClosedPipe. All three mean the
		// same thing to the gateway: the backend is gone.
		if errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EPIPE) {
			return ErrClosed
		}
		return err
	}
	if n != len(out) {
		return io.ErrShortWrite
	}
	return nil
}

// closeWrite sends EOF to the peer and makes further sends report ErrClosed.
func (c *lineConn) closeWrite() {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.up {
		return
	}
	c.up = false
	_ = c.w.Close()
}
