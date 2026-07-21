package backend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/config"
)

// TestRemoteConcurrentSendClose hammers the seam the inflight counter
// defends: a Send that already passed the closed check must finish delivering
// without ever writing to a closed recv channel. The only outcomes allowed
// are success and ErrClosed — Close does not abort requests already issued.
// Run with -race; a regression panics or trips the detector.
func TestRemoteConcurrentSendClose(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer hs.Close()

	for range 20 {
		b := NewRemote("racy", config.Backend{Transport: TransportStreamableHTTP, URL: hs.URL}, nil)
		if err := b.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		// Keep draining so senders never park on a full buffer.
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for range b.Recv() {
			}
		}()

		var senders sync.WaitGroup
		for range 8 {
			senders.Add(1)
			go func() {
				defer senders.Done()
				err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
				if err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("Send = %v, want nil or ErrClosed", err)
				}
			}()
		}
		time.Sleep(time.Millisecond)
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		senders.Wait()
		<-drained
	}
}
