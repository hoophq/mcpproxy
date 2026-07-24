package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
)

// observer mirrors gateway.Observer. Restating it here rather than importing
// gateway keeps the dependency arrow one-way (gateway does not import
// telemetry, and telemetry must not import gateway) while still failing the
// build if the method signature ever drifts.
type observer interface {
	ObserveMessage(dir inspect.Direction, backendName, method, tool, decision string, dur time.Duration)
}

var _ observer = (*Telemetry)(nil)

func metricsEnabled(t *testing.T) *Telemetry {
	t.Helper()
	tel, err := New(config.Telemetry{PrometheusPath: "/metrics"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tel
}

// gather finds a metric family by name and returns its metrics.
func gather(t *testing.T, tel *Telemetry, name string) []*dto.Metric {
	t.Helper()
	families, err := tel.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.GetMetric()
		}
	}
	return nil
}

// labelsOf flattens a metric's label pairs for comparison.
func labelsOf(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, l := range m.GetLabel() {
		out[l.GetName()] = l.GetValue()
	}
	return out
}

func TestObserveMessageCounts(t *testing.T) {
	tel := metricsEnabled(t)

	tel.ObserveMessage(inspect.C2S, "github", "tools/call", "list_issues", "allow", 12*time.Millisecond)
	tel.ObserveMessage(inspect.C2S, "github", "tools/call", "list_issues", "allow", 8*time.Millisecond)
	tel.ObserveMessage(inspect.S2C, "github", "tools/call", "list_issues", "deny", 1*time.Millisecond)

	metrics := gather(t, tel, "mcpproxy_messages_total")
	if len(metrics) != 2 {
		t.Fatalf("messages_total series = %d, want 2 (allow+deny)", len(metrics))
	}

	got := map[string]float64{}
	for _, m := range metrics {
		l := labelsOf(m)
		got[l["direction"]+"/"+l["decision"]] = m.GetCounter().GetValue()
	}
	if got["c2s/allow"] != 2 {
		t.Errorf("c2s/allow = %v, want 2", got["c2s/allow"])
	}
	if got["s2c/deny"] != 1 {
		t.Errorf("s2c/deny = %v, want 1", got["s2c/deny"])
	}

	// Labels must carry every dimension the gateway passes.
	want := map[string]string{
		"direction": "c2s", "backend": "github", "method": "tools/call",
		"tool": "list_issues", "decision": "allow",
	}
	var found bool
	for _, m := range metrics {
		l := labelsOf(m)
		if l["decision"] != "allow" {
			continue
		}
		found = true
		for k, v := range want {
			if l[k] != v {
				t.Errorf("label %s = %q, want %q", k, l[k], v)
			}
		}
	}
	if !found {
		t.Fatal("no allow series found")
	}
}

func TestObserveMessageDuration(t *testing.T) {
	tel := metricsEnabled(t)

	// Two calls differing only in the tool label must land in one histogram
	// series: tool is excluded from the histogram on purpose.
	tel.ObserveMessage(inspect.C2S, "github", "tools/call", "list_issues", "allow", 20*time.Millisecond)
	tel.ObserveMessage(inspect.C2S, "github", "tools/call", "create_pr", "allow", 30*time.Millisecond)

	metrics := gather(t, tel, "mcpproxy_message_duration_seconds")
	if len(metrics) != 1 {
		t.Fatalf("duration series = %d, want 1 (tool must not be a histogram label)", len(metrics))
	}
	h := metrics[0].GetHistogram()
	if h.GetSampleCount() != 2 {
		t.Errorf("sample count = %d, want 2", h.GetSampleCount())
	}
	if sum := h.GetSampleSum(); sum < 0.049 || sum > 0.051 {
		t.Errorf("sample sum = %v, want ~0.05", sum)
	}
	if l := labelsOf(metrics[0]); l["tool"] != "" {
		t.Errorf("histogram has tool label %q, want none", l["tool"])
	}
}

func TestSessionGauge(t *testing.T) {
	tel := metricsEnabled(t)

	value := func() float64 {
		m := gather(t, tel, "mcpproxy_sessions_active")
		if len(m) != 1 {
			t.Fatalf("sessions_active series = %d, want 1", len(m))
		}
		return m[0].GetGauge().GetValue()
	}

	if v := value(); v != 0 {
		t.Fatalf("initial gauge = %v, want 0", v)
	}
	tel.SessionStarted()
	tel.SessionStarted()
	if v := value(); v != 2 {
		t.Errorf("after 2 starts = %v, want 2", v)
	}
	tel.SessionEnded()
	if v := value(); v != 1 {
		t.Errorf("after 1 end = %v, want 1", v)
	}
}

func TestHandlerServesMetrics(t *testing.T) {
	tel := metricsEnabled(t)
	tel.ObserveMessage(inspect.C2S, "github", "tools/list", "", "allow", time.Millisecond)

	h := tel.Handler()
	if h == nil {
		t.Fatal("Handler is nil with PrometheusPath set")
	}
	if got := tel.Path(); got != "/metrics" {
		t.Errorf("Path = %q, want /metrics", got)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"mcpproxy_messages_total",
		"mcpproxy_message_duration_seconds",
		"mcpproxy_sessions_active",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %s", want)
		}
	}
}

// A zero config must produce something that is safe to wire everywhere.
func TestNoopSafety(t *testing.T) {
	tel, err := New(config.Telemetry{})
	if err != nil {
		t.Fatalf("New(zero): %v", err)
	}
	if tel == nil {
		t.Fatal("New(zero) returned nil Telemetry; callers would lose the Observer")
	}
	if tel.Handler() != nil {
		t.Error("Handler non-nil without PrometheusPath")
	}
	if tel.Registry() != nil {
		t.Error("Registry non-nil without PrometheusPath")
	}
	if tel.Path() != "" {
		t.Error("Path non-empty without PrometheusPath")
	}

	// None of these may panic.
	tel.ObserveMessage(inspect.C2S, "b", "m", "t", "allow", time.Second)
	tel.SessionStarted()
	tel.SessionEnded()
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// A nil *Telemetry is a valid Observer: hosts that skip telemetry entirely
// pass nil rather than branching at every call site.
func TestNilReceiverSafety(t *testing.T) {
	var tel *Telemetry
	tel.ObserveMessage(inspect.S2C, "b", "m", "t", "kill", time.Second)
	tel.SessionStarted()
	tel.SessionEnded()
	if tel.Handler() != nil {
		t.Error("nil Handler non-nil")
	}
	if tel.Registry() != nil {
		t.Error("nil Registry non-nil")
	}
	if tel.Path() != "" {
		t.Error("nil Path non-empty")
	}
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Errorf("nil Shutdown: %v", err)
	}
}

func TestConcurrentObserve(t *testing.T) {
	tel := metricsEnabled(t)

	const workers, each = 8, 50
	done := make(chan struct{})
	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for range each {
				tel.ObserveMessage(inspect.C2S, "b", "tools/call", "t", "allow", time.Millisecond)
				tel.SessionStarted()
				tel.SessionEnded()
			}
		}()
	}
	for range workers {
		<-done
	}

	m := gather(t, tel, "mcpproxy_messages_total")
	if len(m) != 1 {
		t.Fatalf("series = %d, want 1", len(m))
	}
	if got, want := m[0].GetCounter().GetValue(), float64(workers*each); got != want {
		t.Errorf("count = %v, want %v", got, want)
	}
}

// Tracing is configured independently of metrics. With only OTLP set there
// must be no metrics handler, observation must still work, and — since the
// collector here is unreachable — Shutdown must stay bounded by the caller's
// context instead of retrying forever.
func TestTracingOnly(t *testing.T) {
	start := time.Now()
	tel, err := New(config.Telemetry{OTLPEndpoint: "127.0.0.1:1", ServiceName: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// New must not dial: an unreachable collector cannot delay startup.
	if d := time.Since(start); d > time.Second {
		t.Errorf("New blocked for %v on an unreachable collector", d)
	}
	if tel.Handler() != nil {
		t.Error("Handler non-nil without PrometheusPath")
	}
	if tel.Registry() != nil {
		t.Error("Registry non-nil without PrometheusPath")
	}
	// Spans go to a batcher; this must not block or panic.
	tel.ObserveMessage(inspect.C2S, "b", "tools/call", "t", "allow", time.Millisecond)

	deadline := 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	start = time.Now()
	// The error is expected (nothing is listening); the contract under test
	// is that Shutdown honors the deadline rather than hanging the process.
	_ = tel.Shutdown(ctx)
	if d := time.Since(start); d > deadline+2*time.Second {
		t.Errorf("Shutdown took %v, want it bounded by the %v context", d, deadline)
	}

	// Shutdown is idempotent: a second call must not panic or block.
	if err := tel.Shutdown(context.Background()); err == nil {
		t.Log("second Shutdown returned nil")
	}
}
