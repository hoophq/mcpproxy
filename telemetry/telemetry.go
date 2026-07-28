// Package telemetry implements the gateway's observability seam: a
// Prometheus registry for per-message counters/histograms and an optional
// OTLP trace exporter. It satisfies gateway.Observer structurally, so the
// gateway never imports this package.
//
// Everything here is nil-safe by construction. A zero config yields a
// Telemetry whose ObserveMessage costs a nil check and whose Handler is nil,
// so a caller wires telemetry once and lets configuration decide whether
// anything gets recorded.
package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
)

// defaultServiceName labels traces when the config omits a name.
const defaultServiceName = "mcpproxy"

// durationBuckets span sub-millisecond policy decisions through slow remote
// backends. The pipeline itself lands in the first three buckets; tool calls
// land in the tail.
var durationBuckets = []float64{
	.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30,
}

// Telemetry records per-message metrics and (optionally) traces. The zero
// value and a nil pointer are both usable no-ops.
type Telemetry struct {
	registry *prometheus.Registry
	path     string

	messages *prometheus.CounterVec
	duration *prometheus.HistogramVec
	sessions prometheus.Gauge

	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer
}

// New builds telemetry from config. cfg.PrometheusPath enables metrics and
// cfg.OTLPEndpoint enables tracing; either, both, or neither may be set. The
// OTLP exporter connects in the background, so New never blocks on an
// unreachable collector.
func New(cfg config.Telemetry) (*Telemetry, error) {
	t := &Telemetry{path: cfg.PrometheusPath}

	if cfg.PrometheusPath != "" {
		t.registry = prometheus.NewRegistry()
		t.messages = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpproxy_messages_total",
			Help: "JSON-RPC messages processed by the gateway, by pipeline decision.",
		}, []string{"direction", "backend", "method", "tool", "decision"})
		t.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "mcpproxy_message_duration_seconds",
			Help:    "Time spent in the inspection pipeline per message.",
			Buckets: durationBuckets,
		}, []string{"direction", "backend", "method"})
		t.sessions = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpproxy_sessions_active",
			Help: "Currently open MCP sessions.",
		})
		for _, c := range []prometheus.Collector{t.messages, t.duration, t.sessions} {
			if err := t.registry.Register(c); err != nil {
				return nil, fmt.Errorf("register metric: %w", err)
			}
		}
	}

	if cfg.OTLPEndpoint != "" {
		service := cfg.ServiceName
		if service == "" {
			service = defaultServiceName
		}
		// WithDialOption stays out: the exporter reconnects on its own and
		// NewClient does not dial eagerly, so a down collector costs dropped
		// spans instead of a failed startup.
		exp, err := otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("otlp trace exporter: %w", err)
		}
		res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
			attribute.String("service.name", service),
		))
		if err != nil {
			// Schema conflicts only. Fall back to the bare service resource
			// instead of dropping tracing.
			res = resource.NewSchemaless(attribute.String("service.name", service))
		}
		t.tracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
		t.tracer = t.tracerProvider.Tracer("github.com/hoophq/mcpproxy")
	}

	return t, nil
}

// Path is the HTTP path the caller should mount Handler at, or "" when
// metrics are disabled.
func (t *Telemetry) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

// Handler serves the Prometheus exposition format, or nil when metrics are
// disabled. Callers must nil-check before mounting.
func (t *Telemetry) Handler() http.Handler {
	if t == nil || t.registry == nil {
		return nil
	}
	return promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{Registry: t.registry})
}

// Registry exposes the underlying registry so a host process can add its own
// collectors. Nil when metrics are disabled.
func (t *Telemetry) Registry() *prometheus.Registry {
	if t == nil {
		return nil
	}
	return t.registry
}

// ObserveMessage implements gateway.Observer: one call per message that
// completed the inspection pipeline.
//
// The tool label sits on the counter alone. Tool names come from remote
// servers, so their cardinality is unbounded, and multiplying them by the
// bucket count would explode the series the registry holds. The histogram
// keeps direction, backend and method.
func (t *Telemetry) ObserveMessage(dir inspect.Direction, backendName, method, tool, decision string, dur time.Duration) {
	if t == nil {
		return
	}
	d := dir.String()
	if t.messages != nil {
		t.messages.WithLabelValues(d, backendName, method, tool, decision).Inc()
		t.duration.WithLabelValues(d, backendName, method).Observe(dur.Seconds())
	}
	if t.tracer != nil {
		// One span per message, back-dated to the pipeline entry so the span
		// duration equals the measured latency. v1 keeps spans flat: no
		// ambient request context exists to parent them to, and a flat span
		// with good attributes beats a fabricated hierarchy.
		end := time.Now()
		_, span := t.tracer.Start(context.Background(), "mcp."+methodOrMessage(method),
			trace.WithTimestamp(end.Add(-dur)),
			trace.WithAttributes(
				attribute.String("mcp.direction", d),
				attribute.String("mcp.backend", backendName),
				attribute.String("mcp.method", method),
				attribute.String("mcp.tool", tool),
				attribute.String("mcp.decision", decision),
			),
		)
		span.End(trace.WithTimestamp(end))
	}
}

func methodOrMessage(method string) string {
	if method == "" {
		return "response"
	}
	return method
}

// SessionStarted increments the active-session gauge.
func (t *Telemetry) SessionStarted() {
	if t == nil || t.sessions == nil {
		return
	}
	t.sessions.Inc()
}

// SessionEnded decrements the active-session gauge.
func (t *Telemetry) SessionEnded() {
	if t == nil || t.sessions == nil {
		return
	}
	t.sessions.Dec()
}

// Shutdown flushes pending spans and releases the exporter. Safe on a nil or
// trace-less Telemetry.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil || t.tracerProvider == nil {
		return nil
	}
	if err := t.tracerProvider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown tracer provider: %w", err)
	}
	return nil
}
