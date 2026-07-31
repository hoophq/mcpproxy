// Command mcpproxyd is the standalone MCP gateway daemon: one process
// serving one or many MCP backends behind /mcp with inbound auth, policy
// checks, approvals, telemetry, and session recording.
//
// Usage:
//
//	mcpproxyd -config config.yaml
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hoophq/mcpproxy/approval"
	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/auth/authserver"
	"github.com/hoophq/mcpproxy/auth/inbound"
	"github.com/hoophq/mcpproxy/auth/outbound"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/optimizer"
	"github.com/hoophq/mcpproxy/telemetry"
	"github.com/hoophq/mcpproxy/wal"
)

// version is the released build's tag, set by the release build with
// -ldflags "-X main.version=vX.Y.Z". A build from source reports "dev".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	debug := flag.Bool("debug", false, "debug logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("mcpproxyd", version)
		return
	}

	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	if err := run(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- audit sinks --------------------------------------------------
	sinks := audit.MultiSink{newLogSink(log)}
	if cfg.WALDir != "" {
		w, err := wal.New(cfg.WALDir)
		if err != nil {
			return fmt.Errorf("wal: %w", err)
		}
		sinks = append(sinks, w)
	}
	var sink audit.Sink = sinks

	// ---- telemetry ----------------------------------------------------
	tel, err := telemetry.New(cfg.Telemetry)
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(sctx)
	}()

	// ---- embedded auth server (optional) -------------------------------
	var authSrv *authserver.Server
	if cfg.AuthServer != nil {
		var fed authserver.UpstreamFederator
		if cfg.AuthServer.Upstream != nil {
			fed, err = authserver.NewOIDCFederator(ctx, *cfg.AuthServer.Upstream,
				cfg.AuthServer.Issuer+"/callback", nil)
			if err != nil {
				return fmt.Errorf("auth server upstream: %w", err)
			}
		}
		authSrv, err = authserver.New(*cfg.AuthServer, fed)
		if err != nil {
			return fmt.Errorf("auth server: %w", err)
		}
	}

	// ---- inbound auth ---------------------------------------------------
	resolver, err := buildResolver(cfg, authSrv)
	if err != nil {
		return fmt.Errorf("inbound auth: %w", err)
	}

	// ---- outbound auth + backends ---------------------------------------
	tokenDeps, err := buildOutboundDeps(cfg, authSrv, log)
	if err != nil {
		return fmt.Errorf("outbound auth: %w", err)
	}
	factories := map[string]backend.Factory{}
	for name, bcfg := range cfg.Backends {
		ts, err := outbound.Resolve(ctx, name, bcfg, tokenDeps)
		if err != nil {
			return fmt.Errorf("backend %s auth: %w", name, err)
		}
		factories[name] = backend.NewFactory(name, bcfg, ts)
	}

	// ---- approvals -------------------------------------------------------
	heldStore := approval.New(cfg.Approvals.Timeout, sink)

	// ---- pipeline ---------------------------------------------------------
	hooks := inspect.Hooks{} // standalone: guardrails/redaction via future plugins
	pipeline := checks.Assemble(cfg.Policy, hooks, sink, true)
	if cfg.Optimizer != nil && cfg.Optimizer.TopK > 0 {
		pipeline = append(pipeline, optimizer.New(*cfg.Optimizer, sink, nil))
	}

	// ---- gateway ----------------------------------------------------------
	gw, err := gateway.New(gateway.Options{
		Backends: factories,
		Pipeline: pipeline,
		Resolver: resolver,
		Sink:     sink,
		Held:     heldStore,
		Observer: tel,
		Logger:   log,
	})
	if err != nil {
		return err
	}
	defer gw.Close()

	// ---- HTTP mux -----------------------------------------------------------
	mux := http.NewServeMux()
	mux.Handle("/mcp", gw.Handler())
	mux.Handle("/approvals/", http.StripPrefix("/approvals",
		approval.NewAPI(heldStore, cfg.Approvals.APIToken)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if h := tel.Handler(); h != nil && cfg.Telemetry.PrometheusPath != "" {
		mux.Handle(cfg.Telemetry.PrometheusPath, h)
	}
	if authSrv != nil {
		mux.Handle("/.well-known/", authSrv.Routes())
		mux.Handle("/authorize", authSrv.Routes())
		mux.Handle("/token", authSrv.Routes())
		mux.Handle("/register", authSrv.Routes())
		mux.Handle("/callback", authSrv.Routes())
	} else if cfg.Inbound.Mode == "oidc" {
		// Serve RFC 9728 protected-resource metadata pointing at the
		// external issuer, so MCP clients can discover where to
		// authenticate.
		mux.Handle("/.well-known/oauth-protected-resource",
			inbound.WellKnownHandler("http://"+cfg.Listen, cfg.Inbound.Issuer))
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("mcpproxyd listening", "addr", cfg.Listen, "backends", len(cfg.Backends))

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// buildResolver wires inbound auth. An embedded auth server validates its
// own tokens; otherwise the configured inbound mode decides.
func buildResolver(cfg *config.Config, authSrv *authserver.Server) (gateway.IdentityResolver, error) {
	if authSrv != nil {
		return func(r *http.Request) (inspect.Identity, error) {
			tok := bearerToken(r)
			if tok == "" {
				return inspect.Identity{}, fmt.Errorf("missing bearer token")
			}
			return authSrv.ValidateToken(r.Context(), tok)
		}, nil
	}
	res, err := inbound.New(cfg.Inbound)
	if err != nil {
		return nil, err
	}
	// Stash the raw bearer and the upstream passthrough header in the
	// context for outbound passthrough and exchange sources.
	return func(r *http.Request) (inspect.Identity, error) {
		id, err := res(r)
		if err != nil {
			return id, err
		}
		ctx := r.Context()
		if up := r.Header.Get(outbound.UpstreamAuthHeader); up != "" {
			ctx = outbound.WithClientToken(ctx, up)
		}
		if tok := bearerToken(r); tok != "" {
			ctx = outbound.WithInboundToken(ctx, tok)
		}
		ctx = outbound.WithUser(ctx, id.Subject)
		*r = *r.WithContext(ctx)
		return id, nil
	}, nil
}

func buildOutboundDeps(cfg *config.Config, authSrv *authserver.Server, log *slog.Logger) (outbound.Deps, error) {
	stateDir := os.Getenv("MCPPROXY_STATE_DIR")
	if stateDir == "" {
		home, _ := os.UserHomeDir()
		stateDir = home + "/.mcpproxy"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return outbound.Deps{}, err
	}
	store, err := outbound.NewFileStore(stateDir+"/tokens.enc", stateDir+"/tokens.key")
	if err != nil {
		return outbound.Deps{}, err
	}
	deps := outbound.Deps{
		Store:      store,
		Authorizer: outbound.NewLoopbackAuthorizer(log),
	}
	if authSrv != nil {
		deps.UpstreamSwap = authserver.NewUpstreamSwapSource(authSrv)
	}
	return deps, nil
}

func bearerToken(r *http.Request) string {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

// logSink logs audit events as structured slog records.
type logSink struct{ log *slog.Logger }

func newLogSink(log *slog.Logger) audit.Sink { return &logSink{log: log} }

func (s *logSink) Emit(_ context.Context, ev audit.Event) {
	attrs := []any{"sid", ev.Session}
	if ev.User != "" {
		attrs = append(attrs, "user", ev.User)
	}
	if ev.Backend != "" {
		attrs = append(attrs, "backend", ev.Backend)
	}
	if ev.Tool != "" {
		attrs = append(attrs, "tool", ev.Tool)
	}
	if ev.Rule != "" {
		attrs = append(attrs, "rule", ev.Rule)
	}
	if ev.Reason != "" {
		attrs = append(attrs, "reason", ev.Reason)
	}
	for k, v := range ev.Fields {
		attrs = append(attrs, k, v)
	}
	s.log.Info(string(ev.Type), attrs...)
}
