// Package config defines the gateway configuration schema (YAML for the
// standalone daemon; hoop later constructs these structs from connection
// opts).
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root gateway configuration.
type Config struct {
	Listen string `yaml:"listen"` // e.g. 127.0.0.1:8000

	// Inbound selects how callers authenticate to the gateway.
	Inbound Inbound `yaml:"inbound"`

	// Backends: one entry per MCP server. One backend = plain proxy;
	// several = aggregation (tools prefixed "<name>_").
	Backends map[string]Backend `yaml:"backends"`

	// Policy is the global policy; per-backend Policy overrides fields.
	Policy Policy `yaml:"policy"`

	// Approvals configures the hold-and-review workflow.
	Approvals Approvals `yaml:"approvals"`

	// Telemetry configures OTel/Prometheus.
	Telemetry Telemetry `yaml:"telemetry"`

	// WALDir enables session recording when set: one JSONL file per session.
	WALDir string `yaml:"wal_dir"`

	// AuthServer enables the embedded OAuth authorization server.
	AuthServer *AuthServer `yaml:"auth_server,omitempty"`

	// Optimizer enables semantic tool filtering.
	Optimizer *Optimizer `yaml:"optimizer,omitempty"`
}

// Inbound authentication modes.
type Inbound struct {
	// Mode: "anonymous" | "local" | "static" | "oidc" | "github" | "awssts".
	Mode string `yaml:"mode"`

	// Static bearer token (mode=static). Env expansion applies.
	Token string `yaml:"token,omitempty"`

	// OIDC settings (mode=oidc).
	Issuer   string   `yaml:"issuer,omitempty"`
	Audience string   `yaml:"audience,omitempty"`
	Scopes   []string `yaml:"scopes,omitempty"`

	// GitHub settings (mode=github): validate tokens against the GitHub API.
	GitHubAllowedOrgs []string `yaml:"github_allowed_orgs,omitempty"`

	// AWS STS settings (mode=awssts).
	AWSRoleMappings map[string]string `yaml:"aws_role_mappings,omitempty"` // role ARN pattern → subject
}

// Backend describes one MCP server.
type Backend struct {
	// Transport: "stdio" | "streamable-http".
	Transport string `yaml:"transport"`

	// stdio: command line to spawn. Env expansion applies to Env values.
	Command []string          `yaml:"command,omitempty"`
	Env     map[string]string `yaml:"env,omitempty"`

	// streamable-http: remote endpoint.
	URL     string            `yaml:"url,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`

	// Auth selects the outbound token source for remote backends:
	// "none" | "static" (Headers carry it) | "passthrough" | "oauth".
	Auth string `yaml:"auth,omitempty"`

	// OAuth holds manual OAuth client settings; empty fields are
	// auto-discovered (RFC 9728/8414) and DCR-registered (RFC 7591).
	OAuth *OAuthClient `yaml:"oauth,omitempty"`

	// Policy overrides global policy for this backend.
	Policy *Policy `yaml:"policy,omitempty"`
}

// OAuthClient is manual outbound OAuth configuration.
type OAuthClient struct {
	Issuer       string   `yaml:"issuer,omitempty"`
	ClientID     string   `yaml:"client_id,omitempty"`
	ClientSecret string   `yaml:"client_secret,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`
	// PerUser keys grants by (backend, user) instead of (backend).
	PerUser bool `yaml:"per_user,omitempty"`
	// TokenExchange enables RFC 8693: exchange the inbound subject token
	// for an upstream token instead of running an authorization flow.
	TokenExchange bool `yaml:"token_exchange,omitempty"`
}

// Policy is the inspection policy.
type Policy struct {
	AllowedTools []string `yaml:"allowed_tools,omitempty"` // globs; empty = all
	DeniedTools  []string `yaml:"denied_tools,omitempty"`  // globs; win over allow

	// ApprovalTools require human approval before execution (globs).
	ApprovalTools []string `yaml:"approval_tools,omitempty"`

	// BlockSampling / BlockElicitation gate server-initiated requests.
	// Default true (deny) — nil means unset, resolved to true.
	BlockSampling    *bool `yaml:"block_sampling,omitempty"`
	BlockElicitation *bool `yaml:"block_elicitation,omitempty"`

	// OnRugPull: "kill" (default) | "alert".
	OnRugPull string `yaml:"on_rug_pull,omitempty"`

	// Budgets. Zero = unlimited.
	MaxResultKB     int            `yaml:"max_result_kb,omitempty"`
	MaxCallsPerSess int            `yaml:"max_calls_per_session,omitempty"`
	ToolRateLimits  map[string]int `yaml:"tool_rate_limits,omitempty"` // tool glob → calls/min

	// Overrides rewrite the tool catalog.
	Overrides map[string]ToolOverride `yaml:"overrides,omitempty"` // tool name → override
}

// ToolOverride renames a tool and/or rewrites its description.
type ToolOverride struct {
	Name        string `yaml:"name,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Approvals configures the review workflow.
type Approvals struct {
	// Timeout for a pending approval; expiry denies the call. Default 5m.
	Timeout time.Duration `yaml:"timeout,omitempty"`
	// APIToken guards the resolution endpoints (env expansion applies).
	APIToken string `yaml:"api_token,omitempty"`
}

// Telemetry configures observability.
type Telemetry struct {
	// PrometheusPath exposes /metrics when set (e.g. "/metrics").
	PrometheusPath string `yaml:"prometheus_path,omitempty"`
	// OTLPEndpoint enables trace export when set (host:port, gRPC).
	OTLPEndpoint string `yaml:"otlp_endpoint,omitempty"`
	ServiceName  string `yaml:"service_name,omitempty"`
}

// AuthServer configures the embedded OAuth AS.
type AuthServer struct {
	Issuer string `yaml:"issuer"` // external URL of this gateway
	// Upstream federates login to a company IdP; empty = local users file.
	Upstream *OAuthClient `yaml:"upstream,omitempty"`
	// SigningKeyFile is a PEM EC/RSA key; generated if absent.
	SigningKeyFile string `yaml:"signing_key_file,omitempty"`
	// AccessTokenTTL default 1h.
	AccessTokenTTL time.Duration `yaml:"access_token_ttl,omitempty"`
}

// Optimizer configures semantic tool filtering.
type Optimizer struct {
	// TopK tools exposed per tools/list based on session purpose. 0 = off.
	TopK int `yaml:"top_k"`
	// Purpose is matched against tool name+description with the built-in
	// lexical scorer. (Embedding providers can be added behind the same
	// interface.)
	Purpose string `yaml:"purpose,omitempty"`
}

// Load reads and validates a YAML config, expanding ${ENV} references in
// string values.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	expanded := os.Expand(string(b), func(k string) string { return os.Getenv(k) })
	var c Config
	if err := yaml.Unmarshal([]byte(expanded), &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks structural invariants.
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8000"
	}
	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend is required")
	}
	for name, b := range c.Backends {
		switch b.Transport {
		case "stdio":
			if len(b.Command) == 0 {
				return fmt.Errorf("backend %q: stdio requires command", name)
			}
		case "streamable-http", "sse":
			if b.URL == "" {
				return fmt.Errorf("backend %q: %s requires url", name, b.Transport)
			}
		default:
			return fmt.Errorf("backend %q: unknown transport %q", name, b.Transport)
		}
	}
	switch c.Inbound.Mode {
	case "", "anonymous", "local", "static", "oidc", "github", "awssts":
	default:
		return fmt.Errorf("unknown inbound mode %q", c.Inbound.Mode)
	}
	if c.Inbound.Mode == "oidc" && c.Inbound.Issuer == "" {
		return fmt.Errorf("inbound oidc requires issuer")
	}
	if c.Inbound.Mode == "static" && c.Inbound.Token == "" {
		return fmt.Errorf("inbound static requires token")
	}
	if c.Approvals.Timeout == 0 {
		c.Approvals.Timeout = 5 * time.Minute
	}
	return nil
}

// EffectivePolicy merges the global policy with a backend override.
func (c *Config) EffectivePolicy(backend string) Policy {
	p := c.Policy
	b, ok := c.Backends[backend]
	if !ok || b.Policy == nil {
		return p
	}
	o := b.Policy
	if len(o.AllowedTools) > 0 {
		p.AllowedTools = o.AllowedTools
	}
	if len(o.DeniedTools) > 0 {
		p.DeniedTools = o.DeniedTools
	}
	if len(o.ApprovalTools) > 0 {
		p.ApprovalTools = o.ApprovalTools
	}
	if o.BlockSampling != nil {
		p.BlockSampling = o.BlockSampling
	}
	if o.BlockElicitation != nil {
		p.BlockElicitation = o.BlockElicitation
	}
	if o.OnRugPull != "" {
		p.OnRugPull = o.OnRugPull
	}
	if o.MaxResultKB != 0 {
		p.MaxResultKB = o.MaxResultKB
	}
	if o.MaxCallsPerSess != 0 {
		p.MaxCallsPerSess = o.MaxCallsPerSess
	}
	if len(o.ToolRateLimits) > 0 {
		p.ToolRateLimits = o.ToolRateLimits
	}
	if len(o.Overrides) > 0 {
		p.Overrides = o.Overrides
	}
	return p
}
