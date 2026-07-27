# Authentication architecture

Auth splits into three independent planes. You configure each one on its
own, and any combination is valid.

```
        plane 1: inbound              plane 2: outbound
client ──────────────▶ gateway ─────────────────▶ MCP server
                          │
                          └── plane 3: identity bridging
                              (embedded auth server, token exchange,
                               per-user grants, upstream swap)
```

## Plane 1: inbound (who may talk to the gateway)

`inbound.mode`, implemented in `auth/inbound`:

| Mode | Mechanism | Identity |
|---|---|---|
| `anonymous` | none | `anonymous` |
| `local` | none (trusts the host) | OS username |
| `static` | shared bearer token, constant-time compare | `static-token` |
| `oidc` | JWT against any OIDC issuer: discovery, remote JWKS (cached), exp/aud/scope checks | `sub`, email, all claims |
| `github` | token validated via GitHub API, optional org allowlist, 5-min cache | GitHub login |
| `awssts` | presigned `GetCallerIdentity` URL (validated then executed server-side), ARN→subject glob mappings | mapped subject |

Identity flows into every audit event, review, and per-user token grant.
Under `oidc`, the gateway also serves RFC 9728 protected-resource metadata
so MCP clients can discover the issuer.

Enabling `auth_server` replaces plane 1: the gateway then validates the
tokens it issued itself.

## Plane 2: outbound (how the gateway auths to MCP servers)

`backends.<name>.auth`, implemented in `auth/outbound`:

| Mode | Mechanism |
|---|---|
| `none` | no credential |
| `static` | fixed headers from config (API keys, PATs) |
| `passthrough` | caller supplies the upstream credential per request via `X-Mcpproxy-Upstream-Authorization`; gateway stores nothing |
| `oauth` | the full MCP authorization flow (below) |

### The OAuth flow

```
probe → 401 WWW-Authenticate ─▶ RFC 9728 resource metadata
                                  └▶ RFC 8414 AS metadata (OIDC fallback)
no client_id configured? ───────▶ RFC 7591 dynamic client registration
authorize (PKCE S256) ──────────▶ human approves in browser
                                  loopback listener catches the callback
token endpoint ─────────────────▶ access + refresh token
                                  stored AES-256-GCM, auto-refreshed
                                  (30s early margin, per-key singleflight)
```

Design points:

- Public clients send `client_id` in the body, never Basic auth. Strict
  OAuth 2.1 servers consume the single-use code while rejecting Basic.
- `invalid_grant` on refresh deletes the grant, forcing a human to
  re-authorize; a 5xx leaves it alone.
- The gateway tolerates an issuer mismatch between the metadata URL and
  the document, trusting the document's own issuer, because split-origin
  metadata exists in the wild.
- `oauth.per_user: true` keys grants by (backend, caller identity) rather
  than (backend), so each user authorizes once with their own account.
- `oauth.token_exchange: true` swaps the interactive flow for RFC 8693:
  the gateway exchanges the caller's inbound token for an upstream token
  at the IdP. That removes the browser step and adds a trust
  configuration on the IdP side.

Tokens and DCR registrations persist under `$MCPPROXY_STATE_DIR` (default
`~/.mcpproxy`), encrypted with a generated keyfile.

## Plane 3: the embedded authorization server

`auth_server`, implemented in `auth/authserver`. The gateway acts as an
OAuth 2.1 AS, letting MCP clients such as Claude Code and Cursor
authenticate without a pre-shared secret:

```
MCP client ─ 401 ─▶ /.well-known/oauth-authorization-server
           ─ RFC 7591 ─▶ /register            (dynamic client registration)
           ─ PKCE ─▶ /authorize ──▶ upstream IdP login (federation)
                     /callback ◀── IdP redirects back
           ─ code ─▶ /token  ──▶ ES256 access token + rotating refresh token
```

- **Without `upstream`**: `/authorize` auto-approves a local dev identity
  and logs a warning. Use this in development only.
- **With `upstream`**: login federates to the company IdP. The gateway
  extracts identity from the ID token, namespaces subjects as
  `<issuer>#<sub>`, and KEEPS the upstream tokens.
- **Upstream swap**: those stored upstream tokens can serve as outbound
  credentials (`authserver.NewUpstreamSwapSource`), so the MCP server sees
  the user's own identity. That gives you on-behalf-of access without
  RFC 8693.

Security posture: S256 PKCE mandatory, one-time codes (10-min TTL),
refresh rotation, exact redirect-URI matching, ES256 pinned to close
alg-confusion, and authorize errors rendered before redirect-URI
validation so the endpoint is not an open redirector. The server keeps
state in memory: a restart drops codes, refresh tokens, and upstream
tokens. The signing key persists only when you set `signing_key_file`.

## Choosing a setup

| Scenario | Configuration |
|---|---|
| local dev | inbound `anonymous`/`local`, outbound `static` |
| team gateway, IdP in place | inbound `oidc`, outbound `oauth` with `per_user` |
| MCP clients must self-onboard | `auth_server` with `upstream` federation |
| callers manage their own upstream tokens | outbound `passthrough` |
| headless service-to-service | inbound `oidc`, outbound `oauth` + `token_exchange` |
