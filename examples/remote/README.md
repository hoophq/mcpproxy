# Remote MCP servers

Known publicly hosted MCP endpoints and how to configure them as mcpproxy
backends. Grouped by outbound auth mode; ready-to-run configs sit next to
this file.

Notes before you pick one:

- mcpproxy's remote backend speaks **streamable-HTTP** (`POST /mcp`, JSON or
  SSE responses). Endpoints listed as *SSE transport* use the older
  `GET /sse` + `POST /messages` protocol and are NOT supported yet — they're
  listed for completeness and marked ⚠.
- `auth: oauth` endpoints run discovery + dynamic client registration +
  PKCE; the daemon prints the authorize URL on first use. Many of these
  providers also issue static tokens (PATs) usable with `auth: static`.
- URLs change; verify against the provider's docs if a probe returns 404.

## No auth required

| Provider | URL | Notes |
|---|---|---|
| DeepWiki | `https://mcp.deepwiki.com/mcp` | GitHub repo Q&A |
| Cloudflare Docs | `https://docs.mcp.cloudflare.com/sse` | ⚠ SSE transport |
| Hugging Face | `https://huggingface.co/mcp` | anonymous works; HF token adds private access |

Config: [`no-auth.yaml`](no-auth.yaml)

## Static token / API key (`auth: static`)

| Provider | URL | Credential |
|---|---|---|
| Stripe | `https://mcp.stripe.com` | `Authorization: Bearer sk_…` (restricted API key) |
| Context7 | `https://mcp.context7.com/mcp` | `CONTEXT7_API_KEY` header per their docs |
| GitHub | `https://api.githubcopilot.com/mcp/` | `Authorization: Bearer <PAT>` (also supports OAuth) |
| Zapier | `https://mcp.zapier.com/api/mcp/mcp` | per-user endpoint token from Zapier dashboard |
| Hugging Face | `https://huggingface.co/mcp` | `Authorization: Bearer hf_…` |

Config: [`static-token.yaml`](static-token.yaml)

## OAuth (`auth: oauth` — discovery + DCR + PKCE)

| Provider | URL | Notes |
|---|---|---|
| Linear | `https://mcp.linear.app/mcp` | issues PATs too (static works) |
| Notion | `https://mcp.notion.com/mcp` | |
| Sentry | `https://mcp.sentry.dev/mcp` | |
| GitHub | `https://api.githubcopilot.com/mcp/` | OAuth or PAT |
| Neon | `https://mcp.neon.tech/sse` | ⚠ SSE transport |
| Atlassian (Jira/Confluence) | `https://mcp.atlassian.com/v1/sse` | ⚠ SSE transport |
| Asana | `https://mcp.asana.com/sse` | ⚠ SSE transport |
| Intercom | `https://mcp.intercom.com/sse` | ⚠ SSE transport |
| PayPal | `https://mcp.paypal.com/mcp` | |
| Square | `https://mcp.squareup.com/sse` | ⚠ SSE transport |
| Webflow | `https://mcp.webflow.com/sse` | ⚠ SSE transport |
| Cloudflare (bindings) | `https://bindings.mcp.cloudflare.com/sse` | ⚠ SSE transport |

Config: [`oauth.yaml`](oauth.yaml)

## Everything at once

[`aggregated.yaml`](aggregated.yaml) fronts several remotes behind one
endpoint with per-backend policy — the "one URL for the whole team" setup.

## Local-only impostors

Some well-known "MCP servers" are NOT remote endpoints despite marketing:
Figma's Dev Mode MCP runs locally inside the desktop app
(`http://127.0.0.1:3845/mcp` — configure it as a `streamable-http` backend
with that URL), and most community servers (filesystem, git, fetch…) are
stdio packages — see the top-level examples for those.
