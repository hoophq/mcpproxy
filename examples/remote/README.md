# Remote MCP servers

Known publicly hosted MCP endpoints and how to configure them as mcpproxy
backends, grouped by outbound auth mode. Ready-to-run configs sit next to
this file.

Before you pick one:

- Both remote transports work: **streamable-HTTP**
  (`transport: streamable-http`) and the legacy **HTTP+SSE** protocol
  (`transport: sse`). Entries marked ⚠ below need `transport: sse`.
- All of these ship in the built-in catalog ([`catalog/catalog.yaml`](../../catalog/catalog.yaml)):
  `import-catalog -list` shows them, `import-catalog linear stripe …`
  emits ready-made backend stanzas. `-catalog <file>` loads a custom YAML
  catalog with the same schema; `-dir <dir>` imports from a tree of
  MCP-registry `server.json` files.
- `auth: oauth` endpoints run discovery + dynamic client registration +
  PKCE; the daemon prints the authorize URL on first use. Many of these
  providers also issue static tokens (PATs) usable with `auth: static`.
- URLs change. Check the provider's docs if a probe returns 404.

## No auth required

| Provider | URL | Notes |
|---|---|---|
| DeepWiki | `https://mcp.deepwiki.com/mcp` | GitHub repo Q&A |
| Cloudflare Docs | `https://docs.mcp.cloudflare.com/sse` | ⚠ `transport: sse` |
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

## OAuth (`auth: oauth`, discovery + DCR + PKCE)

| Provider | URL | Notes |
|---|---|---|
| Linear | `https://mcp.linear.app/mcp` | issues PATs too (static works) |
| Notion | `https://mcp.notion.com/mcp` | |
| Sentry | `https://mcp.sentry.dev/mcp` | |
| GitHub | `https://api.githubcopilot.com/mcp/` | OAuth or PAT |
| Neon | `https://mcp.neon.tech/sse` | ⚠ `transport: sse` |
| Atlassian (Jira/Confluence) | `https://mcp.atlassian.com/v1/sse` | ⚠ `transport: sse` |
| Asana | `https://mcp.asana.com/sse` | ⚠ `transport: sse` |
| Intercom | `https://mcp.intercom.com/sse` | ⚠ `transport: sse` |
| PayPal | `https://mcp.paypal.com/mcp` | |
| Square | `https://mcp.squareup.com/sse` | ⚠ `transport: sse` |
| Webflow | `https://mcp.webflow.com/sse` | ⚠ `transport: sse` |
| Cloudflare (bindings) | `https://bindings.mcp.cloudflare.com/sse` | ⚠ `transport: sse` |

Config: [`oauth.yaml`](oauth.yaml)

## Everything at once

[`aggregated.yaml`](aggregated.yaml) fronts several remotes behind one
endpoint with per-backend policy, giving your team one URL for everything.

## Local-only impostors

Marketing calls some well-known projects "MCP servers" when they expose no
remote endpoint. Figma's Dev Mode MCP runs locally inside the desktop app,
so configure `http://127.0.0.1:3845/mcp` as a `streamable-http` backend.
Most community servers (filesystem, git, fetch…) ship as stdio packages;
see the top-level examples for those.
