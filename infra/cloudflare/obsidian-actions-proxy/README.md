# Obsidian Actions Proxy Worker

Cloudflare Worker that sits in front of the vault API. Acts as the public entry point — filters paths and injects Cloudflare Access service token headers so requests can reach the CF Tunnel-protected upstream.

## Why this exists

The vault API upstream (`vaultapi.michaelkness.com`) is behind Cloudflare Access. Direct calls without a service token are blocked by CF Access. This Worker:

1. Filters to only allowed paths (returns 404 for everything else)
2. Injects `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers
3. Passes through the caller's `Authorization: Bearer <jwt>` header unchanged

The vault API then validates the JWT as usual.

## Request flow

```
Caller (MCP / curl) → Worker → CF Access (service token) → vault-api (JWT auth)
```

## Allowed paths

- `/health`
- `/v1/*`
- `/docs`
- `/openapi.yaml`

Everything else returns `404`.

## Configure

From `infra/cloudflare/obsidian-actions-proxy`:

```bash
wrangler secret put CF_ACCESS_CLIENT_ID
wrangler secret put CF_ACCESS_CLIENT_SECRET
```

`UPSTREAM_BASE_URL` is set in `wrangler.toml`. It points to `vaultapi.michaelkness.com` (the CF Tunnel endpoint).

## Deploy

```bash
cd infra/cloudflare/obsidian-actions-proxy
wrangler deploy
```

## Usage

Point any client at the deployed Worker URL (`obsidian-actions-proxy.michaelkness.com`), not the upstream tunnel URL directly. Include only `Authorization: Bearer <jwt>` — the Worker handles CF Access headers automatically.

This applies to:
- The Claude Desktop MCP server (`VAULT_API_BASE_URL`)
- The OpenAPI spec server URL
- Any direct `curl` testing
