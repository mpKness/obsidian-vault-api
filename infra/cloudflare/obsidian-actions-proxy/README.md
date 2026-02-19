# Obsidian Actions Proxy Worker

Cloudflare Worker that forwards requests to the vault API and injects Cloudflare Access service token headers.

## Why this exists

GPT Actions imports currently do not reliably support custom header auth parameters per operation. This Worker lets Actions use only bearer auth while the Worker adds:

- `CF-Access-Client-Id`
- `CF-Access-Client-Secret`

## Request flow

1. GPT Action calls this Worker URL with `Authorization: Bearer <jwt>`.
2. Worker forwards the request to `UPSTREAM_BASE_URL`.
3. Worker injects Cloudflare Access service token headers.
4. Upstream API validates JWT as usual.

## Allowed paths

The Worker only proxies:

- `/health`
- `/v1/*`

Everything else returns `404`.

## Configure

From `infra/cloudflare/obsidian-actions-proxy`:

```bash
wrangler secret put CF_ACCESS_CLIENT_ID
wrangler secret put CF_ACCESS_CLIENT_SECRET
```

`UPSTREAM_BASE_URL` is configured in `wrangler.toml`. Change it there if needed.

## Deploy

```bash
wrangler deploy
```

## GPT Actions setup

1. Set your OpenAPI server URL to the deployed Worker URL.
2. Keep only bearer auth in OpenAPI (`Authorization: Bearer <jwt>`).
3. Do not include Cloudflare Access headers in OpenAPI; Worker handles them.
