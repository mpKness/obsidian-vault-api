# CLAUDE.md — obsidian-vault-api

## Project Purpose

Self-hosted backend stack for serving Obsidian vault content (DnD world notes) via a JWT-protected REST API. Runs on a Raspberry Pi, exposed to the internet via Cloudflare Tunnel.

## Repo Layout

```
.
|- docker-compose.yml          # Root compose file for all services
|- .env.example                # Copy to .env and fill real values
|- infra/
|  |- caddy/Caddyfile          # Internal reverse proxy config
|  |- cloudflare/
|     |- obsidian-actions-proxy/
|        |- src/index.ts       # Cloudflare Worker: path filter + CF Access header injection
|        |- wrangler.toml      # Worker config, upstream = vaultapi.michaelkness.com
|- scripts/
|  |- mint_jwt.py              # Mint HS256 JWTs for local testing
|- services/
|  |- obsidian-vault-api/      # Core Go service
|     |- main.go               # Config, env loading, server startup (:8787)
|     |- routes.go             # Chi router, JWT middleware (HS256)
|     |- handlers.go           # listNotes, getNote, batchGetNotes, searchHandler
|     |- search.go             # ripgrep first, naive walk fallback
|     |- helpers.go            # safeJoin (path traversal guard), writeJSON, writeErr
```

## Services (docker-compose.yml)

| Service | Image | Purpose |
|---------|-------|---------|
| `vault-api` | ghcr.io/mpkness/vault-api | Go REST API, port 8787 (internal only) |
| `caddy` | caddy:2.8-alpine | Internal reverse proxy on :80 |
| `cloudflared` | cloudflare/cloudflared | Cloudflare Tunnel connector |
| `infisical` | infisical/infisical | Self-hosted secrets manager, exposed :8081 |
| `postgres` | postgres:16-alpine | Infisical backend DB |
| `infisical-redis` | redis:7-alpine | Infisical backend cache |

## Traffic Flow

```
Internet -> Cloudflare Tunnel -> cloudflared -> caddy:80 -> vault-api:8787
```

The Cloudflare Worker (`obsidian-actions-proxy`) sits in front as an additional public-facing filter:
- Only passes `/v1/*`, `/health`, `/docs`, and `/openapi.yaml` paths
- Injects `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers (service token auth)

## API Endpoints

All `/v1/*` routes require `Authorization: Bearer <HS256-JWT>`.

| Method | Path | Params | Description |
|--------|------|--------|-------------|
| GET | `/health` | — | Public health check |
| GET | `/docs` | — | Scalar API docs UI (public) |
| GET | `/openapi.yaml` | — | Raw OpenAPI 3.1 spec (public) |
| GET | `/v1/notes` | `?prefix=` | List markdown files, optional subfolder |
| GET | `/v1/note` | `?path=` | Read a single `.md` file (max 2 MiB) |
| POST | `/v1/notes/batch` | JSON `{paths:[]}` | Read up to 50 files at once |
| GET | `/v1/search` | `?q=&limit=` | Full-text search (ripgrep > naive, 3s timeout, max 50 hits) |
| PUT | `/v1/note` | JSON `{path, content}` | Write note directly — path must be under `WRITE_ALLOW_PREFIXES` |
| PUT | `/v1/draft` | JSON `{path, content}` | Write note to `_Staging/<path>` for review |

## Key Config (env vars)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `OBSIDIAN_VAULT_ROOT` | yes | — | Absolute path inside container (`/vault`) |
| `JWT_SECRET` | yes | — | Long random string for HS256 signing |
| `JWT_ISSUER` | no | `obsidian-vault-api` | |
| `JWT_AUDIENCE` | no | `vault-clients` | |
| `VAULT_PATH` | yes | — | Host path mounted to `/vault` in container |
| `CLOUDFLARED_TUNNEL_TOKEN` | yes | — | Cloudflare Tunnel token |
| `WRITE_ALLOW_PREFIXES` | no | — | Comma-separated folders for direct writes (e.g. `Sessions`) |
| `STAGING_PREFIX` | no | `_Staging` | Folder where `PUT /v1/draft` writes land |

## Build & Deploy

```bash
# Local dev build
cd services/obsidian-vault-api
go build -o vault-api .

# Docker (multi-arch via GitHub Actions on push to main)
# Images pushed to ghcr.io/mpkness/vault-api:<commit-sha>

# Deploy on Pi
docker compose pull && docker compose up -d
```

GitHub Actions workflow: `.github/workflows/publish-ghcr.yml`
Builds `linux/amd64` + `linux/arm64`. Prefer pinned SHA tags in production.

## JWT Token for Testing

```bash
python scripts/mint_jwt.py
# Optional flags:
python scripts/mint_jwt.py --ttl 1800 --subject dnd-client-1 --secret "your-secret"
```

## Security Notes

- `safeJoin` in `helpers.go` prevents path traversal — all file reads are confined to `VaultRoot`
- Optional `AllowListPrefix` in `Config` restricts reads to specific vault folders
- Only `.md` / `.markdown` files are readable
- JWT requires `exp` claim; leeway is 30s for clock skew
- Only HS256 is accepted (algorithm confusion protection)

## Language & Framework Conventions

- **Go 1.22**, `github.com/go-chi/chi/v5` router, `github.com/golang-jwt/jwt/v5`
- No ORM, no database — filesystem only
- New services go under `services/<service-name>/` and get wired into root `docker-compose.yml` and Caddy routing
- Cloudflare Workers (TypeScript) live under `infra/cloudflare/<worker-name>/`

## MCP Server (`services/obsidian-vault-mcp/`)

TypeScript stdio MCP server for Claude Desktop. Thin client — all real work stays in the vault API.

**Adding a new vault API endpoint always requires three matching changes:**
1. `services/obsidian-vault-api/openapi.yaml` — add the path, parameters, and response schemas
2. `services/obsidian-vault-mcp/src/index.ts` — add tool definition to `ListToolsRequestSchema` handler, add `case` to `CallToolRequestSchema` switch
3. Rebuild MCP: `cd services/obsidian-vault-mcp && npm run build`

**Claude Desktop config** (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "obsidian-vault": {
      "command": "node",
      "args": ["C:/Users/mpkne/Documents/GitHub/obsidian-vault-api/services/obsidian-vault-mcp/dist/index.js"],
      "env": {
        "VAULT_API_BASE_URL": "https://obsidian-actions-proxy.michaelkness.com",
        "VAULT_API_JWT": "<token from mint_jwt.py>"
      }
    }
  }
}
```

**Mint a long-lived token for local use:**
```bash
python scripts/mint_jwt.py --ttl 31536000 --subject claude-desktop
```
