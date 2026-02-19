# DnD Services Monorepo

This repository hosts backend services used to run and support your DnD worlds.

## Services

- `services/obsidian-vault-api`: JWT-protected API for listing, reading, and searching notes in an Obsidian vault.
- `caddy`: internal reverse proxy and service routing layer.
- `cloudflared`: Cloudflare Tunnel connector for external ingress.

## Quick Start

### Prerequisites

- Docker + Docker Compose
- A vault directory on your machine
- A Cloudflare Tunnel token (`CLOUDFLARED_TUNNEL_TOKEN`)

### Configure environment

1. Copy `.env.example` to `.env`.
2. Set real values for:
- `JWT_SECRET`
- `VAULT_PATH`
- `CLOUDFLARED_TUNNEL_TOKEN`
- `INFISICAL_ENCRYPTION_KEY`
- `INFISICAL_AUTH_SECRET`
- `INFISICAL_SITE_URL`
- `POSTGRES_PASSWORD`

### Start services

```bash
docker compose pull
docker compose up -d
```

### Stop services

```bash
docker compose down
```

## Deployment Model

- Push code to `main`.
- GitHub Actions builds and pushes multi-arch images (`linux/amd64`, `linux/arm64`) to GHCR.
- On the Pi, pull the repo and run `docker compose pull && docker compose up -d`.
- Prefer pinned image tags (commit SHA) for production deploys.

Detailed Pi steps: `docs/deploy-pi.md`

## Traffic Flow

- External traffic enters through Cloudflare Tunnel into `cloudflared`.
- `cloudflared` forwards to `caddy` on the internal Docker network.
- `caddy` routes requests to internal services (currently `vault-api`).

## JWT Token Generation

Use `scripts/mint_jwt.py` to mint HS256 tokens for `obsidian-vault-api`.

```bash
python scripts/mint_jwt.py
```

Optional flags:

```bash
python scripts/mint_jwt.py --ttl 1800 --subject dnd-client-1
python scripts/mint_jwt.py --issuer obsidian-vault-api --audience vault-clients
python scripts/mint_jwt.py --secret "your-secret-here"
```

Example request with a generated token:

```bash
TOKEN=$(python scripts/mint_jwt.py)
curl -H "Authorization: Bearer $TOKEN" https://your-api-domain.example.com/v1/notes
```

## Repository Layout

```text
.
|- docker-compose.yml
|- docs/
|  |- deploy-pi.md
|- infra/
|  |- caddy/
|     |- Caddyfile
|  |- cloudflare/
|     |- obsidian-actions-proxy/
|        |- wrangler.toml
|        |- src/
|           |- index.ts
|- scripts/
|  |- mint_jwt.py
|- services/
|  |- obsidian-vault-api/
|     |- main.go
|     |- go.mod
|     |- Dockerfile
|     |- makefile
```

## Notes

- `docker-compose.yml` at the root is the shared compose file for all services.
- `caddy` is intentionally internal-only; no host ports are published.
- Additional services should be added under `services/<service-name>` and wired into root compose and Caddy routing.
