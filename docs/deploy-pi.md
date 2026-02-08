# Pi Deployment Runbook

This runbook assumes:

- repo is cloned on the Pi
- Docker and Docker Compose are installed
- GitHub Actions publishes images to GHCR

## 1. Configure environment

Create `.env` (or copy from `.env.example`) and set:

```env
JWT_SECRET=replace-with-a-long-random-secret
VAULT_PATH=/srv/obsidian/obsidian-vaults
CLOUDFLARED_TUNNEL_TOKEN=replace-with-cloudflare-tunnel-token
GHCR_OWNER=mpkne
VAULT_API_IMAGE_TAG=latest
CADDY_IMAGE_TAG=2.8-alpine
CLOUDFLARED_IMAGE_TAG=latest
```

## 2. First deploy

```bash
docker compose pull
docker compose up -d
```

## 3. Update deploy

```bash
git pull --ff-only
docker compose pull
docker compose up -d --remove-orphans
```

## 4. Pin to a CI image tag (recommended)

Use the image tag pushed by CI (for example a SHA tag) by setting:

```env
VAULT_API_IMAGE_TAG=sha-<gitsha>
```

Then apply:

```bash
docker compose pull vault-api
docker compose up -d vault-api
```

## 5. Verify

```bash
docker compose ps
docker compose logs --tail=100 cloudflared caddy vault-api
```

## 6. Roll back

Set `VAULT_API_IMAGE_TAG` to the previous known-good tag, then:

```bash
docker compose pull vault-api
docker compose up -d vault-api
```
