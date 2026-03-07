# obsidian-vault-api

JWT-protected Go HTTP API for listing, reading, searching, and writing markdown notes in an Obsidian vault.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Health check |
| GET | `/docs` | none | Scalar API docs UI |
| GET | `/openapi.yaml` | none | Raw OpenAPI spec |
| GET | `/v1/notes` | JWT | List notes (`?prefix=` optional subfolder) |
| GET | `/v1/note` | JWT | Read a note (`?path=`) |
| POST | `/v1/notes/batch` | JWT | Read up to 50 notes (`{"paths":[...]}`) |
| GET | `/v1/search` | JWT | Full-text search (`?q=&limit=`) |
| PUT | `/v1/note` | JWT | Write note directly — path must be under `WRITE_ALLOW_PREFIXES` |
| PUT | `/v1/draft` | JWT | Write note to `_Staging/<path>` for review |

## Config (env vars)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `OBSIDIAN_VAULT_ROOT` | yes | — | Absolute path to vault inside container (`/vault`) |
| `JWT_SECRET` | yes | — | HS256 signing secret |
| `JWT_ISSUER` | no | `obsidian-vault-api` | |
| `JWT_AUDIENCE` | no | `vault-clients` | |
| `ADDR` | no | `:8787` | Listen address |
| `WRITE_ALLOW_PREFIXES` | no | — | Comma-separated folders for direct writes (e.g. `Sessions`) |
| `STAGING_PREFIX` | no | `_Staging` | Folder where `PUT /v1/draft` writes land |

## Local build

```bash
go build -o vault-api .
OBSIDIAN_VAULT_ROOT=/path/to/vault JWT_SECRET=test ./vault-api
```

## Docker

Built and pushed to GHCR via GitHub Actions on push to `main`. See root `docker-compose.yml` for deployment config.
