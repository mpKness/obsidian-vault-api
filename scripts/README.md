# scripts

## mint_jwt.py

Mints HS256 JWTs for authenticating against the vault API. No external dependencies — pure stdlib.

Reads `JWT_SECRET` from env by default, or pass `--secret`.

```bash
# Short-lived token for testing (1 hour)
python scripts/mint_jwt.py

# Long-lived token for Claude Desktop MCP config (1 year)
python scripts/mint_jwt.py --ttl 31536000 --subject claude-desktop

# Custom TTL and subject
python scripts/mint_jwt.py --ttl 1800 --subject dnd-client-1

# Explicit secret (e.g. if JWT_SECRET not set in env)
python scripts/mint_jwt.py --secret "your-secret-here"
```

The token is printed to stdout, suitable for use in scripts:

```bash
TOKEN=$(python scripts/mint_jwt.py)
curl -H "Authorization: Bearer $TOKEN" https://obsidian-actions-proxy.michaelkness.com/v1/notes
```
