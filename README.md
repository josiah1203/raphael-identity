# raphael-identity

Login, SSO, MFA, sessions, devices, API keys

## API

- Prefix: `/v1/identity`
- Port: `8081`
- Health: `GET /health`

## Events

_Published and consumed events documented in `openapi.yaml` and raphael-contracts._

## Development

```bash
uv sync
uv run uvicorn raphael_identity.app:app --reload --port 8081
```

### Dev seed user

On startup (unless `RAPHAEL_SEED_DEV_USER=false`), a default account is created:

| Field | Default |
|-------|---------|
| Email | `dev@raphael.app` |
| Password | `raphaeldev1` |

Override with `RAPHAEL_DEV_USER_EMAIL` and `RAPHAEL_DEV_USER_PASSWORD`.

Part of the [Raphael Platform](https://github.com/hummingbird-labs) by HummingBird Labs.
