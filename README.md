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

Part of the [Raphael Platform](https://github.com/hummingbird-labs) by HummingBird Labs.
