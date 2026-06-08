# Deployment

> Product name TBD. **Current reality:** `v0.1` is a CLI + scanning core — there is no
> server to deploy yet. The server/Docker workflow below is design intent for `v0.2`+.
> Sections are marked accordingly.

## Design principle

The simple path must work with **zero extra services**: `docker compose up` with SQLite,
no Redis, no LLM classifier. Production features (PostgreSQL, Redis, RBAC, streaming,
tamper-evident audit) are **additive**, not required.

## CLI (`v0.1`, available first)

```bash
pip install -e ".[dev]"            # core, regex PII/secrets
# pip install -e ".[dev,pii]"      # optional: Microsoft Presidio
aisg scan "some prompt text"
```

## Server (`v0.2`+, planned)

```bash
cp .env.example .env               # set provider key + admin token
docker compose up                  # default profile: gateway + SQLite
# point your client at http://localhost:8080/v1
```

### Docker (planned)

- **Dockerfile:** multi-stage (builder installs deps into a venv; slim runtime on
  `python:3.11-slim` — 3.11 is the runtime baseline while CI also tests 3.12),
    **non-root** user, runtime artifacts only. Entry point runs the
  ASGI server (or `aisg serve`). `HEALTHCHECK` hits `/health`.
- **docker-compose.yml** services:
  - `gateway` — the app; reads `.env`.
  - `db` — PostgreSQL (`prod` profile); the `default` profile uses SQLite and skips it.
  - `redis` — optional (cache/budgets), behind a Compose profile.
  - `dashboard` — optional separate service, or served by the gateway in early versions.
  - Profiles: `default` (gateway + SQLite), `prod` (gateway + Postgres + Redis + dashboard).

## Environment variables

| Var | Purpose |
|---|---|
| `GATEWAY_PORT` | listen port (default 8080) |
| `GATEWAY_DB_URL` | `sqlite:///gateway.db` or `postgresql://…` |
| `GATEWAY_REDIS_URL` | optional; enables cache/budgets (v0.4) |
| `GATEWAY_ADMIN_TOKEN` | bearer token for `/admin/*` |
| `GATEWAY_DEFAULT_PROVIDER` | `openai` / `anthropic` / `ollama` |
| `OPENAI_API_KEY` (etc.) | upstream provider credentials |
| `GATEWAY_CLASSIFIER_ENABLED` | turn the LLM classifier on/off (v0.5) |
| `GATEWAY_CLASSIFIER_MODEL` | model used for classification (v0.5) |
| `GATEWAY_POLICY_PATH` | path to the active policy file (v0.5) |
| `GATEWAY_LOG_LEVEL` | structured log level |

See [`.env.example`](../.env.example) for a ready-to-copy template.

## Healthcheck

`GET /health` returns `200` with dependency checks; used by the Docker `HEALTHCHECK`
and by orchestrators. See [api-reference.md](api-reference.md#get-health-v02).

## Running tests

```bash
pip install -e ".[dev]"
pytest                      # unit + integration (provider always mocked in CI)
pytest tests/attacks -v     # red-team corpus
ruff check . && mypy app
```
