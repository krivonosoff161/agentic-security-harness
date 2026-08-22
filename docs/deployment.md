# Deployment

> **Agentic Security Harness.** **Current reality:** the local harness and the `ash` CLI run
> a deterministic 24-pattern corpus against mock/demo targets and write reports. A source-based,
> non-root Dockerfile packages that CLI. A separate source-only Docker/Compose contour now
> runs the local synthetic Runtime Gateway; no image or production gateway is published.
> Future production sections are marked accordingly.

## Design principle

The simple path must work with **zero extra services**: a local `pip install` and the
`ash` CLI - no server, database, or classifier. Everything runs offline against synthetic
targets. The local gateway is optional and uses only the standard library, fixed synthetic
tools, and local files. Provider routing, PostgreSQL, Redis, RBAC, streaming, and remotely
attested audit are **additive future work**, not required.

## Harness CLI (available now)

Install locally, then run the `ash` CLI:

```bash
pip install -e .            # local install of the harness
ash run --target demo-agent --out reports/
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/
ash validate examples/
```

The `ash` CLI runs locally against mock/demo targets: it executes the defensive test
patterns, writes one [trace](harness.md#failure-trace-format) per chain, derives a
[scorecard](harness.md#scorecard), and can `compare` a baseline vs a protected target.
Usage is in the [README](../README.md) and [harness.md](harness.md).

## Local Runtime Gateway (available in source)

The root `Dockerfile` remains a local CLI wrapper. `Dockerfile.gateway` and
`compose.gateway.yml` run the credential-free synthetic server documented in
[runtime-gateway.md](runtime-gateway.md):

```bash
docker compose -f compose.gateway.yml up --build
```

Host publication is fixed to `127.0.0.1:8787`; the root filesystem is read-only, the
process is non-root with Linux capabilities dropped, and only the named audit volume is
writable. The image is not published, and this source definition is not a production
deployment claim.

## Production gateway server (later, planned)

### Production Docker (planned)

- **Dockerfile:** multi-stage (builder installs deps into a venv; slim runtime on
  `python:3.11-slim`; 3.11 is the runtime baseline),
    **non-root** user, runtime artifacts only. Entry point runs the
  ASGI server. `HEALTHCHECK` hits `/health`.
- **docker-compose.yml** services:
  - `gateway` - the app; reads `.env`.
  - `db` - PostgreSQL (`prod` profile); the `default` profile uses SQLite and skips it.
  - `redis` - optional (cache/budgets), behind a Compose profile.
  - `dashboard` - optional separate service, or served by the gateway in early versions.
  - Profiles: `default` (gateway + SQLite), `prod` (gateway + Postgres + Redis + dashboard).

## Future production environment variables

| Var | Purpose |
|---|---|
| `GATEWAY_PORT` | listen port (default 8080) |
| `GATEWAY_DB_URL` | `sqlite:///gateway.db` or `postgresql://...` |
| `GATEWAY_REDIS_URL` | optional; enables cache/budgets |
| `GATEWAY_ADMIN_TOKEN` | bearer token for `/admin/*` |
| `GATEWAY_DEFAULT_PROVIDER` | `openai` / `anthropic` / `ollama` |
| `OPENAI_API_KEY` (etc.) | upstream provider credentials |
| `GATEWAY_CLASSIFIER_ENABLED` | turn the LLM classifier on/off |
| `GATEWAY_CLASSIFIER_MODEL` | model used for classification |
| `GATEWAY_POLICY_PATH` | path to the active policy file |
| `GATEWAY_LOG_LEVEL` | structured log level |

See [`.env.example`](../.env.example) for a planned gateway configuration sketch.

## Healthcheck

The local synthetic gateway exposes `GET /healthz` and `GET /readyz`; its Docker
`HEALTHCHECK` uses `/healthz`. A future production gateway may add dependency-aware
`GET /health` semantics described in [api-reference.md](api-reference.md).

## Quality gates

```bash
pip install -e ".[dev]"
python -m pytest            # full local test suite
python -m ruff check .      # lint
python -m mypy src tests tools    # type checks
ash validate examples/      # validate committed benchmark artifacts and corpus
git diff --check            # whitespace / conflict-marker check
```
