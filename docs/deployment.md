# Deployment

> **Agentic Security Harness.** **Current reality:** the local harness and the `ash` CLI run
> a deterministic 7-pattern corpus against mock/demo targets and write reports — there is no
> server to deploy yet. The reference-gateway server / Docker workflow below is design intent
> for later versions. Sections are marked accordingly.

## Design principle

The simple path must work with **zero extra services**: a local `pip install` and the
`ash` CLI - no server, no Docker, no database, no LLM classifier. Everything runs
offline against synthetic targets. Later features (the reference gateway server,
PostgreSQL, Redis, RBAC, streaming, tamper-evident audit) are **additive**, not required.

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

## Reference gateway server (later, planned)

The reference gateway is design intent only. This repository does not currently ship a
server entry point, Dockerfile, or Compose stack. `.env.example` is a gateway sketch, not
configuration required by the current `ash` CLI.

### Docker (planned)

- **Dockerfile:** multi-stage (builder installs deps into a venv; slim runtime on
  `python:3.11-slim`; 3.11 is the runtime baseline),
    **non-root** user, runtime artifacts only. Entry point runs the
  ASGI server. `HEALTHCHECK` hits `/health`.
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

In the planned gateway, `GET /health` returns `200` with dependency checks; used by the
Docker `HEALTHCHECK` and by orchestrators. See
[api-reference.md](api-reference.md#get-health-planned).

## Quality gates

```bash
pip install -e ".[dev]"
python -m pytest            # full local test suite
python -m ruff check .      # lint
python -m mypy src tests    # type checks
ash validate examples/      # validate committed benchmark artifacts and corpus
git diff --check            # whitespace / conflict-marker check
```
