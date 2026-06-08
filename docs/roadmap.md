# Roadmap

Versioning is feature-gated, not date-gated. Each version is shippable. Detector
precision/recall (including **false-negative rate**) is measured against the attack
corpus and published per release.

---

## v0.1 — Scanning core + CLI (no proxy)

**Scope is deliberately narrow: a scanning core and a CLI. There is no network proxy
and no provider call in this version.**

- **Goal:** prove the scanning core works on text, end to end, with tests.
- **Features:**
  - CLI `scan` takes text → runs deterministic scanners (injection signatures,
    encoding tricks) + **regex-based** PII/secrets detection → returns a verdict
    (`ALLOW`/`WARN`/`REDACT`/`BLOCK`) and findings JSON.
  - Simple rule-based policy with fixed precedence.
  - **Normal** SQLite audit logging (append-only rows; no hash chain yet).
- **PII/secrets:** lightweight regex only (emails, cards via Luhn, phones, common
  API-key/token/private-key formats). **Microsoft Presidio is an optional extra
  (`pip install .[pii]`)**, never a core dependency.
- **Technical tasks:** project scaffold, `pyproject.toml`, Pydantic v2 models
  (`CanonicalText`, `Finding`, `Decision`), `Scanner` protocol + registry, normalizer,
  SQLite audit writer.
- **Done when:** `aisg scan "..."` returns a verdict; audit row persisted; ruff + mypy
  (on `core`/`scanners`) clean; CI green on 3.11/3.12.
- **Tests:** normal prompt → `ALLOW`; known injection → `BLOCK`; base64 injection
  decoded → `BLOCK`; zero-width injection caught; PII detected; secret detected;
  REDACT masks output; audit row created.

## v0.2 — Non-streaming OpenAI-compatible proxy

- **Goal:** put the gateway in the request path. **Non-streaming only.**
- **Features:** FastAPI server exposing `POST /v1/chat/completions` (OpenAI-compatible,
  **request/response, no SSE streaming**), one provider adapter (OpenAI), request +
  response scanning, `GET /health`, `GET /metrics`. Decisions: `ALLOW`/`BLOCK`/`WARN`/`REDACT`.
- **Out of scope (deferred):** **streaming** (see v1.0), quarantine (v0.3),
  declarative policy (v0.5).
- **Technical tasks:** request normalizer (provider → canonical), `ProviderAdapter`
  protocol, async `httpx` client with timeouts/retries, provider-shaped error envelopes,
  structured logging.
- **Done when:** an unmodified OpenAI SDK pointed at the gateway gets correct
  (non-streamed) completions; an injected prompt is blocked with a provider-shaped
  error; latency overhead measured and documented.
- **Tests:** provider **mocked** (no real API calls in CI); passthrough; block path
  error shape; REDACT rewrites the outbound payload; egress leak detection.

## v0.3 — Quarantine (async) + dashboard

- **Goal:** humans in the loop; visibility.
- **Features:** `QUARANTINE` status with the **async `quarantine_id` + retry/approve
  workflow** (see [architecture.md](architecture.md#quarantine-workflow-async--no-indefinitely-held-http-request));
  quarantine store; admin API (`/admin/events`, `/admin/quarantine`, approve/reject);
  read-only web dashboard (event feed, quarantine queue, decision stats).
- **Technical tasks:** quarantine schema + state machine (`pending → approved/rejected`),
  worker that processes approved items, result retrieval by id, dashboard
  (dependency-light: HTMX/Jinja), event pagination/filtering.
- **Done when:** a borderline request returns `202` + `quarantine_id` without holding
  the connection; an operator approves it; the client retrieves the stored result;
  reject path returns a clean denial.
- **Tests:** full quarantine flow (hold → approve → result retrievable;
  hold → reject → blocked); admin authz; dashboard renders.

## v0.4 — Cost / token optimization

- **Goal:** make the gateway pay for itself.
- **Features:** per-request token counting, per-key/per-route budgets with enforcement,
  exact-match response cache (Redis optional), optional semantic cache, model-downgrade
  policy hooks, cost reporting in the dashboard.
- **Technical tasks:** tokenizer integration, budget store, cache layer with TTL +
  invalidation, cost attribution by key/route, Prometheus cost metrics.
- **Done when:** exceeding a budget blocks with a clear error; a cache hit avoids a
  provider call; the dashboard shows spend by key.
- **Tests:** budget enforcement; cache hit/miss; token accounting vs fixtures.

## v0.5 — Policy engine

- **Goal:** declarative, auditable, hot-reloadable rules.
- **Features:** YAML/JSON policy files (conditions on findings/route/key/content;
  actions `ALLOW`/`WARN`/`REDACT`/`QUARANTINE`/`BLOCK`; precedence), policy validation +
  **dry-run** mode, per-route binding, optional **LLM threat classifier** as a scanner
  feeding the engine (cached, circuit-breakered).
- **Technical tasks:** policy schema (Pydantic), evaluator with deterministic precedence,
  hot reload + versioning, `policy test` (replay events against a policy).
- **Done when:** a policy change takes effect without restart; dry-run shows what
  *would* happen; conflicting rules resolve deterministically.
- **Tests:** precedence; dry-run correctness; bad policy rejected at load; classifier mocked.

## v1.0 — Production-ready self-hosted release

- **Goal:** something a platform team can actually run.
- **Features:**
  - PostgreSQL backend; multi-provider adapters (OpenAI + Anthropic + local/Ollama);
    API-key auth + RBAC for admin; rate limiting.
  - **Streaming support** (`stream: true` / SSE) — deferred to here on purpose:
    streaming and full egress scanning are in tension (you cannot fully scan a
    response you are emitting token-by-token), so streaming ships with an explicit,
    documented buffering/partial-scan policy rather than silently weakening egress checks.
  - **Tamper-evident audit log** (hash-chained integrity) — earlier versions use
    normal append-only logging; the hash chain is introduced here.
  - Helm chart / hardened Docker Compose; SBOM + dependency scanning in CI; published
    performance budget; semantic-versioned API; finalized threat model.
- **Done when:** deploy via Compose/Helm; survives a load test at the documented p95
  overhead; audit log tamper-evident; security disclosure process live.
- **Tests:** full integration suite, attack corpus, load/soak, migration, RBAC matrix,
  audit-integrity verification.

---

## A note on self-learning

**The MVP does not self-learn.** The gateway never mutates its own rules or thresholds
automatically. Approve/reject decisions and reviewed `WARN`s produce **feedback labels**
that are stored only. Any adaptive rules built from those labels are a **future,
explicitly human-reviewed** step — a security control that silently rewrites itself is
hard to audit and hard to trust. Predictability is a feature here.
