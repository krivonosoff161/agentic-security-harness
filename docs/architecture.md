# Architecture

> Product name TBD; referred to here as "the gateway".

## Components

| Component | Responsibility | First appears |
|---|---|---|
| **API gateway / reverse proxy** | Terminates client connections, speaks an OpenAI-compatible API, orchestrates the pipeline, returns the final response. | v0.2 |
| **Request normalizer** | Converts provider-specific request shapes into one canonical internal model; normalizes encodings (Unicode NFKC, strip zero-width, decode base64 candidates) so scanners see what the model sees. | v0.1 (text) / v0.2 (requests) |
| **Deterministic scanner** | Fast, no-LLM checks: regex/heuristic injection signatures, encoding tricks, known patterns, tool-call argument inspection. Always runs first. | v0.1 |
| **PII / secrets detector** | Detects and optionally redacts PII and secrets, inbound and outbound. **v0.1 uses lightweight regex** (emails, cards via Luhn, phones, common key formats). Microsoft Presidio is an **optional extra** (`[pii]`), not a core dependency. | v0.1 (regex) / Presidio optional |
| **LLM threat classifier** | Optional, slower: classifies ambiguous inputs/outputs as injection/benign with a score. Gated by deterministic results to control cost; has a circuit breaker. | v0.5 |
| **Policy engine** | Maps findings + context (route, key, direction) to a decision via declarative rules with deterministic precedence. The single decision authority. | simple in v0.1, declarative in v0.5 |
| **Quarantine store** | Persists held requests awaiting human approve/reject; async workflow (below). | v0.3 |
| **Audit logger** | Append-only record of every request, finding, decision, and admin action. **Normal logging through v0.5; tamper-evidence (hash chain) is v1.0.** | v0.1 (normal) / v1.0 (tamper-evident) |
| **Token / cost optimizer** | Token counting, budgets, caching, model-downgrade hooks. | v0.4 |
| **Provider adapters** | Translate canonical request ↔ provider call; isolate provider quirks. | v0.2 (OpenAI) / v1.0 (multi) |
| **Dashboard** | Read + light-write admin UI: events, quarantine queue, stats. | v0.3 |
| **CLI / admin tools** | `scan`, `serve`, `policy test`, `replay`, DB utilities. | v0.1 |

## Decision precedence

The policy engine resolves multiple findings deterministically:

```
BLOCK  >  QUARANTINE  >  REDACT  >  WARN  >  ALLOW
```

The highest-severity applicable action wins. Precedence is fixed and testable.

## Data flow

```
                          ┌──────────────────── AI Security Gateway ──────────────────────┐
 client / app  ──HTTP──►  │  gateway → normalizer → ┌ deterministic scanner ┐             │
 (OpenAI SDK,             │                         │ PII/secrets detector  │ ─► findings │
  LangChain,              │                         └ LLM classifier (opt.) ┘     │       │
  agent)                  │                                                       ▼       │
                          │                                                 policy engine │
                          │       ┌──────────┬───────────┬──────────┬────────────┤        │
                          │       ▼          ▼           ▼          ▼            ▼        │
                          │     BLOCK    QUARANTINE    REDACT      WARN        ALLOW       │
                          │       │          │           │          │            │        │
                          │   error to   202 +       rewrite     annotate     forward     │
                          │   client     quarantine_id payload   + forward       │        │
                          │              (async, no    └─────────────┬──────────┘         │
                          │               held conn)                 ▼                    │
                          │                                   provider adapter ──► LLM    │
                          │                                          │           provider │
                          │                                     response                  │
                          │                                          ▼                    │
                          │                          response scanner (PII/secret/leak,   │
                          │                          system-prompt leak, tool-call check) │
                          │                                          ▼                    │
                          │                       ALLOW / REDACT / BLOCK / QUARANTINE     │
                          │                                          │                    │
   client  ◄──────────────┤◄──────────────────────────────── response to client          │
                          │  audit logger writes at every stage (append-only)             │
                          └────────────────────────────────────────────────────────────────┘
```

> **Version & scope note:** the diagram shows the full intended pipeline. The LLM
> classifier is **v0.5**; QUARANTINE and the admin/dashboard flow are **v0.3** — the
> v0.2 proxy emits **ALLOW / WARN / REDACT / BLOCK** only. Quarantine currently targets
> **ingress** (client → provider); **egress quarantine** (holding a completion) is not
> yet designed, so on egress the pipeline uses ALLOW / WARN / REDACT / BLOCK.

## Quarantine workflow (async — no indefinitely-held HTTP request)

A blocked-pending request must **not** hold the client's HTTP connection open waiting
for a human. The flow is asynchronous:

1. Pipeline returns `QUARANTINE`. The gateway persists the held request and replies
   **immediately** with `202 Accepted` and a body:
   `{"quarantine_id": "...", "status": "pending", "retry_after": <seconds>}`.
   The client connection is released.
2. An operator reviews the item in the dashboard / admin API and calls
   `approve` or `reject`.
3. **On approve:** the request is processed (forwarded to the provider) by a worker;
   the result is stored against the `quarantine_id`.
4. **The client retrieves the outcome** by either:
   - polling `GET /v1/quarantine/{id}` until `status` is `approved` (with `result`)
     or `rejected`; or
   - re-submitting the original request to `/v1/chat/completions` with an idempotency
     key / `X-Quarantine-Id` header — once approved it returns the stored result,
     while pending it returns `202` again, and if rejected it returns the block error.

This keeps the gateway connectionless for held items and works for any HTTP client,
including SDKs with short timeouts.

## Trust boundaries

```
[ untrusted: user input, RAG docs, web/tool content ] ─► boundary 1 ─►
[ semi-trusted: the app/agent calling the gateway ]   ─► boundary 2 ─►
[ TRUSTED control plane: gateway + policy + audit ]   ─► boundary 3 ─►
[ external: LLM provider ]
```

Boundary 1 is where scanners live; everything to its left is hostile by default.
Provider credentials are never exposed to clients; they are used only for upstream
provider calls (boundary 3) and are not returned across boundary 1/2.

## Storage

- **v0.1–v0.3:** SQLite (zero-ops; full stack runs with `docker compose up`).
- **v1.0:** PostgreSQL for concurrency, JSONB findings, and audit retention.
- **Redis:** optional from v0.4 (response cache, budget/rate-limit counters).

See [roadmap.md](roadmap.md) for the per-version scope and [threat-model.md](threat-model.md)
for the security stance.
