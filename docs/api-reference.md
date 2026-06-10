# Reference gateway API

> **Planned reference-gateway API - NOT implemented in the current benchmark release.**
> This is a forward-looking design sketch, not shipped code.

> **Agentic Security Harness.** This documents the **planned reference gateway** — the
> optional [defense component](harness.md#reference-defense-replay), not the harness. The
> harness has **no published HTTP API** (the `ash` CLI is documented in the
> [README](../README.md)); its core artifacts are
> [traces](harness.md#failure-trace-format). Endpoints are annotated as planned for the
> future reference gateway; treat them as design intent only.

Current repository status: there is no gateway server package, Dockerfile, database,
provider adapter, or HTTP runtime in this release.

The reference gateway exposes two surfaces: the **proxy API** (OpenAI-compatible, for apps
and as a replay defense target) and the **admin API** (for operators).

## Auth

- **Proxy API:** per-client API keys issued by the gateway, mapped to routes/budgets.
- **Admin API:** a separate admin bearer token; RBAC planned for a later milestone.
- Provider credentials are held by the gateway and never returned to clients.

---

## `POST /v1/chat/completions` — OpenAI-compatible *(planned)*

Accepts the standard OpenAI chat-completions body (`model`, `messages`, `tools`,
`temperature`, …). On the happy path it would behave like the provider and return the same
response shape.

> **The planned first iteration is non-streaming only.** `stream: true` would be rejected
> with a clear error until streaming is added in a later milestone (see
> [roadmap](roadmap.md) for why it is deferred).

Differences are additive and non-breaking:

- **BLOCK** → provider-shaped error envelope, e.g.:
  ```json
  { "error": { "type": "gateway_blocked", "code": "prompt_injection",
               "message": "Request blocked by policy.", "request_id": "req_..." } }
  ```
- **REDACT** → the request is sanitized before forwarding (recorded in the audit log).
- **QUARANTINE** *(planned)* → `202 Accepted` with:
  ```json
  { "quarantine_id": "qz_...", "status": "pending", "retry_after": 30 }
  ```
  The connection is released; the client polls or re-submits (see below).
- Adds `X-Gateway-Decision` and `request_id` response headers for traceability.

**Compatibility goal:** for a non-streaming request, an OpenAI SDK (Python/JS) or
LangChain pointed at `base_url=http://<gateway>/v1` works with only a base-URL change
plus gateway-issued credentials. It is **not** fully transparent: clients still need to
handle gateway-specific behavior — the quarantine `202` + `quarantine_id` flow, auth,
and the streaming restriction (see those sections).

### Quarantine retrieval *(planned)*

The async workflow avoids holding the HTTP connection open for human review.

- `GET /v1/quarantine/{id}` → current status:
  - `pending` → `202`, `{ "status": "pending", "retry_after": <s> }`
  - `approved` → `200`, `{ "status": "approved", "result": <completion> }`
  - `rejected` → block error envelope
- **Re-submit path:** repeat the original `POST /v1/chat/completions` with header
  `X-Quarantine-Id: qz_...` (or an idempotency key). While pending it returns `202`;
  once approved it returns the stored completion; if rejected it returns the block error.

---

## `GET /health` *(planned)*

Liveness/readiness plus dependency checks.

```json
{ "status": "ok", "version": "planned",
  "checks": { "db": "ok", "provider": "reachable" } }
```

## `GET /metrics` *(planned)*

Prometheus exposition: request counts by decision, scanner latencies, classifier calls,
tokens/cost by key, quarantine queue depth, cache hit rate *(all planned)*.

## `GET /admin/events` *(planned)*

Paginated audit feed. Filters: time range, decision, route, key, finding type.
Auth: admin token. Read-only.

## `GET /admin/quarantine` *(planned)*

List quarantined items (status, findings, snippet, `created_at`). Auth: admin.

## `POST /admin/quarantine/{id}/approve` *(planned)*

Approve a held request → a worker forwards it to the provider; the result is stored
against the id and retrieved as above. Records who/when. Idempotent. *(Quarantine
currently targets ingress; egress quarantine is not yet designed — see the architecture
[reference-gateway notes](architecture.md#reference-gateway-optional-defense-target).)*

## `POST /admin/quarantine/{id}/reject` *(planned)*

Reject → permanent `BLOCK`; records reason. Idempotent.
