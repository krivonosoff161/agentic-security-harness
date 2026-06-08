# API reference

> Product name TBD. Endpoints are annotated with the version they first appear in.
> Until then, treat them as design intent.

Two surfaces: the **proxy API** (OpenAI-compatible, for apps) and the **admin API**
(for operators).

## Auth

- **Proxy API:** per-client API keys issued by the gateway, mapped to routes/budgets.
- **Admin API:** a separate admin bearer token; RBAC from v1.0.
- Provider credentials are held by the gateway and never returned to clients.

---

## `POST /v1/chat/completions` — OpenAI-compatible *(v0.2)*

Accepts the standard OpenAI chat-completions body (`model`, `messages`, `tools`,
`temperature`, …). On the happy path it behaves like the provider and returns the same
response shape.

> **`v0.2` is non-streaming only.** `stream: true` is rejected with a clear error until
> streaming ships in **v1.0** (see [roadmap](roadmap.md#v10--production-ready-self-hosted-release)
> for why it is deferred).

Differences are additive and non-breaking:

- **BLOCK** → provider-shaped error envelope, e.g.:
  ```json
  { "error": { "type": "gateway_blocked", "code": "prompt_injection",
               "message": "Request blocked by policy.", "request_id": "req_..." } }
  ```
- **REDACT** → the request is sanitized before forwarding (recorded in the audit log).
- **QUARANTINE** *(v0.3)* → `202 Accepted` with:
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

### Quarantine retrieval *(v0.3)*

The async workflow avoids holding the HTTP connection open for human review.

- `GET /v1/quarantine/{id}` → current status:
  - `pending` → `202`, `{ "status": "pending", "retry_after": <s> }`
  - `approved` → `200`, `{ "status": "approved", "result": <completion> }`
  - `rejected` → block error envelope
- **Re-submit path:** repeat the original `POST /v1/chat/completions` with header
  `X-Quarantine-Id: qz_...` (or an idempotency key). While pending it returns `202`;
  once approved it returns the stored completion; if rejected it returns the block error.

---

## `GET /health` *(v0.2)*

Liveness/readiness plus dependency checks.

```json
{ "status": "ok", "version": "0.2.0",
  "checks": { "db": "ok", "provider": "reachable" } }
```

## `GET /metrics` *(v0.2)*

Prometheus exposition: request counts by decision, scanner latencies, classifier calls,
tokens/cost by key *(v0.4)*, quarantine queue depth *(v0.3)*, cache hit rate *(v0.4)*.

## `GET /admin/events` *(v0.3)*

Paginated audit feed. Filters: time range, decision, route, key, finding type.
Auth: admin token. Read-only.

## `GET /admin/quarantine` *(v0.3)*

List quarantined items (status, findings, snippet, `created_at`). Auth: admin.

## `POST /admin/quarantine/{id}/approve` *(v0.3)*

Approve a held request → a worker forwards it to the provider; the result is stored
against the id and retrieved as above. Records who/when. Idempotent. *(Quarantine
currently targets ingress; egress quarantine is not yet designed — see the architecture
[version & scope note](architecture.md#data-flow).)*

## `POST /admin/quarantine/{id}/reject` *(v0.3)*

Reject → permanent `BLOCK`; records reason. Idempotent.
