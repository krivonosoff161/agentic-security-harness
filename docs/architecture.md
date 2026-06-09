# Architecture

> **Agentic Security Harness** (repository `agentic-security-harness`). The gateway is the
> **reference defense** component, not the main product. Core concepts live in
> **[harness.md](harness.md)**.

The system is **harness-first**: it drives a target with defensive test patterns, records
each run as a **portable trace**, and derives a **scorecard**. The gateway is one optional
**defense target** you can replay traces against.

## Components

| Component | Responsibility | First appears |
|---|---|---|
| **Runner** | Executes attack chains (defensive test patterns) against a target via an adapter; emits one trace per chain. | v0.1 |
| **Target adapters** | Drive a system under test: LLM agent, MCP / tool chain, multi-agent workflow, **voice / multimodal target** (sanitized ASR/OCR fixtures), AI gateway. Mock/demo adapters first. | v0.1 (mock) / later (real) |
| **Attack library** | Versioned, sanitized defensive test patterns (the [taxonomy](harness.md#attack-pattern-taxonomy)); seeded from `tests/attacks/`. | v0.1 |
| **Trace store** | Persists [traces](harness.md#exploit-trace-format) — machine-readable, portable, replayable. Normal append-only storage; integrity hardening is v1.0. | v0.1 |
| **Scorecard generator** | Derives a deterministic aggregate from a set of traces. | v0.1 |
| **Scanner core (reused)** | Deterministic checks — injection signatures, encoding tricks, PII/secret (regex; Presidio optional `[pii]`), **tool-call / tool-permission inspection**. Used as harness **detectors/oracles** *and* as detection inside the reference gateway. | v0.1 |
| **MCP / tool-permission scanner** | Static analysis of an agent's tools/permissions and MCP tool schemas → the tools/permissions layer of the attack graph. | later |
| **Data-boundary checker** | Verifies the [data envelope](harness.md#agentic-data-boundary-and-recipient-control) survives handoffs, memory, tools, and provider routing (classification mutation, recipient confusion, label stripping, leakage). | later |
| **Reference gateway** | OpenAI-compatible proxy = optional **defense target** + reference defense implementation (normalizer, scanners, policy, quarantine, audit). | later |
| **CLI / admin** | `ash run` / `ash compare` ship now (run patterns, write traces and scorecards); admin tooling later. | now / later |

## Attack graph

```
target → exposed inputs → agents → tools → permissions → memory → external data
       → attack chain → observed behavior → finding → mitigation
```

**Sensor / multimodal targets** extend the front with an
`external signal (audio/image) → input channel → ASR/OCR transcript` prefix before
`exposed inputs` — the pre-LLM channel text-only gateways typically do not see. A **data
envelope** (`data_class`, `allowed_recipients`, `can_store`, `can_forward`, `ttl`,
`classification_mutable=false`) travels alongside the data, and the harness checks it
**survives** each hop (handoff, memory, tool, provider).
Each trace is a path through this graph; the finding records **where it broke**. Details in
[harness.md](harness.md#attack-graph).

## Data flow (harness)

```
 defensive test pattern ┐
                        ├─► Runner ──► Target adapter ──► system under test
 target descriptor ─────┘                │                  (mock agent / MCP /
                                         │                   multi-agent / gateway)
                                         ▼
                                   Trace (portable, machine-readable)
                                         │
                          ┌──────────────┼───────────────┐
                          ▼              ▼                ▼
                    Trace store    Scorecard      Replay against a
                                   (derived)      defended target  ──► risk-reduction Δ
```

The honest core: the harness does not assert protection — it **measures the delta** a
defense produces against the **same** reproducible traces.

## Reference gateway (optional defense target)

When a target is put behind the reference gateway, the gateway inspects requests/responses
and emits one of five decisions — `ALLOW / WARN / REDACT / QUARANTINE / BLOCK` — with
fixed precedence `BLOCK > QUARANTINE > REDACT > WARN > ALLOW`.

```
 client/app ─► gateway → normalizer → [deterministic scanner | PII/secrets | classifier]
                                              │
                                          policy engine
                            ┌──────────┬──────┴────┬──────────┬─────────┐
                          BLOCK    QUARANTINE     REDACT     WARN      ALLOW
                            │      202+id(async)    │          │         │
                          error   (no held conn)  rewrite   annotate  forward ─► provider
                                                                          │
                                                              response scanner ─► client
```

- **Quarantine is async:** on `QUARANTINE` the gateway returns `202` + `quarantine_id`
  immediately (no held connection); the client polls or re-submits after approve/reject.
- **Classifier** (optional LLM threat classifier) and **declarative policy** are later
  milestones; the v0.1-reused scanner core is deterministic.
- **Credentials:** provider credentials are never exposed to clients; they are used only
  for upstream provider calls and are not returned across the client boundary.

## Trust boundaries

```
[ untrusted: user input, RAG docs, tool/sensor outputs ] ─► boundary 1 ─►
[ target under test (agent / chain / workflow) ]         ─► boundary 2 ─►
[ harness control plane: runner + traces + scorecard ]   ─► boundary 3 ─►
[ optional defense: reference gateway ] ─► [ external: LLM provider ]
```

The harness only drives **mock / demo / authorized** targets. Everything to the left of
boundary 1 is hostile by default — including **sensor inputs** (audio/image), not just text.

## Storage

- **v0.1–early:** SQLite / files (zero-ops; traces + scorecards).
- **v1.0:** PostgreSQL for trace retention; **trace integrity hardening (hash chaining)**
  is introduced here, not earlier.
- **Redis:** optional later (caching/budgets in the reference gateway).

See [roadmap.md](roadmap.md) and [threat-model.md](threat-model.md).
