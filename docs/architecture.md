# Architecture

> **Agentic Security Harness** (repository `agentic-security-harness`). The gateway is the
> **reference defense** component, not the main product. Core concepts live in
> **[harness.md](harness.md)**.

The system is **harness-first**: it drives a target with defensive test patterns, records
each run as a **portable trace**, and derives a **scorecard**. The gateway is one optional
**defense target** you can replay traces against.

## Components

### Current (implemented)

| Component | Responsibility | Module |
|---|---|---|
| **Corpus manifest** | Versioned, machine-readable index of the defensive test patterns (the [taxonomy](harness.md#attack-pattern-taxonomy)) and the coverage matrix. | `corpus.py` |
| **Seed patterns** | The deterministic, sanitized defensive test patterns themselves, defined in code with explicit metadata. | `patterns.py` |
| **Target adapters** | Drive a system under test. Current adapters are local and synthetic: mock target, demo-agent (vulnerable by design), protected-demo-agent (passes all patterns). | `mock_target.py`, `demo_agent.py` / `demo_adapter.py`, `protected_demo_agent.py` |
| **Runner** | Executes a pattern against a target via an adapter; emits one trace per run. | `runner.py` |
| **Trace model** | The portable, machine-readable [trace](harness.md#failure-trace-format) and envelope data structures. | `models.py` |
| **Scorecard generator** | Derives a deterministic aggregate from a set of traces. | `scorecard.py` |
| **Reporting** | Renders traces and scorecards into committed report artifacts. | `reporting.py` |
| **Validation layer** | Validates committed benchmark artifacts and corpus consistency (`ash validate`). | `validation.py` |
| **CLI** | `ash run` / `ash compare` / `ash validate` (run patterns, write traces and scorecards, validate artifacts). | `cli.py` |
| **Committed examples** | Reproducible report artifacts checked into the repo for replay and inspection. | `examples/` |
| **Runtime Gateway reference contour** | Applies a closed pre-dispatch policy to bounded OpenAI-compatible and MCP synthetic requests, dispatches only deterministic synthetic tools, and records a privacy-minimized local audit chain. It is not a production firewall or live-provider transport. | `runtime_gateway.py`, `gateway_server.py` |

### Not implemented in the current release

| Component | Responsibility | Status |
|---|---|---|
| **MCP / tool-permission adapter** | Static analysis of an agent's tools/permissions and live MCP tool schemas -> the tools/permissions layer of the attack graph. Current coverage is a local mock schema record only. | planned |
| **Real LLM adapter** | Drive a live LLM agent target (vs. the current local synthetic adapters). | planned |
| **Multimodal adapter** | Voice / image target via sanitized media fixtures. Current coverage is synthetic OCR / ASR / HTML transcripts only; no live audio/image processing. | planned |
| **Trace store / integrity** | Persistent trace storage with stronger integrity hardening. Current coverage includes a local hash-chain tamper-detection pattern only. | planned |

Note on data-boundary checks: the current local checks that verify the
[data envelope](harness.md#agentic-data-boundary-and-recipient-control) (classification
mutation, recipient confusion, label stripping, leakage, missing-envelope recovery, and
memory read-time drift) live inside the demo and protected target adapters. The
field-level restriction comparator for envelope drift is implemented in
`envelope_policy.py`; a broader live-adapter data-boundary checker is still planned later.

## Attack graph

```
target -> exposed inputs -> agents -> tools -> permissions -> memory -> external data
       -> attack chain -> observed behavior -> finding -> mitigation
```

**Perception-boundary tests** extend the front with an
`external signal -> input channel -> transcript` prefix before `exposed inputs`. The current
release uses synthetic OCR / ASR / HTML transcript fixtures; full media adapters are future
work. A **data envelope** (`data_class`, `allowed_recipients`, `can_store`, `can_forward`,
`ttl`, `classification_mutable=false`) travels alongside the data, and the harness checks
it **survives** each hop (handoff, memory, tool, provider).
Each trace is a path through this graph; the finding records **where it broke**. Details in
[harness.md](harness.md#attack-graph).

## Data flow (harness)

```
 defensive test pattern -+
                          +--> Runner --> Target adapter --> system under test
 target descriptor -------+                 |                  (mock / demo-agent /
                                            |                   protected-demo-agent)
                                            v
                                      Trace (portable, machine-readable)
                                            |
                             +--------------+---------------+
                             v              v               v
                        Scorecard      Reporting      Replay against a
                        (derived)      (artifacts)    protected target  --> risk-reduction delta
                             |              |
                             +------+-------+
                                    v
                              ash validate (over the resulting artifacts)
```

The pipeline is: pattern -> target adapter -> runner -> trace -> scorecard -> reporting,
with `ash validate` checking the resulting artifacts. The honest core: the harness does not
assert protection - it **measures the delta** a defense produces against the **same**
reproducible traces.

For future adapters, the stable contract is documented in
[adapter-contract.md](adapter-contract.md). Report expectations are documented in
[reporting.md](reporting.md).

## Runtime Gateway reference contour

The v1.2.0 Runtime Gateway is an implemented, local synthetic defense target. It accepts a
closed non-streaming OpenAI-compatible subset and a stateless MCP subset, normalizes
credential-free retained provider tool envelopes, applies policy before dispatch, and
allows only bounded deterministic synthetic tools. A request is allowed, blocked, or
stopped as approval-required; the current contour has no API that grants approval.

```
 synthetic client -> closed transport -> normalizer -> policy
                                                   |-> block
                                                   |-> approval-required (non-executable)
                                                   `-> bounded synthetic executor -> local audit chain
```

- **No live providers:** OpenAI, Anthropic, Google, remote MCP, arbitrary executors, and
  credentials remain outside this contour.
- **No hidden enforcement claim:** the gateway is a reproducible reference integration
  surface, not a production security boundary.
- **Detailed contract:** see [runtime-gateway.md](runtime-gateway.md) for transports,
  policy, audit, Docker, dashboard, and exact limitations.

## Trust boundaries

```
[ untrusted: user input, RAG docs, tool/sensor outputs ] -> boundary 1 ->
[ target under test (agent / chain / workflow) ]         -> boundary 2 ->
[ harness control plane: runner + traces + scorecard ]   -> boundary 3 ->
[ optional defense: reference gateway ] -> [ external: LLM provider ]
```

The harness only drives **mock / demo / authorized** targets. Everything to the left of
boundary 1 is hostile by default - including **sensor inputs** (audio/image), not just text.

## Storage

- **Current release:** local files (traces + scorecards written under the output dir;
  committed examples under `examples/`). Zero-ops, no database.
- **Future tracks:** a persistent trace store (PostgreSQL) with stronger integrity
  controls beyond the current local hash-chain fixture, and optional Redis (caching /
  budgets in the reference gateway). These are post-v1.0 and not part of the current
  benchmark release.

See [roadmap.md](roadmap.md) and [threat-model.md](threat-model.md).
