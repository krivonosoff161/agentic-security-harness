# Bounded Local Swarm

Status: research-only implementation for issues #61 and #63.

This lane tests a narrow claim:

> A bounded multi-agent topology can reduce modeled boundary failures when generation,
> delegation, memory, verification, and audit roles are separated by deterministic
> contracts.

It does not prove that a production agent system is safe, and it does not prove semantic
truthfulness of model output. The pass/block decision is deterministic. Optional local
model calls are recorded only as role-output hashes and short previews for evidence
quality review.

## What It Compares

The same synthetic boundary scenarios run through three shapes:

| Mode | Meaning |
| --- | --- |
| `monolith` | One agent consumes unsafe context without a handoff or memory gate. |
| `naive_swarm` | Roles exist, but handoff and memory checks are advisory or absent. |
| `bounded_swarm` | The same attempted transfer is blocked or allowed by ASH contracts before it can affect the next role. |

Current scenarios:

| Scenario | Contract used |
| --- | --- |
| `handoff_label_stripping` | `verify_handoff` catches source-label loss. |
| `authority_expansion` | `verify_handoff` catches delegated authority expansion. |
| `tool_result_injection` | `verify_handoff` catches untrusted tool output without provenance. |
| `approval_laundering` | `verify_handoff` catches approval purpose drift. |
| `missing_envelope_recovery` | `verify_handoff(None, ...)` fails closed on absent metadata. |
| `malformed_envelope` | `verify_raw_handoff` fails closed on schema-invalid envelope metadata. |
| `verifier_outage` | `verify_handoff(..., verifier_available=False)` blocks unchecked consumption. |
| `memory_stale_recall` | `validate_memory_read` catches stale recall after TTL expiry. |
| `cross_user_memory` | `validate_memory_read` catches scope crossing. |
| `memory_trust_precedence` | `validate_memory_read` catches lower-trust memory overriding higher-trust memory. |

## Commands

List scenarios and modes:

```bash
ash local-swarm --list
```

Dry-run only, no network and no files:

```bash
ash local-swarm
```

Write deterministic artifacts without model calls:

```bash
ash local-swarm --write-dry-run --out reports/local-swarm
ash validate reports/local-swarm
```

A committed deterministic example is available at `examples/local-swarm-report/`:

```bash
ash validate examples/local-swarm-report
```

Run bounded sequential local-model role calls through Ollama:

```bash
ash local-swarm --execute \
  --model prometheus-qwen15b-lowctx:latest \
  --max-requests 80 \
  --out reports/local-swarm-prometheus
ash validate reports/local-swarm-prometheus
```

For a smaller smoke, select one scenario and one mode:

```bash
ash local-swarm --execute \
  --scenario handoff_label_stripping \
  --mode bounded_swarm \
  --model prometheus-qwen15b-lowctx:latest \
  --max-requests 4 \
  --out reports/local-swarm-prometheus-smoke
```

The command refuses `calculator` / `calculator:latest`. That local model is reserved for
the trading research project and must not be consumed by ASH runs.

## Artifacts

`local_swarm_summary.json`
: Machine-readable scenario outcomes, metrics, and optional role-call hashes.

`local_swarm_report.md`
: Human-readable summary for review.

`run_index.json`
: Standard run manifest so `ash list-runs` can index the result.

## Metrics

The main metric is the difference between naive and bounded failure counts:

```text
bounded_failure_reduction_vs_naive = (naive_failures - bounded_failures) / naive_failures
```

For the current deterministic scenario set, `bounded_swarm` should block all ten modeled
boundary failures that `naive_swarm` accepts.

The summary also reports:

- `contract_coverage`: bounded-swarm blocked scenarios divided by declared scenarios.
- `unique_blocked_reasons`: distinct deterministic blocker classes exercised.
- `evidence_completeness`: each result has a deterministic verdict and evidence note.
- `role_transcript_hash_coverage`: optional model responses that produced stored hashes.
- `adapter_error_rate`: optional local-model calls that failed at the adapter layer.

## Claim Boundaries

Allowed:

- "The bounded swarm blocks these synthetic handoff, memory, approval/tool, and verifier
  outage boundary failures."
- "The optional local model produced role text, but deterministic contracts made the
  safety decision."
- "This supports the research hypothesis that role separation needs enforceable
  contracts, not just multiple agents."

Not allowed:

- "This proves the model/system is safe."
- "The local model passed the benchmark."
- "A swarm is secure because it has multiple agents."
- "The scenarios prove real-world exploitability or production coverage."
- "Optional local-model role text is a verifier decision."
