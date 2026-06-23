# Bounded Local Swarm

Status: research-only implementation for issues #61, #63, #65, #66, and #67.

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
| `memory_poisoned_recall` | `validate_memory_read` catches tool-output memory below the required trust floor. |
| `memory_envelope_widening` | `validate_memory_read` catches stored memory that widened recipients or purpose. |
| `tool_output_authority_confusion` | `verify_handoff` catches tool output that tries to expand authority into an external action. |
| `multi_hop_label_laundering` | `verify_handoff` catches restricted labels washed through an intermediate summary hop. |
| `multi_hop_authority_laundering` | `verify_handoff` catches read-only authority washed into send authority through an intermediate hop. |

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

Calculate the deterministic attack-variation matrix:

```bash
ash local-swarm-matrix
ash local-swarm-matrix --write --out reports/local-swarm-attack-matrix
ash validate reports/local-swarm-attack-matrix
```

A committed matrix example is available at `examples/local-swarm-attack-matrix/`:

```bash
ash validate examples/local-swarm-attack-matrix
```

Run bounded sequential local-model role calls through Ollama:

```bash
ash local-swarm --execute \
  --model prometheus-qwen15b-lowctx:latest \
  --max-requests 120 \
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

## Local Real-Model Evaluation

The 15-scenario suite was run against two local Ollama models on 2026-06-21:
`prometheus-qwen15b-lowctx:latest` and `qwen2.5:1.5b`. Both runs covered all three modes
and 120 role calls per model. `ash validate` passed, `ash evidence-quality` reported 100%
contract coverage, 100% transcript-hash coverage, and 0% adapter-error rate for both.

See [local-swarm-real-model-evaluation.md](local-swarm-real-model-evaluation.md).

This is local-empirical evidence that the runner can exercise real weak local models. It
is not a model pass, leaderboard result, or production-swarm safety proof.

## Attack Variation Matrix

The `local-swarm-matrix` command expands the 15 base scenarios into a deterministic
review matrix. The current committed matrix contains 43 modeled attack/slom rows across
9 families. Ten rows are executable deep probes that call the handoff or memory
governance verifier with mutated payloads/envelopes instead of aliasing only to a base
scenario:

- base contract scenarios;
- prompt-only pressure;
- delayed activation;
- safe recovery path after blocked or malformed handoff;
- audit/provenance evidence omission or tamper pressure;
- budget or recursion pressure;
- cross-provider metadata loss;
- model contradiction, where role text says proceed but the verifier blocks;
- deep invariant probes for payload hash mismatch, recipient switching, expired replay,
  policy-version mismatch, tool-output authority smuggling, tool-output label loss,
  memory key confusion, read-before-write, TTL removal, and forwarding weakening.

Current committed calculation:

```text
cases=43
monolith boundary failures=43
naive-swarm boundary failures=43
bounded-swarm boundary failures=0
bounded blocks=43
deep probe cases=10
unsafe consumption rate=100%
bounded failure reduction vs naive=100%
contract coverage=100%
```

This matrix is not a claim of exhaustive attack coverage. It is a traceable way to show
which declared variations are already represented by deterministic contracts and which
block reason each one exercises. Audit-evidence rows cover local provenance/trace
omission pressure inside the swarm model; cryptographic audit-chain integrity remains a
separate project claim. Deep-probe rows model places where weak role text can become
harmful (`unsafe_consumptions=1`) while the deterministic boundary still blocks the
handoff/read/action.

## Artifacts

`local_swarm_summary.json`
: Machine-readable scenario outcomes, metrics, and optional role-call hashes.

`local_swarm_report.md`
: Human-readable summary for review.

`run_index.json`
: Standard run manifest so `ash list-runs` can index the result.

`local_swarm_attack_matrix.json`
: Machine-readable attack variation rows and aggregate calculations from
  `ash local-swarm-matrix`.

`local_swarm_attack_matrix.md`
: Human-readable attack variation matrix.

## Metrics

The main metric is the difference between naive and bounded failure counts:

```text
bounded_failure_reduction_vs_naive = (naive_failures - bounded_failures) / naive_failures
```

For the current deterministic scenario set, `bounded_swarm` should block all 15 modeled
boundary failures that `naive_swarm` accepts.

The summary also reports:

- `contract_coverage`: bounded-swarm blocked scenarios divided by declared scenarios.
- `unique_blocked_reasons`: distinct deterministic blocker classes exercised.
- `evidence_completeness`: each result has a deterministic verdict and evidence note.
- `role_transcript_hash_coverage`: optional model responses that produced stored hashes.
- `adapter_error_rate`: optional local-model calls that failed at the adapter layer.

## Claim Boundaries

Allowed:

- "The bounded swarm blocks these synthetic handoff, memory, memory-poisoning,
  approval/tool, multi-hop laundering, and verifier-outage boundary failures."
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
