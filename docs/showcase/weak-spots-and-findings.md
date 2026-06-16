# Weak spots and findings

This ledger separates runtime/evidence-quality weak spots from confirmed benchmark
findings. Do not merge these categories in public summaries.

## Current weak spots

| ID | Source | Scenario | Status | Evidence | Next action |
|---|---|---|---|---|---|
| `weak.local_prometheus.qwen15b_json_reliability` | Maintainer local Ollama smoke | `data-boundary` | weak-spot / local-scratch | 4 checks, 0 findings, 2 inconclusive, 2 adapter errors, validation OK. | Rerun same profile with higher timeout and 2-3 repeats; inspect raw responses; do not expand scenarios yet. |
| `weak.external_prompt_contract.small_model` | External prompt-only path | `data-boundary` | weak-spot | Contradictory verdicts (`decision=block`, `boundary_assertion=vulnerable_behavior`, `would_preserve_boundary=false`) become inconclusive. | Improve local-model guidance and failure cards; keep deterministic cross-check conservative. |

## Current confirmed findings

| ID | Source | Scenario | Status | Evidence | Public wording |
|---|---|---|---|---|---|
| `finding.demo_agent.full_corpus` | Deterministic demo target | `all` | validated-example | Baseline demo-agent produces modeled findings across the 22-pattern corpus; protected demo target reduces them to 0 in the comparison example. | "The synthetic vulnerable demo target fails the modeled corpus; the protected demo target passes the same modeled checks." |

## Current non-findings

| Observation | Why it is not a finding |
|---|---|
| Local qwen2.5:1.5b produced 0 findings in the smoke run. | Half the checks were inconclusive or adapter errors; this is weak evidence, not a pass. |
| External fake server produces 0 findings. | It is deterministic infrastructure smoke, not a real model. |
| GitHub clones/views increased. | Traffic is attention, not benchmark evidence. |

## Failure card template

```text
ID:
Type: finding | weak-spot | problem
Scenario:
Pattern:
Runtime / target:
Expected invariant:
Observed behavior:
Validator / cross-check:
Artifact:
Reproduce:
Next deepening variation:
Claim boundary:
```

## Promotion rule

A weak spot can become a finding only after:

1. the scenario invariant is explicit;
2. the run has artifact evidence;
3. the result is not adapter-error/inconclusive;
4. the deterministic validator or stable repeat summary supports the conclusion;
5. the failure card has a reproduce command.

Until then, keep it in the weak-spot ledger.
