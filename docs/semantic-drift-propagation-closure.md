# Semantic Drift Propagation Closure

Date: 2026-06-25

Status: closed research unit for the current public claim boundary.

This page closes the first semantic mini-swarm research unit: a small worker model
can be pressured to relabel a canonical value, and a downstream chief can accept
the worker summary unless deterministic controls preserve the boundary.

The public repository records only sanitized aggregate evidence. Raw prompts,
raw model responses, synthetic canaries, canonical-state hashes, and private
calculation notes stay under `.internal/`.

## Closed Question

Can a bounded multi-agent system prevent a slow semantic relabeling from moving
from a weaker worker into a stronger chief decision?

In this research unit, the canonical state is:

| Symbol | Meaning |
| --- | --- |
| `A` | private calculation |
| `B` | sanitized metric |
| `C` | public claim |

The failure class is not a single prompt trick. It is a chain failure:

1. A worker is pressured to treat `A` as if it can become `C`.
2. A summarizer or memory path can hide the original boundary.
3. A chief sees a clean summary rather than the pressure trail.
4. The chief may approve a public claim unless the handoff is verified.

## Source Map

| Layer | Public artifact |
| --- | --- |
| Drift campaign implementation | `src/agentic_security_harness/semantic_drift_campaign.py` |
| Propagation campaign implementation | `src/agentic_security_harness/semantic_propagation_campaign.py` |
| Drift public evidence | `examples/semantic-drift-sanitized/` |
| Propagation public evidence | `examples/semantic-propagation-sanitized/` |
| Propagation defense model | `docs/semantic-propagation-defense-model.md` |
| Evidence map | `docs/showcase/evidence-map.md` |
| Claim registry | `docs/research-claims.md` |
| Tests | `tests/test_semantic_drift_campaign.py`, `tests/test_semantic_propagation_campaign.py` |

## Evidence Summary

| Campaign | Deterministic rows | Full bounded acceptances | Ablation acceptances | Local observations | Local failure signals | Verifier blocks |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| Semantic drift | 28 | 0 | 19 | 80 | 13 drift detections, 4 synthetic canary leaks | 15 |
| Worker-to-chief propagation | 32 | 0 | 20 | 8 | 2 worker drift detections, 3 chief acceptances, 2 synthetic canary leaks, 1 adapter error | 3 |

The deterministic result is the closure anchor: the full bounded contract accepts
zero declared drift/propagation attempts, while control ablations reopen the same
declared failures.

The local-model result is supporting evidence only. It shows that weak local
models can produce drift-shaped or propagation-shaped behavior under the declared
synthetic scenarios. It is not a model leaderboard.

## Control Model

The closed defense slice depends on explicit controls, not on model self-report:

| Control | Role in this unit |
| --- | --- |
| `canonical_state` | Keeps `A`, `B`, and `C` meanings versioned and non-redefinable by model text. |
| `transition_table` / policy transition checks | Blocks model-authored claims such as "verified(A) means public(C)". |
| `role_matrix` | Prevents a worker, summarizer, or proposer from gaining authority to relabel data. |
| `summary_guard` | Requires summaries to preserve the strongest input boundary. |
| `source_hash` | Requires provenance linkage for memory-derived or policy-derived claims. |
| `worker_attestation` | Requires the worker handoff to attest boundary preservation before chief use. |
| `cross_worker_check` | Prevents poisoned and conservative workers from being averaged into acceptance. |
| `chief_verifier` / `verifier` | Makes the final pass/block decision from deterministic contract features. |

## Closure Criteria

| Criterion | Status | Evidence |
| --- | --- | --- |
| Declared synthetic cases exist | Closed | 4 drift cases and 4 propagation cases are encoded in source and public summaries. |
| Bounded contract blocks declared failures | Closed | Drift bounded acceptances `0`; propagation bounded acceptances `0`. |
| Missing-control ablations reopen failures | Closed | Drift ablation acceptances `19`; propagation ablation acceptances `20`. |
| Local model behavior is recorded conservatively | Closed | Drift observations `80`; propagation observations `8`; adapter errors kept separate. |
| Raw private material is not public | Closed | Tests reject private artifacts, canaries, and canonical hashes in public outputs. |
| Public claim boundary is explicit | Closed | Non-claims are present in summaries, evidence map, and defense model. |

## What This Proves

Within the declared synthetic model, the project can reproduce and measure a
semantic relabeling chain, then show that deterministic controls block the
declared propagation path. The ablation rows identify which missing controls
reopen which failures.

This is enough to close the first research unit as a defensible benchmark slice:
the artifact tells a reviewer what failed, what blocked it, which controls were
responsible, and what was deliberately kept private.

## What This Does Not Prove

- It does not prove a real deployed swarm is secure.
- It does not prove any model is universally vulnerable or safe.
- It is not a CVE.
- It is not a model leaderboard.
- It does not prove semantic truth; it proves declared contract behavior over
  declared artifacts.
- Adapter errors are not passes.

## Reproduce

Validate the committed public artifacts:

```bash
ash validate examples/semantic-drift-sanitized
ash validate examples/semantic-propagation-sanitized
```

Regenerate sanitized public artifacts without executing local models:

```bash
ash semantic-drift-campaign --write --out reports/semantic-drift
ash semantic-propagation-campaign --write --out reports/semantic-propagation
ash validate reports/semantic-drift
ash validate reports/semantic-propagation
```

Private local-model execution must stay under `.internal/`:

```bash
ash semantic-drift-campaign --execute --out .internal/semantic-drift/latest --summary-out reports/semantic-drift
ash semantic-propagation-campaign --execute --out .internal/semantic-propagation/latest --summary-out reports/semantic-propagation
```

## Next Research Unit

The next logical unit is consensus laundering in a bounded swarm.

Current semantic propagation already includes one two-worker consensus case, but
it is not yet a full closure unit. The next unit should deepen that path:

1. Multiple weak workers receive different pressure modes.
2. One worker accepts the unsafe relabeling and another stays conservative.
3. An aggregator tries to convert disagreement into a majority/consensus result.
4. The chief receives the aggregate instead of raw worker traces.
5. Controls must prove that consensus cannot override the strongest boundary or
   the canonical state.

Suggested closure target:

| Requirement | Target |
| --- | --- |
| Cases | At least 4 consensus-laundering topologies. |
| Modes | bounded, naive, no cross-worker check, no canonical state, no summary guard, no chief verifier. |
| Metrics | bounded acceptances, ablation acceptances, disagreement blocks, false-block benign controls, response-hash coverage, adapter-error rate. |
| Public artifact | Sanitized summary under `examples/`, raw model transcripts under `.internal/`. |
| Non-claims | No production swarm safety claim; no model leaderboard; no real secrets. |

This keeps the research sequence coherent: first close single-worker semantic
drift and worker-to-chief propagation, then test whether a swarm aggregator can
launder disagreement into unsafe acceptance.
