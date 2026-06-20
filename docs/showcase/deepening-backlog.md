# Deepening backlog

This backlog turns weak spots and findings into bounded follow-up variations. It is not
a full combinatorial sweep.

## Active deepening candidates

| Candidate | Starts from | Variation | Max scope | Stop condition |
|---|---|---|---|---|
| `data-boundary.local-json-reliability-rerun` | `weak.local_prometheus.qwen15b_json_reliability` | Same scenario/variant, higher timeout, 2-3 repeats. | 6 patterns x 1 variant x <=3 repeats. | If adapter errors remain, classify runtime profile as unreliable for this suite. |
| `data-boundary.multi-turn-handoff` | `data-boundary` scenario matrix row | Add timeline with original envelope, untrusted handoff, and final user continuation. | 2-3 timeline steps, one variant first. | If invariant cannot be checked deterministically, keep design-only. |
| `memory.delayed-recall-source-label` | `memory-governance` | Delayed recall from untrusted memory source. | 1 pattern family, 2 variants. | If raw trace cannot expose source labels, update trace schema before expanding. |
| `authority.claimed-supervisor` | `authority-control` | Claimed higher authority attempts to expand delegated scope. | 1 pattern family, 2 variants. | If target cannot represent delegated identity, keep toy-only. |
| `handoff.verifier-canary` | `handoff-toy-comparison` local artifact | Re-run expected-good and expected-block handoff cases as a canary for verifier liveness and fail-closed behavior. | Existing 2 handoff patterns only. | If protected target consumes a malformed handoff or validation fails, stop expansion and fix verifier/reporting first. |
| `approval.missing-context-recovery` | `approval-audit` | Approval request missing envelope fields should trigger review/recovery path. | 1 pattern family, 2 variants. | If output cannot distinguish refuse/review/recover, add validator vocabulary first. |

## Variation budget

| Level | Budget |
|---|---|
| Smoke | 1 scenario, 1 variant, 1 repeat. |
| Reliability | Same scenario/variant, 2-3 repeats. |
| Deepening | One axis changed at a time. |
| Public showcase | Only after validation, failure card, and reproduce command exist. |

## Not scheduled

- Full provider/model leaderboard.
- All scenarios against all local models.
- Live tool execution.
- Live third-party systems.
- Committed local scratch reports without curation.

## Next implementation order

1. Build public showcase skeleton from these docs (#25).
2. Add trace replay / failure-card generation from artifacts (#21).
3. Implement the first scenario timeline from [scenario-timeline.md](../scenario-timeline.md).
4. Promote local Prometheus smoke from docs-only workflow to a small suite (#19).
5. Add richer showcase generator views over JSON artifacts (#23).
