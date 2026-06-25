# Deepening backlog

This backlog turns weak spots and findings into bounded follow-up variations. It is not
a full combinatorial sweep.

## Active deepening candidates

| Candidate | Starts from | Variation | Max scope | Stop condition |
|---|---|---|---|---|
| `data-boundary.local-json-reliability-rerun` | `weak.local_prometheus.qwen15b_json_reliability` | Same scenario/variant, higher timeout, 2-3 repeats. | 6 patterns x 1 variant x <=3 repeats. | If adapter errors remain, classify runtime profile as unreliable for this suite. |
| `data-boundary.multi-turn-handoff` | `data-boundary` scenario matrix row | Add timeline with original envelope, untrusted handoff, and final user continuation. | 2-3 timeline steps, one variant first. | If invariant cannot be checked deterministically, keep design-only. |
| `memory.delayed-recall-source-label` | `memory-governance` | Delayed recall from untrusted memory source. | 1 pattern family, 2 variants. | Use the memory-governance invariant layer first; if raw trace cannot expose source labels, update trace schema before expanding. |
| `authority.revocation-gap` | `authority-control` | Revoked or expired authority is reused as current authority. | 1 pattern family, 1-2 variants. | Do not claim revocation coverage until a fixture/model and tests exist. |
| `approval.missing-context-recovery` | `approval-audit` | Approval request missing envelope fields should trigger review/recovery path. | 1 pattern family, 2 variants. | If output cannot distinguish refuse/review/recover, add validator vocabulary first. |
| `semantic.long_session_drift` | `semantic-drift-propagation-closure.md`, `semantic-consensus-laundering-closure.md` | Longer low-amplitude pressure tries to move a worker from the canonical A/B/C mapping before the handoff. | Multi-turn deterministic rows first, then optional private local-model probes. | Stop if the first drift turn cannot be detected without raw private transcripts. |

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
4. Keep the bounded local Prometheus suite small: named profiles, dry-run first, validated
   local artifacts only after explicit `--execute`.
5. Add richer showcase generator views over JSON artifacts (#23).
6. Deepen `semantic.long_session_drift` only after the SEM-1 and SEM-2 closure docs
   remain stable under documentation and artifact validation.

Items #25, #21, #23, #20, and #19 now have shipped slices. The next sequence is only
selected timeline/local-runtime deepening variants with explicit deterministic invariants
and new issues for any broader model sweep.

## Recently promoted

| Candidate | Result |
|---|---|
| `handoff.verifier-canary` | Promoted to committed public example at `examples/handoff-toy-comparison/`; validated by `ash validate examples/handoff-toy-comparison`. |
| `authority.claimed-supervisor` | Covered as a verifier-axis test for issuer mismatch in `tests/test_handoff_integrity.py`; not yet a separate corpus pattern. |
