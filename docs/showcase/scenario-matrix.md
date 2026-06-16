# Scenario matrix

This page maps scenario families to the boundary, topology, current evidence status, and
next deepening direction. It is a public reviewer view; `scenarios.py` remains the code
registry.

| Scenario | Boundary focus | Topology | Current evidence | Next deepening direction |
|---|---|---|---|---|
| `data-boundary` | data envelope, recipient, forwarding, provider boundary | single model / local target / prompt-only external | Implemented; deterministic examples; local Prometheus scratch run produced weak evidence (2 inconclusive, 2 adapter errors). | Split runtime reliability from boundary behavior; rerun with higher timeout/repeats, then add multi-turn handoff variant. |
| `memory-governance` | memory provenance, TTL, scope isolation | memory loop / delayed recall | Implemented deterministic scenario family. | Timeline scenario with delayed recall and untrusted memory source. |
| `tool-selection` | tool schema honesty, permission and selection boundary | agent plus tools (toy target) | Implemented deterministic scenario family. | Keep tool execution local/toy until adapter safety gates exist. |
| `authority-control` | capability delegation, ambient authority, scope expansion | delegated agent / host authority | Implemented deterministic scenario family. | Add claimed-supervisor and delegated-worker timeline variants. |
| `approval-audit` | approval context, audit completeness, hash-chain integrity | human approval loop / audit trail | Implemented deterministic scenario family. | Add missing-context approval and recovery-path variants. |
| `budget-control` | loop, recursion, step budget | multi-step local target | Implemented deterministic scenario family. | Add recursion-depth evidence cards and stop-condition reporting. |
| `perception-boundary` | sensor/OCR/transcript content mistaken for instruction | perception transcript | Implemented deterministic scenario family. | Keep sanitized transcript-only; do not add real media before multimodal policy exists. |
| `all` | full shipped corpus | aggregate run | Validated deterministic comparison example. | Do not use for first local weak-model runs; too broad for low-memory profiles. |

## Scenario status rules

| Status | Meaning |
|---|---|
| Implemented | Scenario exists in `scenarios.py`. |
| Validated example | Committed artifacts validate with `ash validate`. |
| Local scratch | A maintainer local run exists but is not committed public evidence. |
| Needs deepening | The scenario needs selected variations based on evidence. |

## Why not full scenario x model x provider sweeps

The project is designed to deepen by invariant and evidence, not brute-force every
combination. Full cross-products are expensive, hard to interpret, and can make weak
local models look worse because of runtime limits rather than boundary behavior.

Start narrow:

```text
one scenario -> one variant -> one runtime profile -> validate -> classify evidence
```

Only after classification should a variation be added to the deepening backlog.
