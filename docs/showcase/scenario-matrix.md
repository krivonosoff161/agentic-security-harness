# Scenario matrix

This page maps scenario families to the boundary, topology, current evidence status, and
next deepening direction. It is a public reviewer view; `scenarios.py` remains the code
registry.

| Scenario | Boundary focus | Topology | Current evidence | Next deepening direction |
|---|---|---|---|---|
| `data-boundary` | data envelope, recipient, forwarding, provider boundary | single model / local target / prompt-only external | Implemented; deterministic examples; local Prometheus scratch run produced weak evidence (2 inconclusive, 2 adapter errors). | Split runtime reliability from boundary behavior; rerun with higher timeout/repeats, then add multi-turn handoff variant. |
| `memory-governance` | memory provenance, TTL from write time, trust precedence, scope isolation | memory loop / delayed recall | Implemented deterministic scenario family plus executable invariant layer in `memory_governance.py`. | Timeline scenario with delayed recall and untrusted memory source. |
| `tool-selection` | tool schema honesty, permission and selection boundary | agent plus tools (toy target) | Implemented deterministic scenario family. | Keep tool execution local/toy until adapter safety gates exist. |
| `authority-control` | capability delegation, ambient authority, issuer/scope/purpose/TTL/depth non-expansion | delegated agent / host authority | Implemented deterministic scenario family; handoff verifier now covers issuer, scope, purpose, TTL, and depth axes. | Add revocation/expiry variant only after a bounded fixture and tests exist. |
| `inter-agent-handoff` | provenance, source labels, payload integrity, authority non-expansion across worker handoff | local synthetic coordinator/worker handoff | Shipped public toy topology: `toy-multi-agent` exposes label-loss and authority-expansion findings; `protected-toy-multi-agent` blocks them; committed comparison validates with `ash validate examples/handoff-toy-comparison`. | Add only new handoff variants with explicit deterministic invariants; malformed raw-envelope recovery is currently verifier-level, not corpus-level. |
| `local-swarm` | role separation plus enforceable contracts across handoff, memory, approval/tool, multi-hop laundering, and verifier-outage boundaries | monolith vs naive swarm vs bounded swarm | Shipped research-only evidence suite: committed `examples/local-swarm-report/` shows 15 modeled boundary failures accepted by `naive_swarm` and blocked by `bounded_swarm`; committed `examples/local-swarm-attack-matrix/` expands them into 43 rows across 9 families, including 10 executable deep invariant probes for handoff and memory mutations. | Run bounded local-model role calls as evidence-quality probes; add new matrix rows only when the deterministic invariant and non-claim boundary are explicit. |
| `semantic-drift-campaign` | semantic relabeling pressure against canonical parameter meaning | local mini-swarm / private local-model probes | Shipped research-only campaign artifact: committed `examples/semantic-drift-sanitized/` summarizes deterministic bounded-vs-ablation rows and local-model observations without raw prompts, responses, canaries, or canonical-state hashes. | Add new pressure cases only after the public/private boundary and response-hash metrics remain explicit. |
| `semantic-propagation-campaign` | worker-to-chief propagation after semantic drift | local mini-swarm chain / private local-model probes | Shipped research-only defense slice: committed `examples/semantic-propagation-sanitized/` declares 6 controls, 6 control-effect rows, 0 bounded propagation acceptances, 20 ablation acceptances, and 8 sanitized observations with 1 adapter error. | Deepen long-session propagation only with adapter-error accounting, control attribution, and explicit non-claims. |
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

## Campaign Artifacts vs Corpus Scenarios

`semantic-drift-campaign`, `semantic-propagation-campaign`,
`secret-leak-campaign`, and `evidence-campaign` are campaign artifacts, not one-for-one
corpus patterns. They aggregate declared cases, deterministic contract rows, and optional
private local-model observations. They can inform future corpus candidates, but they do
not automatically become shipped corpus coverage.
