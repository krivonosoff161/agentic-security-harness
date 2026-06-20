# Research claims registry

> Last reviewed: 2026-06-20.
>
> This is a status table for research claims in Agentic Security Harness. Each row
> tracks one claim from hypothesis through evidence artifacts. This is not a marketing
> document; it is a working research spine.

## Status definitions

| Status | Meaning |
|---|---|
| `hypothesis` | A problem area has been identified. No formal model or code yet. |
| `formal_model_draft` | A draft formal model or invariant exists in documentation. |
| `executable_invariant` | Deterministic code implements the invariant. |
| `synthetic_validation` | The invariant is validated against synthetic fixtures. |
| `local_empirical` | Local run evidence exists but is not public-example quality. |
| `public_example` | Validated artifact is committed in `examples/` or another explicitly curated tracked artifact path. |
| `planned` | Intentionally deferred to a future phase. |
| `superseded` | Replaced by a newer claim or design. |

## Claim registry

| Claim | Boundary / topic | Status | Theory doc | Code mapping | Tests | Evidence artifacts | What this proves | What this does NOT prove | Next step |
|---|---|---|---|---|---|---|---|---|---|
| Data boundary / envelope preservation | Primary public coverage for envelope labels, recipients, purpose, classification immutability, handoff labels, provider forwarding gates, fail-closed recovery for a missing required envelope, and memory write/read envelope drift. Tool envelope uses are adjacent coverage, not primary proof. | `public_example` | `docs/theory/data-boundary.md`, `docs/agentic-boundary-model.md` | `src/agentic_security_harness/patterns.py` (data-boundary patterns), `src/agentic_security_harness/envelope_policy.py`, `src/agentic_security_harness/demo_agent.py`, `src/agentic_security_harness/protected_demo_agent.py` | `tests/test_envelope_policy.py`, `tests/test_runner.py`, `tests/test_demo_agent.py` | `examples/comparison-report/`, `ash validate examples/` passes | The shipped 24-pattern corpus can produce a visible 24 -> 0 modeled-risk reduction between demo targets under deterministic local replay; the six primary data-boundary patterns are part of that corpus. | A real deployed agent is secure. Envelope labels prove provenance correctness. Complete memory-governance behavior for real deployed memory stores is not covered. Tool-result trust and cross-provider label survival are not yet covered as primary data-boundary claims. | Maintain parity between corpus, examples, and docs; implement multi-hop laundering and cross-provider label-loss gaps separately. |
| Capability delegation / authority non-expansion | Delegated authority scope, TTL, depth, and revocation must not expand across agent hops. | `synthetic_validation` | `docs/inter-agent-handoff-integrity.md` (authority section), `docs/research-roadmap.md` | `handoff_integrity.py` (authority checks), `patterns.py` (`capability.delegation_chain_drift`) | `tests/test_handoff_integrity.py`, `tests/test_toy_multi_agent.py` | `reports/handoff-toy-comparison` (local validated) | A protected receiver blocks capability scope expansion under deterministic synthetic conditions. | A real multi-agent framework enforces authority boundaries. | Extend with additional delegation-depth and TTL-expansion fixtures. |
| Audit hash-chain integrity | Append-only audit entries with previous_hash must detect deletion, reorder, and edit. | `public_example` | `docs/research-roadmap.md` (audit.hash_chain_tamper section) | `src/agentic_security_harness/patterns.py` (`audit.hash_chain_tamper`), target adapters | `tests/test_runner.py`, `tests/test_v07_patterns.py` | `examples/comparison-report/` includes `audit.hash_chain_tamper`; `ash validate examples/` passes | Deterministic hash-chain tamper is detectable in synthetic audit trails under the committed corpus-level example. | Real audit logs are tamper-proof; a dedicated audit-only public showcase exists. | Add a dedicated audit-integrity theory doc and optional curated audit-only showcase. |
| Memory governance / TTL / provenance | Memory entries must carry provenance, trust level, TTL, and cross-user isolation. | `synthetic_validation` | `docs/research-roadmap.md` (memory_governance patterns), `docs/agentic-boundary-model.md` | `src/agentic_security_harness/patterns.py` (`memory_governance.*`), `src/agentic_security_harness/demo_agent.py` (memory subsystem) | `tests/test_runner.py`, `tests/test_demo_agent.py` | `examples/comparison-report/` (memory patterns included in 24-pattern corpus) | Deterministic memory-governance failures are detectable under synthetic conditions. | Real cross-session memory information-flow control. | Add delayed-recall and cross-user variation fixtures. |
| Inter-agent handoff integrity | Provenance, source labels, payload integrity, policy version, and recovery metadata survive worker-to-senior handoffs. | `synthetic_validation` | `docs/inter-agent-handoff-integrity.md`, `docs/handoff-toy-topology.md` | `handoff_integrity.py` (full verifier), `toy_adapters.py` (toy-multi-agent, protected-toy-multi-agent) | `tests/test_handoff_integrity.py`, `tests/test_toy_multi_agent.py` | `reports/handoff-toy-comparison` (local validated) | A deterministic local toy topology models malformed handoffs and verifies that a protected receiver blocks them. | A live multi-agent framework preserves handoff integrity. Semantic truthfulness is solved by hash checks. | Add canary operations, additional payload types, and evidence artifacts. |
| Local Prometheus weak-model evidence quality | Weak local models (Ollama qwen2.5:1.5b) produce inconclusive/error results, not benchmark findings. | `local_empirical` | `docs/local-prometheus-workflow.md`, `docs/local-model-profiles.md` | `src/agentic_security_harness/external_runner.py` (prompt-only external path) | `tests/test_external.py`, `tests/test_local_suite.py` | `reports/local-prometheus-lowmem-smoke-qwen2.5-1.5b` (local scratch, not committed) | A weak local model can be exercised through the external path; the harness correctly classifies weak evidence as inconclusive/error. | Public benchmark finding. Model leaderboard result. | Promote to documented showcase after curation, repeats, and `ash validate`. |

## How to read this table

- **Status** is the current stage. A claim can move forward (hypothesis -> formal_model_draft -> executable_invariant -> synthetic_validation -> local_empirical -> public_example) or be superseded.
- **Theory doc** links to the public document where the claim is formally described.
- **Code mapping** links to the source files that implement the invariant.
- **Tests** links to the test files that validate the invariant.
- **Evidence artifacts** links to committed or local run artifacts that prove the claim.
- **What this proves / does NOT prove** is the conservative claim boundary.

## Closure notes

| Closure | Claim | Public status after closure | Public evidence | Private/local derivation |
|---|---|---|---|---|
| DB-1 | Data boundary restriction model | `formal_model_draft` completed and promoted into the public theory module. | `docs/theory/data-boundary.md` defines `E_out <= E_in`, field-level non-expansion rules, policy caveats, and non-claims. | Owner-retained local derivation note; not committed and not public evidence. |
| DB-2 | Missing envelope recovery | `public_example` after deterministic corpus implementation. | `data_boundary_missing_envelope_recovery` is in the corpus; `examples/comparison-report/` validates vulnerable finding vs protected pass. | Owner-retained local verification checklist; not committed and not public evidence. |
| DB-3 | Memory write/read envelope drift | `public_example` after deterministic corpus implementation. | `data_boundary_memory_envelope_drift` is in the 24-pattern corpus; `tests/test_envelope_policy.py` validates the field-level restriction relation and `examples/comparison-report/` validates vulnerable finding vs protected pass. | Owner-retained local verification checklist; not committed and not public evidence. |

## Rules for this registry

- Do not upgrade a claim status without a corresponding artifact or test.
- Do not claim `public_example` if the artifact is only in local `reports/`, even when it validates locally.
- Do not claim `synthetic_validation` without passing deterministic tests.
- Every claim must have a "does NOT prove" column to prevent scope creep.
- Superseded claims remain in the table with their final status for traceability.

## Claim boundary

Allowed:

> The project maintains a research claims registry that tracks the status of each
> research claim from hypothesis through validated evidence artifacts.

Not allowed:

- treating this registry as proof that any claim is universally true;
- upgrading claim status without evidence;
- claiming a claim is `public_example` when it is only local scratch.
