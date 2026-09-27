# Ecosystem foundation matrix

This reconciles the **17 original catalog questions**, not 17 independent proofs and
not the 24 seed patterns. The [machine-readable matrix](foundation-matrix.json) is
checked against the catalog, current pattern IDs, source paths and test files.
The public [contract conclusions and evidence limits](theory/foundation-obligations.md)
state the reviewable obligations; complete working derivations remain outside public Git.

Status: local candidate review against the source baseline recorded in the JSON.
Nothing here declares a new release, an independent human review, or universal safety.
`bounded_code` means a predicate has executable checks; `partial_model` leaves part of
the question outside the model; `scripted_control` is a prescribed toy response;
`planned` has no claimed implementation. None is a whole-question completion certificate.

## Every original question

Each row states a falsifiable condition, its mathematical obligations and concrete
Core source/test anchors. Companion ownership below is part of the row's scope.

### 1. Shared-chat data boundaries

Actual recipient must belong to the preserved allow-set; storage requires can_store.

- Argument: L1, L4. Evidence class: `partial_model`.
- Source-owned contours: core, router, filter, playbooks.
- Core code: [models.py](../src/agentic_security_harness/models.py), [envelope_policy.py](../src/agentic_security_harness/envelope_policy.py), [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_memory_governance.py](../tests/test_memory_governance.py).
- Remaining question: Authenticate initial labels and actual shared-chat recipient identity.

### 2. Delayed instructions

Retrieved content cannot itself create an action grant; expiry uses a fixed epoch.

- Argument: L2, L4. Evidence class: `scripted_control`.
- Source-owned contours: core, handoff, playbooks.
- Core code: [memory_governance.py](../src/agentic_security_harness/memory_governance.py), [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_memory_governance.py](../tests/test_memory_governance.py).
- Remaining question: Test semantic delayed activation beyond the scripted rejection branch.

### 3. Reclassification

Sensitivity cannot decrease and classification-source identity cannot self-promote.

- Argument: L1, L4. Evidence class: `bounded_code`.
- Source-owned contours: core, transfer, filter.
- Core code: [envelope_policy.py](../src/agentic_security_harness/envelope_policy.py), [quarantine_connector.py](../src/agentic_security_harness/quarantine_connector.py).
- Checks: [test_envelope_policy.py](../tests/test_envelope_policy.py), [test_quarantine_connector.py](../tests/test_quarantine_connector.py).
- Remaining question: Authenticated initial classification is outside label comparison.

### 4. Recipient confusion

An actual recipient must satisfy the preserved restriction at dispatch.

- Argument: L1, L4. Evidence class: `bounded_code`.
- Source-owned contours: core, transfer, router.
- Core code: [envelope_policy.py](../src/agentic_security_harness/envelope_policy.py), [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py), [runtime_gateway.py](../src/agentic_security_harness/runtime_gateway.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_runtime_gateway.py](../tests/test_runtime_gateway.py).
- Remaining question: Reconcile empty-list semantics and bind real recipient identity at every adapter.

### 5. Memory poisoning

No-store and read-time restrictions survive the write/store/read path.

- Argument: L1, L2, L4. Evidence class: `partial_model`.
- Source-owned contours: core, handoff, playbooks.
- Core code: [memory_governance.py](../src/agentic_security_harness/memory_governance.py).
- Checks: [test_memory_governance.py](../tests/test_memory_governance.py), [test_protected.py](../tests/test_protected.py).
- Remaining question: Semantic poisoning and forgotten provenance are not solved by TTL.

### 6. Tool permissions

Only a policy-bound exact action may reach the no-op executor.

- Argument: L1, L4. Evidence class: `bounded_code`.
- Source-owned contours: core, filter, playbooks.
- Core code: [runtime_gateway.py](../src/agentic_security_harness/runtime_gateway.py), [quarantine_connector.py](../src/agentic_security_harness/quarantine_connector.py), [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py).
- Checks: [test_runtime_gateway.py](../tests/test_runtime_gateway.py), [test_quarantine_gateway_composition.py](../tests/test_quarantine_gateway_composition.py).
- Remaining question: Prove complete mediation for any future real executor separately.

### 7. Cross-agent contamination

Required parent labels are retained; payload commitment matches supplied bytes.

- Argument: L1, L3, L5. Evidence class: `partial_model`.
- Source-owned contours: core, transfer, handoff.
- Core code: [handoff_integrity.py](../src/agentic_security_harness/handoff_integrity.py), [toy_adapters.py](../src/agentic_security_harness/toy_adapters.py).
- Checks: [test_handoff_integrity.py](../tests/test_handoff_integrity.py), [test_toy_multi_agent.py](../tests/test_toy_multi_agent.py).
- Remaining question: Parent authenticity, complete ancestry and a global replay ledger remain separate.

### 8. Multimodal channel confusion

A perception transcript is data and cannot itself grant action authority.

- Argument: L4. Evidence class: `scripted_control`.
- Source-owned contours: core, transfer, playbooks.
- Core code: [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_demo_agent.py](../tests/test_demo_agent.py).
- Remaining question: No raw image/audio/sensor or arbitrary decoder enforcement is exercised.

### 9. Approval laundering

Approval must bind the exact action/context; display text alone is not a grant.

- Argument: L4, L5. Evidence class: `partial_model`.
- Source-owned contours: core, transfer, playbooks.
- Core code: [runtime_gateway.py](../src/agentic_security_harness/runtime_gateway.py), [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py).
- Checks: [test_runtime_gateway.py](../tests/test_runtime_gateway.py), [test_protected.py](../tests/test_protected.py).
- Remaining question: Human comprehension and authenticated consent are not established by a summary.

### 10. Loops and budgets

A counted local loop cannot exceed its bound; receipt arithmetic must reconcile.

- Argument: L6. Evidence class: `bounded_code`.
- Source-owned contours: core, router, filter.
- Core code: [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py), [receipt_auditors.py](../src/agentic_security_harness/receipt_auditors.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_receipt_auditors.py](../tests/test_receipt_auditors.py).
- Remaining question: No global atomic budget reservation or truthful provider-usage guarantee.

### 11. Audit suppression

Untrusted labels cannot suppress the local audit append operation.

- Argument: L4, L5. Evidence class: `partial_model`.
- Source-owned contours: core, handoff, playbooks.
- Core code: [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py), [validation.py](../src/agentic_security_harness/validation.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_foundation_contracts.py](../tests/test_foundation_contracts.py).
- Remaining question: Producer completeness and omission-resistant external anchoring are not supplied.

### 12. Provider boundary leakage

No-forward metadata must prevent the declared egress path.

- Argument: L1, L4. Evidence class: `partial_model`.
- Source-owned contours: core, router, filter.
- Core code: [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py), [provider_tool_adapters.py](../src/agentic_security_harness/provider_tool_adapters.py), [receipt_auditors.py](../src/agentic_security_harness/receipt_auditors.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_provider_tool_adapters.py](../tests/test_provider_tool_adapters.py), [test_receipt_auditors.py](../tests/test_receipt_auditors.py).
- Remaining question: Provider retention, hidden routing and out-of-path sends need separate evidence.

### 13. Delegation drift

Child scope is a subset of every supplied parent scope, including empty scope.

- Argument: L3. Evidence class: `bounded_code`.
- Source-owned contours: core, transfer, handoff.
- Core code: [handoff_integrity.py](../src/agentic_security_harness/handoff_integrity.py).
- Checks: [test_handoff_integrity.py](../tests/test_handoff_integrity.py), [test_foundation_contracts.py](../tests/test_foundation_contracts.py).
- Remaining question: Child depth ceiling is self-declared; authenticated parent depth/revocation is absent.

### 14. Tool schema deception

A changed schema digest cannot satisfy the trusted exact schema pin.

- Argument: L4, L5. Evidence class: `partial_model`.
- Source-owned contours: core, playbooks.
- Core code: [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py), [runtime_gateway.py](../src/agentic_security_harness/runtime_gateway.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_runtime_gateway.py](../tests/test_runtime_gateway.py).
- Remaining question: Schema semantics, trusted pin distribution and real MCP execution are separate.

### 15. Audit chain tampering

Changed interior data cannot match a trusted later commitment under hash assumptions.

- Argument: L5. Evidence class: `partial_model`.
- Source-owned contours: core, handoff.
- Core code: [protected_demo_agent.py](../src/agentic_security_harness/protected_demo_agent.py), [validation.py](../src/agentic_security_harness/validation.py).
- Checks: [test_protected.py](../tests/test_protected.py), [test_foundation_contracts.py](../tests/test_foundation_contracts.py).
- Remaining question: A re-rooted or truncated self-consistent history needs independent head/length binding.

### 16. Trust gate without recovery

Safe bounded recovery needs both non-expansion and progress to an approved terminal state.

- Argument: L4, L8. Evidence class: `planned`.
- Source-owned contours: core, handoff, playbooks.
- Core code: no implementation claimed.
- Checks: planned; no executable coverage claimed.
- Remaining question: No shipped recovery.trust_gate_no_path scenario proves this; a gate can deny forever.

### 17. Read-time envelope drift

Stored <= write, read <= stored, elapsed <= earliest finite deadline from original write.

- Argument: L1, L2. Evidence class: `bounded_code`.
- Source-owned contours: core, handoff.
- Core code: [envelope_policy.py](../src/agentic_security_harness/envelope_policy.py), [memory_governance.py](../src/agentic_security_harness/memory_governance.py).
- Checks: [test_envelope_policy.py](../tests/test_envelope_policy.py), [test_memory_governance.py](../tests/test_memory_governance.py), [test_foundation_contracts.py](../tests/test_foundation_contracts.py).
- Remaining question: Clock trust, omitted elapsed time and deletion/retention remain outside this predicate.

## Companion boundaries that cannot be collapsed into Core

| Owner | Examined source seam and its own tests | What composes / what does not |
|---|---|---|
| [Transfer](https://github.com/krivonosoff161/agentic-transfer-verifier/tree/847f62d0d68d8f76b98f704283c185ed2c85186b) | `verifier.py::verify_envelope/assess_transfer_risk`; `test_verifier.py`, `test_risk_model_v02.py` | Structural findings and weighted risk are reports, not a trusted parent graph. Rejecting self-parent is not general cycle rejection. |
| [Handoff](https://github.com/krivonosoff161/ai-agent-handoff/tree/46aba8284dd1a006bf9739edaa1c9d3212b7e735) | `agent_guard/handoff_metadata.py::project_handoff_metadata`; `test_handoff_metadata.py` | Adjacent sequence, byte/parent binding and authority-none projection. Requires caller-supplied previous state; not authenticated global custody. |
| [Router](https://github.com/krivonosoff161/llm-router/tree/2a743af4518985f7d8c51a8870a53f7290886b23) | `llm_router/receipt.py`; `test_receipt.py`; Core `receipt_auditors.py` | Canonical receipt and fixed-point arithmetic. Usage/prices are declared; a consistent receipt is not provider attestation or permission. |
| [Filter](https://github.com/krivonosoff161/llm-cheap-filter/tree/17f13fd3986a2869686e59ca62123340fd56178b) | `llm_cheap_filter/policy.py::EscalationPolicy.decide`, `pipeline.py`, triage receipt; `test_pipeline.py`, `test_triage_receipt.py` | drop/cheap/chief is workload routing, not allow/deny. A caller must never turn a low score into a grant or erase a deterministic rejection. |
| [Playbooks](https://github.com/krivonosoff161/llm-safety-playbooks/tree/190769a15a44f5a5af790b33fc37724e6417c27f) | packaged `policy_pack_bytes`; source `tools/policy_pack.py`; `test_policy_pack_contract.py`; Core `policy_pack_extension.py` | Wheel exposes verified data bytes; evaluator is a distinct source seam and Core validates its own exact-pinned pack. Guidance never becomes execution. |

Package version, current source commit and installed wheel provenance are separate
identities. This source review does not upgrade older wheel observations to current-main
proof. Any source repair belongs in its owning repository, with its own CI/regression.
A Core test cannot silently certify all companion implementations.

Runtime Guard is a separate private effect-boundary project. Its executor/one-time receipt
obligations must be reviewed privately; its code, private math and evidence are not copied
into this public matrix. It is not an extra enforcement feature of the public Core package.

## Cross-contour composition obligations

1. **Empty versus unspecified:** Core DataEnvelope uses empty recipient/purpose sets as
   no permissions; Core toy HandoffEnvelope uses empty allowed_recipients as unconstrained.
   An adapter must translate explicitly or reject ambiguity, never treat emptiness as authority.
2. **No inherited authority from evidence:** Transfer PASS, Handoff metadata, Router
   receipt, Filter route and Playbook advice all remain observations. None is a Gateway grant.
3. **No digest substitution:** bind exact bytes plus schema/source/policy to a trusted pin.
   Rehashing attacker-controlled content and its expected digest proves no origin.
4. **Time and replay are independent:** common-epoch expiry does not supply an atomic spent
   set; sequence validation needs trustworthy previous state and cannot invent missing ancestors.
5. **All effects pass the boundary:** pure no-op composition checks declared paths only.
   Any new provider/tool/process executor needs a separate complete-mediation argument.

The [installed ecosystem example](../examples/installed-ecosystem/README.md) and
`test_quarantine_gateway_composition.py`, `test_advisory_gateway_connector.py`,
`test_receipt_auditors.py`, `test_cross_repo_policy_pack_compatibility.py` test explicit
parts of this composition. They do not implement every remaining obligation.

## Candidate corrections and next depth work

- Fixed known-empty parent scope and narrowed memory TTL; positive, negative and finite
  regressions accompany the code. These are local candidate changes, not published fixes.
- Corrected depth/freshness/parent-argument wording to match actual toy-verifier behavior.
- Preserved characterization tests for replay, self-declared depth and trace truncation.
- Replaced cardinality-only label metrics with intersection/set-difference reasoning;
  structural scores remain non-authoritative.
- Next substantive gaps: authenticated ancestry/replay context; trace omission detection;
  bounded recovery/progress (question 16); real modality/semantic validation with an
  independently defined oracle. These require designed contracts and discriminating
  checks, not another metadata-only PASS or a new marketing claim.
