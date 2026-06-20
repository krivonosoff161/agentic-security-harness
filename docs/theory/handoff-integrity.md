# Theory: inter-agent handoff integrity

> Status: pilot theory module. Formal executable invariant prototype validated on
> deterministic synthetic topology.
>
> Last reviewed: 2026-06-18.

## 1. Claim

A senior agent should not treat a worker result as trusted fact unless the handoff
preserves enough evidence to verify provenance, payload integrity, authority scope,
freshness, and policy compatibility. A deterministic verifier can enforce these invariants
on synthetic topologies.

## 2. Formal objects

| Object | Definition |
|---|---|
| `HandoffEnvelope` | A typed record carrying identity, payload hash, provenance labels, authority scope, freshness, policy version, and verification metadata. |
| `HandoffPayload` | The data being transferred (summary, tool output, capability, approval, memory recall). |
| `Verdict` | A deterministic decision: `pass`, `blocked`, `needs_review`, `quarantine`. |
| `FailureReason` | A hard blocker or review condition: `missing_envelope`, `missing_provenance`, `integrity_mismatch`, `label_loss`, `authority_expansion`, `recipient_violation`, `stale_or_replayed`, `policy_mismatch`, `verifier_error`. |
| `StructuralScore` | Reporting metadata derived from hard blockers: 1.0 (blocked), 0.5 (review), 0.0 (pass). |
| `SemanticScore` | Reporting metadata derived from unsafe consumption count: `n_unsafe / n_consumptions`. |
| `CombinedScore` | Weighted combination: `0.7 * min(1, multiplier * S_structural) + 0.3 * S_semantic`. |

## 3. Invariants

| Invariant | Deterministic condition | Failure reason |
|---|---|---|
| Payload byte integrity | `payload_hash == SHA-256(JSON-canonical(payload))` | `integrity_mismatch` |
| Source-label preservation | Sender labels are a subset of receiver labels | `label_loss` |
| Required provenance | Required payload types carry non-empty `source_labels` | `missing_provenance` |
| Authority non-expansion | Delegated scope is a subset of parent scope | `authority_expansion` |
| Recipient policy | Receiver is in `allowed_recipients` when constrained | `recipient_violation` |
| Freshness | `current_time <= expires_at` | `stale_or_replayed` |
| Policy compatibility | Sender policy is in receiver-supported policy versions | `policy_mismatch` |
| Fail-closed verifier | Unavailable verifier blocks, not passes | `verifier_error` |

## 4. Verifier decision

The verdict is a blocker decision, not a score:

```text
blocked      if any hard blocker fired
needs_review if no hard blocker fired but review-only evidence is missing
pass         otherwise
```

The structural score is reporting metadata. It does not determine the verdict.
The semantic score is reporting metadata. It does not determine the verdict.
The combined score is reporting metadata for cross-scenario comparison only.

## 5. Metrics

| Metric | Formula | Range | Purpose |
|---|---|---|---|
| `S_structural` | 1.0 if hard blocker, 0.5 if review, 0.0 otherwise | [0, 1] | Structural risk for triage. |
| `S_semantic` | `n_unsafe / n_consumptions` (0 if 0 consumptions) | [0, 1] | Unsafe consumption rate. |
| `S_combined` | `0.7 * min(1, multiplier * S_structural) + 0.3 * S_semantic` | [0, 1] | Cross-scenario comparison. |
| `payload_multiplier` | Per payload type (capability=1.5, approval=1.3, etc.) | [0, 1.5] | Risk weight by payload type. |

## 6. Synthetic topology

```text
coordinator -> worker -> typed handoff envelope -> receiver decision
```

| Target | Behavior |
|---|---|
| `toy-multi-agent` | Vulnerable receiver ignores the verifier result and consumes the malformed handoff. |
| `protected-toy-multi-agent` | Protected receiver enforces the verifier result and blocks the malformed handoff. |

Current fixture scenarios:

| Scenario | Pattern | Expected verdict | Failure reasons |
|---|---|---|---|
| Summary label stripping | `data_boundary_handoff_label_stripping` | `blocked` | `missing_provenance`, `label_loss` |
| Capability scope expansion | `capability.delegation_chain_drift` | `blocked` | `authority_expansion` |

## 7. Code mapping

| Component | File | Role |
|---|---|---|
| Envelope model | `src/agentic_security_harness/handoff_integrity.py` | `HandoffEnvelope` Pydantic model |
| Verifier | `src/agentic_security_harness/handoff_integrity.py` | `verify_handoff()` function |
| Payload hashing | `src/agentic_security_harness/handoff_integrity.py` | `canonical_payload_bytes()`, `payload_sha256()` |
| Toy adapters | `src/agentic_security_harness/toy_adapters.py` | `toy-multi-agent`, `protected-toy-multi-agent` |
| Test fixture | `tests/fixtures/handoff_toy_topology.json` | Synthetic topology scenarios |

## 8. Tests

| Test | File | What it validates |
|---|---|---|
| `test_payload_hash_is_canonical_and_stable` | `tests/test_handoff_integrity.py` | Canonical JSON produces stable hashes. |
| `test_clean_summary_handoff_passes_with_zero_scores` | `tests/test_handoff_integrity.py` | Clean handoff passes with zero scores. |
| `test_missing_labels_are_blocked_and_scored_structurally` | `tests/test_handoff_integrity.py` | Missing provenance triggers `blocked` with `S_structural=1.0`. |
| `test_capability_scope_expansion_is_hard_blocker_with_multiplier` | `tests/test_handoff_integrity.py` | Authority expansion triggers `blocked` with multiplier. |
| `test_integrity_policy_recipient_and_freshness_fail_closed` | `tests/test_handoff_integrity.py` | Multiple hard blockers fire simultaneously. |
| `test_verifier_outage_is_blocked_not_pass` | `tests/test_handoff_integrity.py` | Verifier outage blocks, not passes. |
| `test_committed_handoff_fixture_matches_verifier_expectations` | `tests/test_handoff_integrity.py` | Fixture scenarios match verifier expectations. |

## 9. Evidence

| Artifact | Location | Status |
|---|---|---|
| Handoff toy comparison | `reports/handoff-toy-comparison` | Local validated artifact. |
| Vulnerable trace | `reports/toy-multi-agent/traces.json` | 2 modeled findings. |
| Protected trace | `reports/protected-toy-multi-agent/traces.json` | 0 findings (blocked). |
| Comparison report | `reports/handoff-toy-comparison/comparison.md` | Side-by-side view. |

Reproduce:

```bash
ash compare --baseline toy-multi-agent --protected protected-toy-multi-agent --out reports/handoff-toy-comparison
ash validate reports/handoff-toy-comparison
```

## 10. Limits / non-claims

**This theory module does NOT claim:**

- Mathematical proof of security for real multi-agent systems.
- Semantic truthfulness is solved by hash checks.
- A live multi-agent framework preserves handoff integrity.
- The verdict is a score (it is a blocker decision; scores are metadata).
- The test coverage is complete for all handoff failure classes.

**This theory module DOES claim:**

- A formal executable invariant prototype exists.
- The prototype is validated on a deterministic synthetic topology.
- The verifier produces reproducible verdicts for the defined fixture scenarios.
- The protected receiver blocks malformed handoffs under the same conditions where the
  vulnerable receiver consumes them.

## Claim boundary

Allowed:

> Formal executable invariant prototype validated on deterministic synthetic topology.

Not allowed:

- "This prevents all handoff failures in production."
- "The model itself can cryptographically verify data integrity."
- "This is a complete multi-agent security solution."
- "Score equals security."
