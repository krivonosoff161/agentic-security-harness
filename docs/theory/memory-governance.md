# Theory: memory governance invariants

> Status: executable invariant with synthetic validation.
>
> Last reviewed: 2026-06-21.

## 1. Claim

Agent memory should not be read as trusted current context unless the memory record
preserves envelope restrictions, provenance, trust level, TTL from write time, and
scope isolation.

The project already has a public data-boundary example for write/read envelope drift.
This module defines the broader memory-governance layer around that envelope check.

## 2. Formal Objects

| Object | Definition |
|---|---|
| `MemoryGovernanceRecord` | Synthetic memory record with key, value hash, write/stored envelopes, source channel, trust level, scope, and write step. |
| `MemoryReadRequest` | Requested memory read with key, read envelope, reader scope, read step, and minimum trust level. |
| `MemoryGovernanceDecision` | Deterministic decision with `ok` and violation codes. |
| `TrustLevel` | Ordered local labels: `untrusted < tool_output < user < trusted_policy < system`. |

The model stores a value hash instead of raw content so public examples can reason about
memory behavior without exposing sensitive text.

## 3. Invariants

| Invariant | Deterministic condition | Violation |
|---|---|---|
| Key binding | requested key equals record key | `key_mismatch` |
| Scope isolation | `reader_scope_id == record.scope_id` | `scope_mismatch` |
| Time direction | read step is not before write step | `read_before_write` |
| Minimum trust | `rank(record.trust_level) >= rank(request.min_trust_level)` | `trust_too_low` |
| Envelope preservation | stored/read envelopes are equal or more restrictive than write/stored envelopes | `stored:*` / `read:*` envelope violations |
| TTL from write time | `read_at_step - written_at_step <= write_envelope.ttl_seconds` | `read:ttl_expired_from_write_time` |
| Trust precedence | lower-trust record cannot override a higher-trust same-key/same-scope record | `trust_precedence_violation` |

Envelope preservation reuses `validate_memory_read_envelope()` from
`src/agentic_security_harness/envelope_policy.py`. This prevents a second source of
truth for data-boundary math.

## 4. Code Mapping

| Component | File | Role |
|---|---|---|
| Envelope restriction model | `src/agentic_security_harness/envelope_policy.py` | Field-level `E_out <= E_in` relation. |
| Memory governance layer | `src/agentic_security_harness/memory_governance.py` | Provenance, scope, trust, TTL, and selection checks. |
| Corpus memory patterns | `src/agentic_security_harness/patterns.py` | Existing synthetic memory-governance scenarios. |
| Demo/protected targets | `src/agentic_security_harness/demo_agent.py`, `src/agentic_security_harness/protected_demo_agent.py` | Current memory-pattern behavior in committed examples. |

## 5. Tests

| Test | What it validates |
|---|---|
| `tests/test_memory_governance.py::test_memory_read_accepts_preserved_metadata` | A well-formed governed memory read passes. |
| `tests/test_memory_governance.py::test_memory_read_rejects_expired_ttl_from_write_time` | TTL is measured from write time. |
| `tests/test_memory_governance.py::test_memory_read_rejects_scope_mismatch` | Cross-scope read is blocked. |
| `tests/test_memory_governance.py::test_memory_read_rejects_read_time_envelope_drift` | Read-time envelope widening is blocked. |
| `tests/test_memory_governance.py::test_memory_read_rejects_low_trust_record` | Trust floor is enforced. |
| `tests/test_memory_governance.py::test_memory_read_rejects_lower_trust_override_when_higher_trust_record_exists` | Lower-trust overwrite is detected. |
| `tests/test_memory_governance.py::test_select_governed_memory_prefers_higher_trust_over_newer_lower_trust` | Selection prefers higher trust over newer lower-trust entries. |
| `tests/test_boundary_variation_matrices.py::test_memory_governance_variation_matrix_blocks_each_declared_axis` | The declared memory-governance variation matrix blocks key, scope, time, trust, envelope, TTL, and trust-precedence violations. |

## 5.1 Variation matrix readout

The declared memory-governance matrix has 8 rows:

```text
key binding
scope isolation
time direction
minimum trust
stored envelope preservation
read envelope preservation
TTL from write time
trust precedence
```

All 8 rows are covered by `tests/test_boundary_variation_matrices.py`. The count is a
coverage statement for the declared local synthetic matrix. It does not imply complete
coverage of production memory-store behavior.

The broader public matrix and private/public evidence rules are documented in
[`../boundary-layer-evidence-matrix.md`](../boundary-layer-evidence-matrix.md).

## 6. Evidence Status

| Evidence | Status | Boundary |
|---|---|---|
| `examples/comparison-report/` memory patterns | `public_example` at corpus level | Synthetic demo/protected memory behavior. |
| `data_boundary_memory_envelope_drift` | `public_example` | Data-envelope drift across memory write/read. |
| `tests/test_memory_governance.py` | `synthetic_validation` | Broader memory-governance invariant layer. |

## 7. Limits / Non-Claims

This theory module does not claim:

- real cross-session memory information-flow control;
- production memory-store isolation;
- semantic truthfulness of remembered content;
- deletion authorization or revocation propagation;
- cross-agent memory rehydration in a live framework;
- that every deployed agent memory architecture maps to this toy model.

It does claim that the public codebase now has an executable invariant layer for the
memory-governance properties listed above, with deterministic tests.
