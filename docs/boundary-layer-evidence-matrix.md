# Boundary layer evidence matrix

> Last reviewed: 2026-06-21.
>
> Scope: local deterministic variation matrices for authority delegation,
> inter-agent handoff integrity, and memory-governance invariants.

This page is the public, cleaned readout for the current boundary-layer research
hardening pass. It explains what was varied, what is executable today, and what remains
outside the claim boundary.

## Claim

The project has executable local invariant tests for a declared synthetic variation
matrix across three boundary layers:

1. inter-agent handoff integrity;
2. delegated authority non-expansion;
3. memory governance.

The matrix is useful because every row names one expected failure mode and maps to a
deterministic test. It is not a proof that a deployed agent framework, memory store, or
authorization system is secure.

## Public/private research boundary

| Public artifact | Private/local artifact |
|---|---|
| Cleaned invariant statement. | Scratch derivation notes. |
| Variation matrix row and expected blocker. | Exploratory failed variants. |
| Test name and code mapping. | Raw local model responses. |
| Curated example under `examples/`. | Machine-specific `reports/` captures unless promoted. |

Private calculations may guide a public doc, but they do not upgrade a claim by
themselves. A public claim upgrade requires at least one of:

- deterministic tests committed in `tests/`;
- a curated artifact committed under `examples/` or another tracked evidence path;
- a bounded local-empirical summary with raw responses kept private and explicit
  non-claims.

## Variation counts

These counts are deliberately narrow:

```text
declared_matrix_rows = handoff_rows + authority_rows + memory_rows
declared_matrix_rows = 9 + 5 + 8 = 22
validated_declared_rows = 22
declared_matrix_coverage = 22 / 22 = 1.0
```

This means the declared local synthetic matrix is executable. It does **not** mean the
project has complete coverage for all production handoff, authorization, or memory
architectures.

## Handoff matrix

| Row | Expected blocker | Executable test coverage |
|---|---|---|
| Missing envelope | `missing_envelope` | `tests/test_boundary_variation_matrices.py::test_handoff_variation_matrix_blocks_each_declared_hard_reason_once` |
| Malformed raw envelope | `verifier_error` | Same matrix test |
| Payload hash mismatch | `integrity_mismatch` | Same matrix test |
| Required provenance missing | `missing_provenance` | Same matrix test |
| Parent labels stripped | `label_loss` | Same matrix test |
| Receiver outside allow-list | `recipient_violation` | Same matrix test |
| Expired or replayed envelope | `stale_or_replayed` | Same matrix test |
| Unsupported policy version | `policy_mismatch` | Same matrix test |
| Verifier unavailable | `verifier_error` | Same matrix test |

The handoff matrix checks that the verifier fails closed on structural handoff defects.
It does not check semantic truthfulness of payload content.

## Authority matrix

| Row | Rule | Expected blocker | Executable test coverage |
|---|---|---|---|
| Issuer expansion | `child.issuer == parent.issuer` | `authority_expansion` | `tests/test_boundary_variation_matrices.py::test_authority_non_expansion_matrix_blocks_every_observable_axis` |
| Scope expansion | `set(child.scope) subseteq set(parent.scope)` | `authority_expansion` | Same matrix test |
| Purpose expansion | `child.purpose == parent.purpose` | `authority_expansion` | Same matrix test |
| TTL expansion | `child.ttl_seconds <= parent.ttl_seconds` | `authority_expansion` | Same matrix test |
| Delegation-depth expansion | `child.delegation_depth <= child.max_delegation_depth` | `authority_expansion` | Same matrix test |

The authority matrix treats purpose as exact equality. Purpose hierarchies, near-synonym
normalization, and revocation require a separate policy model and are not covered here.

## Memory-governance matrix

| Row | Expected violation | Executable test coverage |
|---|---|---|
| Key mismatch | `key_mismatch` | `tests/test_boundary_variation_matrices.py::test_memory_governance_variation_matrix_blocks_each_declared_axis` |
| Scope mismatch | `scope_mismatch` | Same matrix test |
| Read before write | `read_before_write` | Same matrix test |
| Trust below requested floor | `trust_too_low` | Same matrix test |
| Stored envelope weakens write envelope | `stored:*` envelope violation | Same matrix test |
| Read envelope weakens stored envelope | `read:*` envelope violation | Same matrix test |
| TTL expired from write time | `read:ttl_expired_from_write_time` | Same matrix test |
| Lower-trust override when higher-trust record exists | `trust_precedence_violation` | Same matrix test |

The memory matrix validates governance metadata. It does not prove that remembered
content is semantically true or that a production memory store enforces isolation.

## Code mapping

| Layer | Implementation | Existing focused tests | Matrix tests |
|---|---|---|---|
| Handoff integrity | `src/agentic_security_harness/handoff_integrity.py` | `tests/test_handoff_integrity.py` | `tests/test_boundary_variation_matrices.py` |
| Authority delegation | `src/agentic_security_harness/handoff_integrity.py` | `tests/test_handoff_integrity.py`, `tests/test_toy_multi_agent.py` | `tests/test_boundary_variation_matrices.py` |
| Memory governance | `src/agentic_security_harness/memory_governance.py`, `src/agentic_security_harness/envelope_policy.py` | `tests/test_memory_governance.py`, `tests/test_envelope_policy.py` | `tests/test_boundary_variation_matrices.py` |

## Gaps

| Gap | Why it is not claimed |
|---|---|
| Live multi-agent runtime handoff behavior | Current evidence uses local synthetic toy topology. |
| Capability revocation propagation | Current authority model checks non-expansion at receipt time only. |
| Purpose hierarchy / semantic purpose matching | Current verifier intentionally uses exact purpose equality. |
| Cross-provider handoff preservation | Planned separately; current matrix is local and in-process. |
| Production memory-store isolation | Current memory model is a synthetic metadata invariant layer. |
| Semantic truthfulness of payload or memory content | Hashes and provenance labels do not prove content truth. |

## Reproduce

```bash
python -m pytest tests/test_boundary_variation_matrices.py
python -m pytest tests/test_handoff_integrity.py tests/test_memory_governance.py
ash validate examples/handoff-toy-comparison
```

## Claim boundary

Allowed:

> The declared local synthetic boundary-layer variation matrix has executable tests for
> handoff integrity, authority non-expansion, and memory-governance metadata checks.

Not allowed:

- "The project proves production multi-agent security."
- "The matrix covers every handoff, authority, or memory failure."
- "The verifier solves semantic truthfulness."
- "Private scratch calculations are public evidence."
