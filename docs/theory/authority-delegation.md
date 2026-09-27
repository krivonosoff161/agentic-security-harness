# Theory: authority delegation non-expansion

> Status: public-example backed synthetic invariant.
>
> Last reviewed: 2026-09-27 (foundation reconciliation candidate).

## 1. Claim

An agent receiving delegated authority should reject a child grant when the child grant
expands the parent grant along any deterministic axis the verifier can observe:
issuer, scope, purpose and TTL when the corresponding parent arguments are supplied.
Depth is checked against the child's declared maximum, not an authenticated parent maximum.

This claim is intentionally narrow. It covers synthetic capability handoffs in the local
toy topology. It does not claim production-grade authorization, live framework coverage,
or revocation propagation.

## 2. Formal Objects

| Object | Definition |
|---|---|
| `ParentGrant` | The authority constraints the sender was allowed to delegate. |
| `ChildGrant` | The authority constraints embedded in the handoff envelope. |
| `authority_issuer` | The identity that issued the grant. A child grant cannot claim a different issuer unless a trusted policy explicitly allows translation. |
| `authority_scope` | A finite set of allowed actions/capabilities. |
| `purpose` | The permitted use of the delegated authority. |
| `ttl_seconds` | Maximum lifetime of the delegated grant. |
| `delegation_depth` | Current delegation depth compared with `max_delegation_depth`. |

## 3. Non-Expansion Rule

For the current deterministic verifier, each supplied parent argument enables the
corresponding comparison. The final predicate is a separate local consistency check:

```text
child.issuer == parent.issuer
set(child.scope) subseteq set(parent.scope)
child.purpose == parent.purpose
child.ttl_seconds <= parent.ttl_seconds
child.delegation_depth <= child.max_delegation_depth
```

If any predicate fails, the verifier returns `blocked` with `authority_expansion`.

For scope, `parent_authority_scope=[]` is a known empty grant: only an empty child
scope can be its subset. `parent_authority_scope=None` means no parent scope was
supplied to this API. The verifier retains that compatibility path and makes no
scope-ancestry claim for it. A passing verdict with an unknown parent cannot prove
that delegation preserved authority from an actual parent grant.

The subset rule also composes over a chain of supplied grants: if every handoff
checks `child_scope ⊆ parent_scope`, then transitivity gives each descendant scope
as a subset of the original scope. Induction proves this for any finite chain of
checked sets; it assumes the supplied parent grants are authentic and complete. The local
synthetic verifier does not establish that provenance or production authorization.

Neither that induction nor a passing fixture proves depth inheritance. Raising both
`delegation_depth` and the self-declared `max_delegation_depth` can satisfy the local
predicate. The caller must supply authenticated policy at the actual enforcement boundary.
Likewise, comparing TTL durations does not prove decreasing absolute deadlines when
issuance times differ. The memory contract's common-epoch rule is a distinct mechanism.

The equality rule for `purpose` is conservative. Purpose hierarchies or near-synonym
normalization would require a policy table that is not part of this public example.

## 4. Code Mapping

| Component | File | Role |
|---|---|---|
| Verifier | `src/agentic_security_harness/handoff_integrity.py` | `verify_handoff()` checks issuer, scope, purpose, TTL, and depth. |
| Raw fail-closed wrapper | `src/agentic_security_harness/handoff_integrity.py` | `verify_raw_handoff()` maps missing/malformed envelopes to blockers. |
| Toy adapters | `src/agentic_security_harness/toy_adapters.py` | Exposes vulnerable and protected capability handoff behavior. |
| Pattern registry | `src/agentic_security_harness/patterns.py` | Includes `capability.delegation_chain_drift`. |

## 5. Tests

| Test | What it validates |
|---|---|
| `tests/test_handoff_integrity.py::test_capability_authority_non_expansion_axes` | Each authority axis blocks independently. |
| `tests/test_handoff_integrity.py::test_capability_scope_expansion_is_hard_blocker_with_multiplier` | Capability payloads receive the deterministic risk multiplier. |
| `tests/test_handoff_integrity.py::test_capability_scope_subset_over_complete_two_action_powerset` | All 16 parent/child pairs over `{read, write}` obey subset semantics, including the empty parent and nonempty narrowing. |
| `tests/test_handoff_integrity.py::test_unspecified_parent_scope_retains_compatibility_without_ancestry_check` | An omitted parent scope retains compatibility without claiming ancestry. |
| `tests/test_handoff_integrity.py::test_raw_handoff_explicit_empty_parent_scope_blocks_nonempty_child` | The raw wrapper preserves the explicit empty-parent restriction. |
| `tests/test_handoff_integrity.py::test_committed_handoff_fixture_matches_verifier_expectations` | The committed topology fixture matches verifier behavior. |
| `tests/test_toy_multi_agent.py` | Vulnerable toy consumes the malformed handoff; protected toy blocks it. |
| `tests/test_validation.py` | The committed example artifacts validate under `ash validate examples`. |
| `tests/test_boundary_variation_matrices.py::test_authority_non_expansion_matrix_blocks_every_observable_axis` | Issuer, scope, purpose, TTL, and depth are checked as an explicit variation matrix. |

## 5.1 Variation matrix readout

The declared authority matrix has 5 observable non-expansion axes:

```text
issuer + scope + purpose + TTL + delegation_depth = 5
```

The clean parent/child grant passes. Each one-axis mutation blocks with
`authority_expansion`. This verifies that the current local rule is not only a prose
statement: every declared axis is executable in tests.

The broader public matrix is documented in
[`../boundary-layer-evidence-matrix.md`](../boundary-layer-evidence-matrix.md).

## 6. Evidence

| Artifact | Status |
|---|---|
| `examples/handoff-toy-comparison/` | Committed public example. |
| `examples/handoff-toy-comparison/baseline/traces.json` | Vulnerable toy records modeled findings. |
| `examples/handoff-toy-comparison/protected/traces.json` | Protected toy records no findings because it blocks consumption. |

Reproduce:

```bash
ash compare --baseline toy-multi-agent --protected protected-toy-multi-agent --out examples/handoff-toy-comparison
ash validate examples/handoff-toy-comparison
```

## 7. Limits / Non-Claims

This theory module does not claim:

- production authorization semantics;
- live multi-agent framework coverage;
- cryptographic capability-token standardization;
- revocation propagation;
- purpose hierarchy or semantic near-synonym matching;
- semantic correctness of the delegated payload.

It only claims that the local deterministic verifier and toy topology exercise observable
authority non-expansion axes and produce reproducible public artifacts.
