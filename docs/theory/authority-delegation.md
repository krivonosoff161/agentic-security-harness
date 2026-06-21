# Theory: authority delegation non-expansion

> Status: public-example backed synthetic invariant.
>
> Last reviewed: 2026-06-21.

## 1. Claim

An agent receiving delegated authority should reject a child grant when the child grant
expands the parent grant along any deterministic axis the verifier can observe:
issuer, scope, purpose, TTL, or delegation depth.

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

For the current deterministic verifier, a child grant is allowed only when all observable
axes are equal or narrower:

```text
child.issuer == parent.issuer
set(child.scope) subseteq set(parent.scope)
child.purpose == parent.purpose
child.ttl_seconds <= parent.ttl_seconds
child.delegation_depth <= child.max_delegation_depth
```

If any predicate fails, the verifier returns `blocked` with `authority_expansion`.

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
| `tests/test_handoff_integrity.py::test_committed_handoff_fixture_matches_verifier_expectations` | The committed topology fixture matches verifier behavior. |
| `tests/test_toy_multi_agent.py` | Vulnerable toy consumes the malformed handoff; protected toy blocks it. |
| `tests/test_validation.py` | The committed example artifacts validate under `ash validate examples`. |

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
- semantic correctness of the delegated payload.

It only claims that the local deterministic verifier and toy topology exercise observable
authority non-expansion axes and produce reproducible public artifacts.
