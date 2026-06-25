# Semantic Propagation Defense Model

Date: 2026-06-25

This note documents the public-safe defense model behind
`examples/semantic-propagation-sanitized/`. It explains what the project claims,
what it measures, and what remains private.

## Problem

In a bounded agent chain, a weaker worker can accept a slow semantic relabeling
such as "A now means C" and pass only a clean summary to a stronger chief. The
chief may then approve the worker summary without seeing the original pressure.

The defensive question is not "how to trick a model". The defensive question is:

> Which deterministic controls must exist between worker output and chief
> approval so semantic drift cannot propagate silently?

## Public Contract

The public campaign contains:

- declared synthetic propagation cases;
- deterministic bounded-vs-ablation rows;
- a defense control catalog;
- a control-effect matrix;
- sanitized local-model observation counts;
- response hashes and validation metadata.

It does not contain raw prompts, raw model responses, synthetic canary values,
canonical-state hashes, or private calculation notes.

## Controls

| Control | Boundary |
| --- | --- |
| `worker_attestation` | Worker output must attest that meaning and boundary labels were preserved. |
| `canonical_state` | Chief checks summary claims against versioned canonical policy state. |
| `summary_guard` | Handoff summaries preserve the strongest input boundary. |
| `chief_verifier` | Chief approval is independently verified before a public claim is accepted. |
| `cross_worker_check` | Multi-worker disagreement cannot be averaged into semantic acceptance. |
| `source_hash` | Memory/policy-derived claims require provenance linkage. |

## Evidence

The committed sanitized example currently records:

- 4 declared propagation cases;
- 32 deterministic rows;
- 6 defense controls;
- 6 control-effect rows;
- 0 bounded propagation acceptances;
- 20 ablation propagation acceptances;
- 8 local-model worker-to-chief observations;
- 3 chief acceptances;
- 3 verifier blocks;
- 1 adapter error;
- 87.5% response-hash coverage.

This is a defense proof slice: the same declared synthetic cases are blocked by
the full bounded contract and reopened when responsible controls are ablated.

## Non-Claims

- This is not a CVE.
- This is not a model leaderboard.
- This is not proof that a deployed production swarm is secure.
- Adapter errors are not passes.
- Response hashes prove artifact hygiene, not semantic correctness.

## Reproduce

```bash
ash semantic-propagation-campaign --write --out reports/semantic-propagation
ash validate reports/semantic-propagation
```

Private local-model probing must write only under `.internal/`:

```bash
ash semantic-propagation-campaign --execute --out .internal/semantic-propagation/latest --summary-out reports/semantic-propagation
```
