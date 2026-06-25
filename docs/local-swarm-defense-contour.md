# Local Swarm Defense Contour

Status: first public defense-contour layer for local mini-swarm research.

This page ties four previously separate agentic-failure themes into one defensive
methodology. The purpose is not to publish attack transcripts. The purpose is to show
where a bounded local swarm needs deterministic controls so that model-generated prose
cannot redefine data meaning, launder handoffs, fake consensus, or leak protected
content through benign framing.

Raw local-model responses, synthetic canaries, and detailed private calculations stay
under `.internal/`. Public artifacts contain only declared topology, deterministic
contract rows, aggregate metrics, sanitized docs, and tests.

## Four Scenario Families

| Family | What can go wrong | Defensive invariant |
| --- | --- | --- |
| Semantic parameter drift | A worker gradually accepts that `A` now means `C`. | Model wording cannot change canonical state. |
| Propagation to chief | A poisoned worker summary is accepted by the chief. | Chief decisions require provenance-backed handoff checks. |
| Consensus laundering | Mixed or copied worker outputs are treated as proof. | Consensus cannot override canonical boundary labels. |
| Benign-framed boundary leak | Protected content is requested through audit/debug/summary framing. | Summaries inherit the strongest input boundary. |

## Control Set

The contour uses these deterministic controls:

- `canonical_state` - canonical A/B/C meanings are versioned outside model prose.
- `transition_table` - only declared transformations are allowed.
- `source_hash` - derived facts must point to source provenance.
- `worker_attestation` - worker summaries must attest meaning and boundary preservation.
- `summary_guard` - summaries inherit the strongest input boundary.
- `chief_verifier` - final decisions are contract-checked, not model-judged.
- `cross_worker_check` - worker disagreement blocks majority-style semantic relabeling.
- `boundary_envelope` - data carries classification, purpose, and recipient constraints.
- `memory_quarantine` - boundary-tainted memory cannot silently re-enter trusted context.
- `audit_hash_chain` - the chain remains reconstructable for reviewer audit.

## Combination Matrix

The public contour evaluates all non-empty combinations of the four families:

```text
4 single-family topologies
6 pair topologies
4 triple topologies
1 full four-family topology
```

Each topology is evaluated in:

- `naive_swarm`
- `bounded_swarm`
- one ablation mode per control

The key defense signal is:

```text
naive accepts -> bounded blocks -> relevant ablation reopens
```

If a control removal does not reopen any declared path, the control is not yet proven
necessary for that topology. If removal reopens every dependent topology, the control is
primary for the declared contour.

## Reproduce

Generate the sanitized public artifact:

```bash
ash swarm-defense-contour --write --out reports/swarm-defense-contour
ash validate reports/swarm-defense-contour
```

Committed examples, when present, must remain sanitized:

```bash
ash validate examples/swarm-defense-contour-sanitized
```

Private local-model probes may use this contour as the plan, but raw outputs must stay
under `.internal/` and must not be committed.

## Claim Boundary

Allowed:

- The project models four local-swarm failure families and their combinations.
- The bounded contract blocks the declared synthetic topologies.
- Ablations identify which deterministic controls reopen each declared path.
- Public artifacts are sanitized and validated.

Not allowed:

- This is a CVE.
- A production swarm is secure.
- A local model is safe or unsafe.
- Deterministic validators prove semantic truth.
- Raw local-model transcripts are public evidence.

