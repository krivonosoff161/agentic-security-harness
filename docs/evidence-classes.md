# Evidence classes and causal claims

> Last reviewed: 2026-07-15.

Agentic Security Harness publishes several kinds of evidence. They are not interchangeable.
Every public metric must be read through its evidence class before it is used in a claim.

The authoritative public inventory is
[`evidence-status-registry.json`](evidence-status-registry.json). It records lifecycle,
evidence class, schema state, causal scope, label source and coverage, reconciliation,
origin authentication, supported claims, and forbidden claims as independent fields.
Registry schema `0.1` fails closed on reconciled, independently labelled,
content-bound, signed/attested, or independent-causal classifications because no public
receipt or attestation contract exists yet. Those vocabulary values are reserved for a
later schema that can validate the referenced assurance artifact rather than trust a
manually edited status field.
Validate the inventory with:

```bash
ash validate docs/evidence-status-registry.json
```

## 1. Executable specification

Machine value: `executable_specification`.

The scenario declares its required controls and the deterministic evaluator applies those
rules. Ablation counts are therefore **rule-derived control attribution**: they prove that
the implementation matches the declared specification and that artifacts are reproducible.
They do not independently estimate whether the control caused safety in a real agent.

Current examples include context-consent, tool-authority, RAG-context, planner-task,
memory-rehydration, and the synthetic swarm-defense contour.

Allowed claim:

> The executable specification marks the declared unsafe transition blocked under the
> full contract and accepted under the named rule ablation.

Not allowed:

> The experiment independently proves that this control prevents the attack.

## 2. Historical rule snapshot

Machine value: `historical_rule_snapshot`.

A legacy artifact retains deterministic rows that are internally consistent with the cases
embedded in that same artifact, but its schema predates the current producer contract. Structural
validation does not bind those rows, reports, or digests to the current canonical corpus. It is a
historical specification snapshot, not a current executable specification.

## 3. Unverified maintainer declaration

Machine value: `maintainer_declaration_unverified`.

A tracked page records what a maintainer says happened, but the public repository has no
versioned result projection with row classifications, adapter-error state, response
anchors, and an artifact validator. The page is useful historical context, not an
empirical observation. Documentation alone does not prove that a run occurred or that
the declared aggregates correspond to retained bytes.

## 4. Local empirical observation

Real local-model text was produced in a private authorized run. Public artifacts retain
sanitized classifications, adapter-error state, and SHA-256 response anchors. Detector
counts describe what the implemented detector matched; they are not ground truth by
themselves.

Adapter errors remain a separate result class. They are never a pass, benign observation,
or evidence of safety.

## 5. Independently labeled evaluation

A reviewer who did not derive the label from detector output adjudicates the private raw
response as `unsafe` or `benign`. The private review note remains under `.internal/`; the
public row carries only:

- `ground_truth_label`;
- `ground_truth_source=independent_review`;
- `ground_truth_evidence_sha256`.

Precision, recall, specificity, and confusion-matrix claims are allowed only over these
independently reviewed, non-error rows. Unreviewed historical rows are
`not_adjudicated`; their label coverage is zero and no detector-accuracy claim is allowed.

## Validator boundary

`ash validate` checks schema, deterministic reconstruction, aggregate consistency,
forbidden public markers, and the label/hash contract. For the evidence-status registry,
it also checks every declared artifact path and requires each validator anchor to be a
registered route compatible with that artifact family's marker file. An arbitrary existing
test or source file is not accepted as validator coverage.
When validating tracked public examples, JSON output attaches the mapped component
statuses. Historical and unreconciled empirical components are explicitly marked
`unverified-private-projection`; docs-only reports are marked
`unverified-maintainer-declaration`; historical rule snapshots are marked
`legacy-structural-only`. A green integrity result does not remove any of these statuses.
It is read-only. It does not rerun models, authenticate artifact provenance,
independently reproduce private adjudication, or certify target safety.
