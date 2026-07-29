# Executable scenario adjudication ledger

The executable ledger is produced by
`agentic_security_harness.scenario_adjudication.build_scenario_adjudication`.
It covers the 120 authoritative units emitted by the current campaign builders.

Each row records:

- exact source builder and source id;
- whether the source unit is a case, scenario, variation row, or contour primitive;
- one explicit primary ontology family;
- a canonical alias key used to collapse variants only when the protected invariant and
  causal source scenario are the same;
- review status.

The mappings are explicit tables or builder-level decisions over homogeneous, inspected
structures. They are not derived from prefixes, embeddings, LLM similarity, or provider
output. Cross-cutting variants such as audit omission and cross-provider metadata loss keep
different primary families even when they reuse the same base scenario.

## Current status

- authoritative builder units: 120;
- unresolved primary families: 0;
- duplicate source identities: 0;
- review status: `provisional_internal_review`;
- independent review: not yet completed;
- documentation-only and planned scenarios: outside this executable ledger.

This closes the mechanical mapping gap, not the scientific review gate. A future independent
review may change a primary family or canonical alias key with an explicit migration record.
It must not silently rewrite historical evidence.
