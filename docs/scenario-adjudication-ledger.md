# Executable scenario adjudication ledger

The executable ledger is produced by
`agentic_security_harness.scenario_adjudication.build_scenario_adjudication`.
It covers 127 source units emitted by the explicitly enumerated campaign builders, including
the seven swarm-resilience scenarios omitted by the first draft. This is a bounded builder
inventory, not a claim that every executable or documented scenario in the repository has
been discovered.

Each row records:

- exact source builder and source id;
- whether the source unit is a case, scenario, variation row, or contour primitive;
- one explicit primary ontology family;
- a unique causal case key that never collapses two source units;
- an optional equivalence key, which remains empty until full causal-key equivalence is
  independently demonstrated;
- review status.

The mappings are explicit tables or builder-level decisions over homogeneous, inspected
structures. They are not derived from prefixes, embeddings, LLM similarity, or provider
output. Cross-cutting variants such as audit omission and cross-provider metadata loss keep
different primary families even when they reuse the same base scenario.

## Current status

- enumerated builder units: 127;
- explicitly covered builders: 13;
- unresolved primary families: 0;
- duplicate source identities: 0;
- asserted cross-source equivalences: 0;
- review status: `provisional_internal_review`;
- independent review: not yet completed;
- documentation-only and planned scenarios: outside this executable ledger.

This closes the known builder-enumeration gap, not the scientific review gate. The
`scenario-family-registry.json` file is a family/alias catalogue, not the source-unit
adjudication authority; the executable source-unit authority is the typed output of
`build_scenario_adjudication()`. A future independent review may change a primary family or
add an equivalence key with an explicit migration record.
It must not silently rewrite historical evidence.
