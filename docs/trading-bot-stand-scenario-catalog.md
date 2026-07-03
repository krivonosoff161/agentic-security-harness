# Trading Bot Paper Stand Scenario Catalog

> Status: public-safe scenario catalog for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> This catalog contains scenario ids, surfaces, invariants, and evidence fields
> only. It intentionally does not include working payloads, raw prompts, raw
> target logs, provider transcripts, timing details, or private calculations.

## Command

```bash
ash trading-stand --mode scenario-catalog
ash trading-stand --mode fixture-template --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/private-fixture.json
ash trading-stand --mode sanitize-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/private-fixture.json
ash trading-stand --mode static-probe --target-path C:/Users/krivo/trading-bot-v2
```

The first three commands do not touch `trading-bot-v2`.
`fixture-template` writes only under the ignored private evidence root.
`sanitize-fixture` reads only the supplied private fixture JSON and emits a
public-safe summary with hash anchors.
`static-probe` reads only the observation files listed by this catalog and emits
hashes plus marker booleans, not raw source text.

## Scenario List

| Scenario id | Contour | Surface | Public evidence shape |
|---|---|---|---|
| `tbps.data_boundary.operational_field_integrity` | Data vs instruction boundary | Input routing | source label, operational-field change flag, result class, artifact hash |
| `tbps.authority.validator_identity_integrity` | Authority escalation | Paper bridge | validator identity, execution flag, result class, artifact hash |
| `tbps.memory.provenance_retention` | Memory contamination | Ledger/training | provenance flag, trust-label change flag, result class, artifact hash |
| `tbps.audit.ledger_integrity` | Audit tampering | Ledger/training | row validity, audit-chain status, result class, artifact hash |
| `tbps.planner.task_authority_confusion` | Planner/task authority confusion | Deterministic gate | task-status source, planner-action flag, result class, artifact hash |
| `tbps.backpass.multi_step_boundary_integrity` | Agentic rule-violation backpass | LLM role boundary | component chain, boundary step count, final-authority flag, artifact hash |
| `tbps.stale_context.expiry_enforcement` | Delayed/stale-context rehydration | Runtime queue | context-age state, expiry flag, result class, artifact hash |

## Public/Private Split

Public scenario artifacts may include:

- scenario id;
- component or component-chain names;
- aggregate `pass`, `finding`, `inconclusive`, and `error` counts;
- boolean or enum evidence fields;
- hashes of private artifacts;
- sanitized finding summaries.

Private-only artifacts include:

- source text;
- raw vectors;
- raw target rows;
- raw advisory/model output;
- raw traces;
- timing notes;
- private calculation notes.

## Researcher Rule

If a real paper-stand run reveals a behavior that does not fit one of these
seven scenarios, record it privately first. Public docs should add only a
sanitized scenario proposal after the failure class, evidence boundary, and
non-claims are clear.
