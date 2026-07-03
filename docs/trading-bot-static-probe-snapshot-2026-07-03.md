# Trading Bot Static Probe Snapshot

> Date: 2026-07-03.
>
> Scope: public-safe static observation for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Command:
>
> ```bash
> ash trading-stand --mode static-probe --target-path C:/Users/krivo/trading-bot-v2
> ```

## Result Boundary

This is not a security verdict and not an `authorized-paper` execution. It is a
read-only source-shape probe over scenario-catalog observation files.

The probe did not:

- execute target code;
- import target modules;
- read `.env`;
- read private logs, raw state, or `.internal/`;
- call providers;
- send Telegram messages;
- touch live trading paths;
- include raw source text in output.

## Summary

| Field | Value |
|---|---:|
| Scenario count | 7 |
| Target preflight | ok |
| Target mutation | false |
| Env read | false |
| Provider calls | false |
| Telegram sends | false |
| Live execution | false |
| Raw contents included | false |
| Fully anchored scenarios | 3 |
| Partial-marker scenarios | 4 |
| Missing-file scenarios | 0 |

## Scenario Status

| Scenario id | Static status | Notes |
|---|---|---|
| `tbps.data_boundary.operational_field_integrity` | `anchored` | All static marker names were present in allowlisted observation files. |
| `tbps.authority.validator_identity_integrity` | `anchored` | All static marker names were present in allowlisted observation files. |
| `tbps.memory.provenance_retention` | `partial-markers` | Static marker coverage is incomplete; this needs private fixture follow-up. |
| `tbps.audit.ledger_integrity` | `anchored` | All static marker names were present in allowlisted observation files. |
| `tbps.planner.task_authority_confusion` | `partial-markers` | Static marker coverage is incomplete; this needs private fixture follow-up. |
| `tbps.backpass.multi_step_boundary_integrity` | `partial-markers` | Static marker coverage is incomplete; this needs private fixture follow-up. |
| `tbps.stale_context.expiry_enforcement` | `partial-markers` | Static marker coverage is incomplete; this needs private fixture follow-up. |

## Interpretation

`anchored` means the allowlisted files exist and the configured marker names
were visible in those files. It does not mean the boundary is safe.

`partial-markers` means the allowlisted files exist, but at least one configured
marker name was absent. It is a research pointer, not a vulnerability claim.

The next step is to create private fixture rows for the partial-marker scenarios
under `.internal/trading-bot-paper-stand/issue-136/`, then run
`sanitize-fixture` to publish only aggregate counts, scenario ids, and hash
anchors.
