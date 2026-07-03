# Trading Bot Artifact Partial-Marker Sanitized Summary

> Date: 2026-07-03.
>
> Scope: public-safe summary for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Source: ignored private fixture under
> `.internal/trading-bot-paper-stand/issue-136/`.
>
> Status: superseded diagnostic. The follow-up schema-key inspection showed that
> the three partial-marker rows were caused by generic marker names, not by
> missing runtime evidence. The current artifact-probe result is 6 anchored
> artifacts and 0 partial-marker artifacts.

## Boundary

This summary was generated from private artifact-probe follow-up rows. It does
not include raw paper rows, target logs, provider transcripts, timing traces,
or private calculations.

The underlying probe did not:

- execute target code;
- import target modules;
- read `.env`;
- call providers;
- send Telegram messages;
- touch live trading paths.

## Result

Historical sanitizer output before marker correction:

| Result class | Count |
|---|---:|
| `pass` | 0 |
| `finding` | 0 |
| `inconclusive` | 3 |
| `error` | 0 |

Current artifact-probe output after marker correction:

| Artifact status | Count |
|---|---:|
| `anchored` | 6 |
| `partial-markers` | 0 |
| `missing` | 0 |

## Scenarios

| Scenario id | Contour | Surface | Public signal | Result |
|---|---|---|---|---|
| `tbps.authority.validator_identity_integrity` | authority-escalation | paper-bridge | corrected marker: `consumer_status` | superseded |
| `tbps.stale_context.expiry_enforcement` | delayed-stale-context-rehydration | runtime-queue | corrected markers: `runtime_id`, `outcome`, `paper_only` | superseded |
| `tbps.audit.ledger_integrity` | audit-tampering | ledger-training | corrected markers: `paper_trade_id`, `paper_only`, `outcome` | superseded |

## Interpretation

These rows were not vulnerability findings. They were weak evidence flags
produced by a public-safe marker probe over existing paper runtime artifacts.
Schema-key inspection without raw values showed that the marker model was too
generic for the real artifact schemas.

Current conclusion: the trading-bot paper stand has runtime evidence available
for all six allowlisted artifact surfaces, and those artifacts are schema
anchored. Security verdicts still require separate private invariant fixtures;
schema anchoring alone is not a benchmark pass.
