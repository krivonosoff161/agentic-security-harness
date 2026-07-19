# Trading Bot Experiment Baseline Sanitized Summary

> Date: 2026-07-03.
>
> Scope: public-safe summary for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Private source fixture:
> `.internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json`.
>
> Historical status (2026-07-15): the seven schema-derived `pass` labels below
> are withdrawn. A safe-shaped schema row is now `inconclusive`; only explicit
> unsafe bounded evidence supports a finding.

## Boundary

This is the first observed baseline for the controlled experiment layer. It was
generated from the existing real paper artifact invariant probe and written
under the ignored private evidence root.

It did not:

- execute `trading-bot-v2`;
- read `.env`;
- call local or external LLMs;
- call external providers;
- send Telegram messages;
- touch live trading paths;
- publish raw vectors, agent scripts, target rows, traces, provider
  transcripts, card text, private calculations, secrets, or prompt bodies.

## Commands

```bash
ash trading-stand --mode experiment-baseline-fixture \
  --target-path <user-home>/trading-bot-v2 \
  --artifact-root <private-strategy-lab-root> \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json

ash trading-stand --mode validate-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json

ash trading-stand --mode sanitize-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json
```

## Result

| Field | Value |
|---|---:|
| records | 7 |
| scenarios | 7 |
| batches | 3 |
| validation issues | 0 |
| pass | 7 |
| finding | 0 |
| inconclusive | 0 |
| error | 0 |
| target observation | true |
| payloads included | false |
| private values included | false |
| raw vectors included | false |
| private calculations included | false |

Batch counts:

| Batch | Count |
|---|---:|
| A | 3 |
| B | 2 |
| C | 2 |

## Interpretation

This historical output shows that the seven rows satisfied the experiment-row
schema and passed through validation and sanitization. It does not show that
the seven behavioral invariants held. Under the current contract the same clean
schema-only evidence is seven `inconclusive` rows.

The next stronger layer is to add private filled rows for the seven scenario
batches. Those rows should keep raw vectors, timing details, target rows, agent
scripts, traces, and calculations in the ignored private fixture, then publish
only sanitized result counts and hash anchors.
