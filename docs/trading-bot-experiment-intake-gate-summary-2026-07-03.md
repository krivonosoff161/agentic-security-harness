# Trading Bot Experiment Intake Gate Summary

> Date: 2026-07-03.
>
> Scope: public-safe summary of the private filled-row intake gate for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).

## What This Adds

The harness now has an intake gate between private experiment rows and public
sanitized summaries.

This is separate from structural validation. A file can be structurally valid
and still be blocked from becoming public research evidence if it is only a
baseline, control, or template row set.

## Commands

Baseline-control intake check:

```bash
ash trading-stand --mode experiment-intake \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json \
  --manifest-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json
```

## Public Result

| Field | Value |
|---|---|
| intake | blocked |
| records | 7 |
| scenarios | 7 |
| batches | 3 |
| blockers | `real-target-observation-count` |
| real target observations | 0 |
| synthetic controls | 0 |
| batch manifest ok | true |
| pass | 7 |
| finding | 0 |
| inconclusive | 0 |
| error | 0 |
| payloads included | false |
| private values included | false |
| raw vectors included | false |
| private calculations included | false |

## Interpretation

The observed baseline rows remain useful as a control, but they are not accepted
as real filled experiment observations because they carry the baseline marker
and have zero real target-observation rows under the filled-row contract.

This prevents a common evidence error: treating a clean paper artifact baseline
as if it were an adversarial experiment result.

The gate does not execute `trading-bot-v2`, does not read `.env`, does not call
external providers, does not send Telegram messages, and does not touch live
trading paths.
