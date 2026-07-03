# Trading Bot Experiment Control Sanitized Summary

> Date: 2026-07-03.
>
> Scope: public-safe control fixture summary for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Private source: ignored fixture under
> `.internal/trading-bot-paper-stand/issue-136/manifests/`.

## Purpose

This is a control artifact for the private-to-public controlled experiment loop.
It is not a target run, not a target finding, and not evidence that the trading
bot passed or failed any adversarial scenario.

The fixture proves that future filled private experiment rows can be:

1. written only under the ignored private evidence root;
2. validated for all seven mapped scenario ids;
3. sanitized into public aggregate counts without raw vectors, agent scripts,
   target rows, traces, or private calculations.

## Commands

```bash
ash trading-stand --mode experiment-control-fixture \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json

ash trading-stand --mode validate-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json

ash trading-stand --mode sanitize-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json
```

## Validation Result

| Field | Value |
|---|---:|
| records | 7 |
| scenarios | 7 |
| issues | 0 |
| batch A records | 3 |
| batch B records | 2 |
| batch C records | 2 |
| pass | 0 |
| finding | 0 |
| inconclusive | 7 |
| error | 0 |

## Public Safety

| Check | Result |
|---|---|
| payloads included | false |
| private values included | false |
| raw vectors included | false |
| private calculations included | false |
| target observation | false |
| target execution | false |
| provider calls | false |
| Telegram sends | false |
| live execution | false |

## Interpretation

All seven rows are intentionally `inconclusive` because this is a
control-only, not-executed fixture. It verifies the evidence mechanics before
future private rows contain real bounded observations.

Public output contains only scenario ids, result counts, batch counts, artifact
hash anchors, and sanitized field names. Raw private slot values remain private.
