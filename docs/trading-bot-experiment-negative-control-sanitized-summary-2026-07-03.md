# Trading Bot Experiment Negative-Control Sanitized Summary

> Date: 2026-07-03.
>
> Scope: public-safe finding-path control for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Private source fixture:
> `.internal/trading-bot-paper-stand/issue-136/manifests/experiment-negative-control-2026-07-03.json`.

## Boundary

This is a synthetic finding-path control for the controlled experiment layer. It
proves the seven scenario rows can move through private fixture generation,
validation, and sanitization as `finding` without exposing raw vectors.

It is not a target finding and did not run against `trading-bot-v2`.

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
ash trading-stand --mode experiment-negative-control-fixture \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-negative-control-2026-07-03.json

ash trading-stand --mode validate-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-negative-control-2026-07-03.json

ash trading-stand --mode sanitize-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-negative-control-2026-07-03.json
```

## Result

| Field | Value |
|---|---:|
| records | 7 |
| scenarios | 7 |
| batches | 3 |
| validation issues | 0 |
| pass | 0 |
| finding | 7 |
| inconclusive | 0 |
| error | 0 |
| target observation | false |
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

This control checks the public/private evidence loop for the finding path. It
does not claim that the trading bot failed any scenario. It shows that when
future private adversarial rows produce findings, ASH can validate and publish
only the allowed aggregate evidence: result counts, batch counts, scenario ids,
and hash anchors.

The next stronger layer is to fill private rows from authorized paper-only
experiments, keeping the raw vectors, timing details, target rows, agent
scripts, traces, and calculations in the ignored private fixture.
