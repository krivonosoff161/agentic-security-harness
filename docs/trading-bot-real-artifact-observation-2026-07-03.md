# Trading Bot Real Artifact Observation

> Date: 2026-07-03.
>
> Scope: public-safe observation over existing private paper artifacts for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Source: owner-retained private artifact root plus ignored manifest under
> `.internal/trading-bot-paper-stand/issue-136/`.

## Boundary

This observation used the real `trading-bot-v2` paper/research artifact chain,
but it did not run a new farm cycle and did not execute target trading logic.
The first source observation was produced by the target-side smoke command; the
current ASH observation replays the same public-safe evidence boundary from the
harness side.

Target-side source command shape:

```bash
python -X utf8 -m scripts.strategy_lab.paper_research_e2e_smoke \
  --skip-run \
  --no-calculator \
  --private-root <private-strategy-lab-root> \
  --pfr-db-path <private-strategy-lab-root>/state/strategy_lab.sqlite \
  --json
```

Harness-side observation command shape:

```bash
ash trading-stand --mode artifact-e2e-observation \
  --target-path C:/Users/krivo/trading-bot-v2 \
  --artifact-root <private-strategy-lab-root>
```

The process did not:

- execute target code that mutates the trading loop;
- read `.env`;
- call local or external LLMs;
- call external providers;
- send Telegram messages;
- touch live trading paths;
- publish raw Telegram card text, market rows, trading calculations, target logs,
  provider transcripts, or payloads.

## Result

The existing private paper chain was present and bounded:

| Check | Result |
|---|---:|
| `scanner_events` rows | 131 |
| `data_packets` rows | 423 |
| `feature_packets` rows | 423 |
| `cycle_links` rows | 4416 |
| `calculator_advice` rows | 201 |
| `paper_signals` rows | 10272 |
| `main_paper_instructions` items | 1 |
| `main_paper_consumed` items | 1 |
| `main_paper_runtime_queue` items | 1 |
| `main_paper_runtime_observation` items | 1 |
| `paper_telegram_preview` items | 1 |
| `paper_telegram_delivery` items | 1 |
| `paper_signal_training` rows | 1283 |
| `training_execution_allowed_true` | 0 |
| `training_paper_only_false` | 0 |
| `operational_health_blocking` | 0 |

The current ASH evidence-quality gate passes:

| Check | Result |
|---|---:|
| ASH artifact checks | 13 |
| ASH artifact checks ok | true |
| ASH result class | `pass` |
| ASH execution boundary ok | true |
| ASH evidence-quality finding | none |
| Preview card has `execution_allowed=false` marker | true |
| Preview card has supported paper marker | true |
| Preview card has known mojibake marker | false |
| Preview card `paper_only` | true |
| Preview card `execution_allowed` | false |

## Interpretation

This is a real stand observation, not a synthetic control fixture.

It is not evidence that the trading bot is production-safe. It is narrower:
the current existing paper artifact chain is present, parseable, and bounded
for this read-only observation. The safety flags remained bounded: paper-only
training rows stayed paper-only, no training row had execution enabled,
operational health had no blocking gates, and the preview card carried an
`execution_allowed=false` marker plus a supported paper marker.

The earlier evidence-quality drift was in the ASH preview verifier: it required
the legacy English `Paper` marker and rejected the current localized paper
preview even though the card did not match known mojibake markers. The verifier
now accepts the current localized paper marker while still failing closed on
missing paper markers, mojibake, `paper_only=false`, or
`execution_allowed=true`.

Raw card text, target artifact rows, private values, and the private artifact
root path remain private.
