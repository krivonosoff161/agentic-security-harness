# Trading Bot Boundary Lock Snapshot

> Date: 2026-07-03.
>
> Scope: public-safe read-only boundary-lock snapshot for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).

## What This Checks

`boundary-lock` scans only the seven scenario catalog observation files. It
does not scan the whole trading bot, does not read `.env`, does not import or
execute target code, does not call providers, does not send Telegram messages,
and does not touch live trading paths.

The output contains counts, scenario ids, file paths, and hashes only. It does
not include source lines, secrets, prompts, raw vectors, target rows, traces, or
private calculations.

## Command

```bash
ash trading-stand --mode boundary-lock \
  --target-path C:/Users/krivo/trading-bot-v2
```

## Public Result

| Field | Value |
|---|---|
| lock | `review-required` |
| lock ok | false |
| scenarios | 7 |
| locked scenarios | 4 |
| review-required scenarios | 3 |
| secret environment access markers | 4 |
| external provider call markers | 0 |
| Telegram send markers | 0 |
| live order execution markers | 0 |
| raw contents included | false |
| private values included | false |

Files with review markers:

- `src/research_lab/intake_adapter.py`
- `src/research_lab/paper_signals/pfr_bridge.py`
- `src/research_lab/setup_outcome_memory.py`

## Interpretation

This is not a target finding and not an exploit result. It is a safety gate
before future private filled-row experiments.

The current observation surface is strong enough to continue planning, but not
clean enough to allow unattended filled-row execution. Before any future
authorized paper runner exists, the marked files need manual review or a more
precise adapter contract proving that environment access cannot cross into
secret disclosure or live/provider behavior during a scenario run.

The useful signal is narrow:

- no provider-call markers were found in the allowlisted observation files;
- no Telegram-send markers were found in the allowlisted observation files;
- no live-order execution markers were found in the allowlisted observation
  files;
- environment-boundary markers are present and must remain under review.

The follow-up classifier is recorded in
[trading-bot-boundary-lock-review-2026-07-03.md](trading-bot-boundary-lock-review-2026-07-03.md).
It classifies the three marked files as 2 documentation-only files and 1
bounded research-root configuration read, with 0 secret env reads, 0 unknown env
reads, 0 provider calls, 0 Telegram sends, 0 live-order sites, and 0 blocking
markers. The remaining requirement is an explicit adapter contract, not a
current secret/provider/live blocker.
