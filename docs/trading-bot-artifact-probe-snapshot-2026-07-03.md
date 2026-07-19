# Trading Bot Artifact Probe Snapshot

> Date: 2026-07-03.
>
> Scope: public-safe artifact observation for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> Command:
>
> ```bash
> ash trading-stand --mode artifact-probe \
>   --target-path <user-home>/trading-bot-v2 \
>   --artifact-root <private-strategy-lab-root>
> ```

## Result Boundary

This is not an `authorized-paper` execution and not a security verdict. It is a
read-only check for allowlisted paper/research artifacts that future runtime
observations can use as evidence anchors.

The probe did not:

- execute target code;
- import target modules;
- read `.env`;
- read private logs or `.internal/`;
- call providers;
- send Telegram messages;
- touch live trading paths;
- include raw artifact rows in output.

## Summary

| Field | Value |
|---|---:|
| Artifact count | 6 |
| Target preflight | ok |
| Target mutation | false |
| Env read | false |
| Provider calls | false |
| Telegram sends | false |
| Live execution | false |
| Raw contents included | false |
| Artifact root mode | separate |
| Existing artifacts | 6 |
| Anchored artifacts | 6 |
| Partial-marker artifacts | 0 |
| Missing artifacts | 0 |

## Artifact Status

| Artifact id | Relative path | Status |
|---|---|---|
| `main-paper-consumed` | `state/derived/main_paper_consumed.jsonl` | `anchored` |
| `main-paper-runtime-queue` | `state/derived/main_paper_runtime_queue.jsonl` | `anchored` |
| `main-paper-runtime-observation` | `state/derived/main_paper_runtime_observation.jsonl` | `anchored` |
| `main-paper-trade-ledger` | `state/derived/main_paper_trades.jsonl` | `anchored` |
| `paper-telegram-preview` | `state/derived/paper_telegram_preview.jsonl` | `anchored` |
| `paper-signal-training` | `state/derived/paper_signal_training.jsonl` | `anchored` |

## Interpretation

The target checkout and runtime evidence root are separate. The target source
shape passed preflight, and all six allowlisted paper artifacts were present
under the private paper/research artifact root. Public output includes only
aggregate statuses, line/byte counts, marker booleans, and artifact hashes.

The current safe conclusion is narrow: ASH can now observe existing paper runtime
evidence without reading raw rows. A schema-key follow-up corrected the marker
model from generic words such as `validator`, `observation`, and `ledger` to the
actual public-safe artifact keys: `consumer_status`, `runtime_id`, `outcome`,
and `paper_trade_id`.

This proves artifact presence and schema anchoring only. It does not yet prove
the seven agentic security invariants under adversarial paper-only scenarios.
The remaining runtime-evidence step is to generate or collect private fixture
rows that exercise each invariant, then sanitize those rows into public-safe
`pass` / `finding` / `inconclusive` summaries.
