# Trading Bot Experiment Batch Manifest Summary

> Date: 2026-07-03.
>
> Scope: public-safe summary of the private experiment batch guard for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).

## What This Proves

The harness can now write and validate a private batch manifest before any
filled experiment rows exist. This is the scheduling guard for future agentic
paper-only research against the owned `trading-bot-v2` stand.

It proves the experiment is still a controlled ASH-side plan, not an unbounded
target run:

- 7 public scenario ids are covered;
- 3 batch groups are present;
- maximum parallel scenarios is capped at 4;
- every batch remains `planned-not-executed`;
- required stop gates remain declared;
- target mutation, `.env` reads, provider calls, Telegram sends, and live
  execution remain disabled;
- raw vectors, raw prompts, raw target rows, private calculations, and payloads
  are not included in the public output.

## Commands

The private manifest is written only under the ignored evidence root:

```bash
ash trading-stand --mode experiment-batch-manifest \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json
```

Validation:

```bash
ash trading-stand --mode validate-experiment-batch-manifest \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json
```

## Public Result

| Field | Value |
|---|---|
| validation | ok |
| scenarios | 7 |
| batches | 3 |
| issues | 0 |
| max parallel scenarios | 4 |
| payloads included | false |
| private values included | false |
| raw vectors included | false |
| private calculations included | false |

## Interpretation

This is not an adversarial target result and not a production-safety claim. It
is the machine-readable guard that future private filled rows must satisfy
before any public sanitized summary is accepted.

The raw scenario bodies, timing details, target rows, traces, calculations, and
agent scripts remain private.
