# Trading Bot Paper Stand Private Evidence Contract

> Status: public-safe contract for issue
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> This document defines where future raw vectors, calculations, target artifacts,
> and replay notes belong when `trading-bot-v2` is used as an authorized
> paper-only stand. It intentionally contains no working payloads, raw target
> logs, secrets, or private trading calculations.

## Purpose

The trading bot stand can produce useful security evidence only if public and
private artifacts are separated before any real paper run exists.

The public repository should show:

- which scenario ids were run;
- which components were observed;
- which ASH result classes were assigned;
- aggregate counts;
- hashes of private artifacts;
- conservative sanitized summaries.

The public repository should not show raw prompts, raw vectors, copied target
logs, provider transcripts, credentials, secret-shaped canaries, private trading
calculations, or step-by-step bypass recipes.

## Private Root

Recommended local-only layout:

```text
.internal/trading-bot-paper-stand/
  issue-136/
    manifests/
    batches/
    raw-vectors/
    traces-private/
    calculations/
    emergent-vectors/
    redaction-notes/
```

`.internal/` is ignored by git. The harness-side contract treats this root as
owner-retained evidence, not as a committed artifact source.

## Public Derivatives

Public artifacts may include only:

| Public field | Meaning |
|---|---|
| `run_id` | Opaque run id with no secret material. |
| `profile_id` | `trading-bot-v2-paper-stand`. |
| `mode` | `profile`, `dry-run`, `offline-fixture`, or future gated `authorized-paper`. |
| `target_commit` | Target repository commit, if safe to expose. |
| `scenario_ids` | Stable scenario ids, not payload bodies. |
| `result_counts` | Aggregate `pass`, `finding`, `inconclusive`, and `error` counts. |
| `artifact_hashes` | Hashes of private artifacts for later owner-side replay. |
| `safety_gates` | Gate names and pass/fail status, not raw evidence. |
| `sanitized_summary` | Short claim-boundary-preserving finding summary. |

## Manifest Contract

Each future private run should have a private manifest with at least:

```json
{
  "run_id": "opaque-run-id",
  "profile_id": "trading-bot-v2-paper-stand",
  "mode": "authorized-paper",
  "target_commit": "optional-target-commit",
  "scenario_ids": ["scenario-id"],
  "result_counts": {
    "pass": 0,
    "finding": 0,
    "inconclusive": 0,
    "error": 0
  },
  "artifact_hashes": {
    "private_trace_jsonl": "sha256:..."
  },
  "redaction_policy": "private-raw-public-aggregate",
  "safety_gates": {
    "no_env_read": true,
    "no_live_execution": true,
    "no_provider_attack": true,
    "no_telegram_send": true
  }
}
```

The public derivative may copy the manifest shape only after removing raw paths,
payload bodies, provider responses, and private calculations.

## Gate Rules

Future `authorized-paper` work remains blocked unless all of these are true:

| Gate | Required state |
|---|---|
| Owner approval | A specific run id and scope are approved. |
| Target path | Explicit local path; no implicit guessing. |
| Preflight | Read-only shape preflight passes. |
| Secret boundary | `.env` and credential files are not read. |
| Live boundary | Live order/account paths are not imported or executed. |
| Provider boundary | External LLM providers are not attacked; synthetic/offline rows are preferred. |
| Telegram boundary | Send paths remain disabled. |
| Evidence boundary | Raw vectors and calculations stay under ignored private root. |

Any failed gate turns the run into `error` or prevents execution. It must not be
converted into `pass` or `finding`.

## Current Implementation

Current shipped commands are still non-executing:

```bash
ash trading-stand --format json
ash trading-stand --mode dry-run --target-path <user-home>/trading-bot-v2
ash trading-stand --mode offline-fixture
ash trading-stand --mode scenario-catalog
ash trading-stand --mode fixture-template --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/private-fixture.json
ash trading-stand --mode sanitize-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/private-fixture.json
ash trading-stand --mode experiment-template --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-template.json
ash trading-stand --mode validate-experiment --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json
ash trading-stand --mode sanitize-experiment --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json
ash trading-stand --mode authorized-paper --target-path <user-home>/trading-bot-v2
```

`fixture-template` writes a 7-record private JSON template under the ignored
evidence root. The command refuses paths outside
`.internal/trading-bot-paper-stand/issue-136/` and refuses to overwrite an
existing template.
All harness-side private fixture writers require those root parts in contiguous order, resolve
existing ancestors before creating directories, recheck the resolved parent, and create the final
JSON file exclusively. A competing file is preserved rather than truncated. The caller remains
responsible for ensuring that a correctly shaped root outside this repository is actually private
and ignored by its own version-control policy.

`sanitize-fixture` reads owner-retained private fixture rows and emits only
catalog-approved public fields plus a hash of the sanitized public projection.
That hash does not depend on private values and is not a private-source
reconciliation receipt. The sanitizer must not copy raw vectors,
raw prompts, raw target rows, provider transcripts, or private calculations into
the public summary.

The `authorized-paper` command is a fail-closed gate report. It does not execute
target code.

The stricter controlled-experiment row contract is documented in
[trading-bot-private-experiment-row-contract.md](trading-bot-private-experiment-row-contract.md).
Filled target-observation rows must keep raw vectors, agent scripts, target rows,
traces, and private calculations in private slots under `.internal/`. They remain
self-declared until a separate observation-authority receipt validates; public
docs may carry only sanitized counts and explicitly scoped public hashes.
