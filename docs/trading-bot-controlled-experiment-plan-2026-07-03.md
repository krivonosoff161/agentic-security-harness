# Trading Bot Controlled Experiment Plan

> Date: 2026-07-03.
>
> Scope: public-safe plan for controlled paper-only experiments over the seven
> `trading-bot-v2` stand scenarios.
>
> Tracking issue:
> [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).

## Purpose

This is the bridge between passive artifact observation and future authorized
paper experiments.

The plan keeps `agentic-security-harness` as the security runner and evidence
owner while `trading-bot-v2` remains an owned paper/research stand. It is not an
executor and does not run target code.

## Commands

Public-safe plan:

```bash
ash trading-stand --mode boundary-lock \
  --target-path C:/Users/krivo/trading-bot-v2

ash trading-stand --mode boundary-lock-review \
  --target-path C:/Users/krivo/trading-bot-v2

ash trading-stand --mode experiment-plan \
  --target-path C:/Users/krivo/trading-bot-v2 \
  --artifact-root <private-strategy-lab-root>
```

Private template:

```bash
ash trading-stand --mode experiment-template \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-template.json
```

Private validation and public-safe sanitization:

```bash
ash trading-stand --mode experiment-baseline-fixture \
  --target-path C:/Users/krivo/trading-bot-v2 \
  --artifact-root <private-strategy-lab-root> \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json

ash trading-stand --mode experiment-negative-control-fixture \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-negative-control-2026-07-03.json

ash trading-stand --mode experiment-control-fixture \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json

ash trading-stand --mode experiment-batch-manifest \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json

ash trading-stand --mode validate-experiment-batch-manifest \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json

ash trading-stand --mode experiment-intake \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json \
  --manifest-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json

ash trading-stand --mode experiment-readiness \
  --target-path <trading-bot-v2> \
  --artifact-root <private-strategy-lab-root> \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json

ash trading-stand --mode authorized-paper \
  --target-path <trading-bot-v2> \
  --artifact-root <private-strategy-lab-root> \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json \
  --manifest-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json

ash trading-stand --mode validate-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json

ash trading-stand --mode sanitize-experiment \
  --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json
```

The template path is intentionally under the ignored private evidence root.
The control fixture path is also ignored and is used only to prove the
validation/sanitization loop before target-side experiment rows exist.

## Batches

The plan keeps agentic pressure grouped into three controlled batches. Each
batch can carry three or four scenario classes without publishing raw vectors or
payloads.

| Batch | Purpose | Public status |
|---|---|---|
| A | LLM boundary pressure | planned, not executed |
| B | Paper chain authority | planned, not executed |
| C | Memory and backpass pressure | planned, not executed |

The public plan exposes scenario ids, contour ids, observation points, expected
boundaries, and public evidence field names. It does not expose prompt bodies,
timing tricks, target rows, raw traces, or calculations.

Filled private experiment rows must pass `validate-experiment` before their
public derivative is accepted. The validator checks:

- all seven scenario ids are present exactly once;
- every row stays under the expected batch id;
- result classes are one of `pass`, `finding`, `inconclusive`, or `error`;
- each row has a `sha256:` artifact anchor;
- private slots exist for raw vectors, agent scripts, target rows, private
  calculation notes, and raw traces;
- claimed real target-observation rows have filled private slots, a public
  evidence object, and an opaque `adversarial_condition_id`;
- the fixture lives under the ignored evidence root.

`sanitize-experiment` emits only aggregate counts, batch counts, scenario ids,
artifact hashes, private slot names, and redacted public fields. It does not
copy private slot values.

The full private row contract is documented in
[trading-bot-private-experiment-row-contract.md](trading-bot-private-experiment-row-contract.md).

The first control fixture summary is recorded in
[trading-bot-experiment-control-sanitized-summary-2026-07-03.md](trading-bot-experiment-control-sanitized-summary-2026-07-03.md):
7 records, 7 scenarios, 0 validation issues, and 7 `inconclusive` rows because
no target experiment was executed.

The first observed baseline fixture summary is recorded in
[trading-bot-experiment-baseline-sanitized-summary-2026-07-03.md](trading-bot-experiment-baseline-sanitized-summary-2026-07-03.md):
7 records, 7 scenarios, 0 validation issues, and 7 `pass` rows from the
existing real artifact invariant probe. It is a baseline, not an adversarial
finding or production-safety claim.

The first finding-path control summary is recorded in
[trading-bot-experiment-negative-control-sanitized-summary-2026-07-03.md](trading-bot-experiment-negative-control-sanitized-summary-2026-07-03.md):
7 records, 7 scenarios, 0 validation issues, and 7 `finding` rows. It is a
synthetic control for the sanitizer/validator path, not a target finding.

The first batch-manifest guard summary is recorded in
[trading-bot-experiment-batch-manifest-summary-2026-07-03.md](trading-bot-experiment-batch-manifest-summary-2026-07-03.md):
7 scenarios, 3 batches, 0 validation issues, max parallel 4, and the same
no-env/no-live/no-provider/no-Telegram boundary as the public experiment plan.
It is a scheduling guard for future private filled rows, not an executor.

The first intake-gate summary is recorded in
[trading-bot-experiment-intake-gate-summary-2026-07-03.md](trading-bot-experiment-intake-gate-summary-2026-07-03.md):
the observed baseline rows remain structurally valid but are blocked from
becoming real filled-row evidence because the real target-observation count is
0. This prevents baseline/control/template rows from being promoted into public
adversarial experiment results.

The current readiness gate is recorded in
[trading-bot-experiment-readiness-snapshot-2026-07-03.md](trading-bot-experiment-readiness-snapshot-2026-07-03.md).
It is ready: target preflight, artifact-chain, execution-boundary,
evidence-quality, control-fixture, provider-boundary, and live-boundary gates
all pass.

The current boundary-lock snapshot is recorded in
[trading-bot-boundary-lock-snapshot-2026-07-03.md](trading-bot-boundary-lock-snapshot-2026-07-03.md).
It is `review-required`: provider-call, Telegram-send, and live-order markers
are 0 in the allowlisted observation files, but 3 scenarios contain
environment-boundary markers. That means unattended filled-row execution remains
blocked until those markers are manually reviewed or covered by a stricter
adapter contract.

The follow-up boundary-lock review is recorded in
[trading-bot-boundary-lock-review-2026-07-03.md](trading-bot-boundary-lock-review-2026-07-03.md).
It reports `adapter-contract-required` with `blocking=false`: 2 reviewed files
are documentation-only, 1 reviewed file contains a bounded research-root config
read, and secret env reads, unknown env reads, provider calls, Telegram sends,
live-order sites, and blocking markers are all 0. The adapter still must pass
paths explicitly and avoid target CLI entrypoints that read environment
configuration.

## Safety Gates

The current mode is read-only:

- target mutation: false;
- `.env` read: false;
- provider calls: false;
- Telegram sends: false;
- live execution: false;
- payloads included: false;
- raw vectors included: false;
- private calculations included: false.

The experiment sanitizer uses a stricter text policy than the generic fixture
sanitizer: free-form strings are hash-redacted unless they match a narrow
identifier/path-shaped allowlist. This prevents a short raw instruction from
being accidentally published as public evidence.

If an artifact root is provided, the plan attaches the current
`artifact-e2e-observation` gate. On the current private paper chain, that gate
shows the artifact chain is present, the execution boundary remains bounded,
and the evidence-quality gate passes without unresolved findings.

## Current Gate Result

Current public-safe result from the real private artifact root:

| Field | Value |
|---|---|
| `artifact_checks_ok` | true |
| `execution_boundary_ok` | true |
| `result_class` | `pass` |
| `evidence_quality_findings` | none |

This is not a production-safety claim. It means the read-only paper artifact
gate is strong enough to start filling private experiment rows for the seven
scenario batches while preserving the same no-live/no-provider/no-secret
boundary.

The `authorized-paper` mode is the non-executing authorization gate for this
step. It reports `accepted` only when the private readiness bundle is valid:
target preflight, artifact readiness, private fixture validation,
batch-manifest validation, explicit owner/run approval, and
no-live/no-provider/no-Telegram boundaries must all pass. It does not execute
target code or run adversarial payloads.

## Next Research Step

The next step is to fill the ignored private experiment template with bounded
synthetic vectors and target-side observation rows, then sanitize only aggregate
result classes and artifact hashes back into public docs.

External-provider adversarial testing, live order paths, `.env`, and Telegram
send paths remain out of scope.
