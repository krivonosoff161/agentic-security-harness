# Trading Bot Paper Stand Runner Design

> Status: design for issue [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> This is the harness-side execution design for using `trading-bot-v2` as an
> authorized paper-only stand. It intentionally does not register a runnable
> built-in target yet, because a profile-only target that returns `pass` would be
> misleading evidence.

## Why This Is Not A Normal Built-In Target Yet

Built-in ASH targets are deterministic and self-contained. The trading bot is a
separate owned repository with its own runtime, private research root, local
state, and paper/research processes. Treating it as a regular built-in target
before an adapter contract exists would blur three things:

- a planned profile;
- a dry-run harness check;
- an actual observed target behavior.

The first implementation should therefore be a guarded harness-side runner that
can prove its safety gates before it records any finding.

## Runner Modes

| Mode | Network | Target mutation | Purpose |
|---|---:|---:|---|
| `profile` | none | none | Print the target profile, contours, allowed surfaces, and non-goals. |
| `dry-run` | none | none | Build scenario plan and expected observation points without touching the target repo. |
| `offline-fixture` | none | temp dir only | Replay sanitized fixture rows through ASH observation mapping. |
| `artifact-e2e-observation` | none | none | Summarize the real paper artifact chain from an allowlisted private artifact root without raw rows or card text. |
| `experiment-plan` | none | none | Plan controlled 3-4 scenario paper batches with private evidence slots and no target execution. |
| `experiment-template` | none | ignored private file only | Write a payload-free private experiment template under `.internal/`. |
| `experiment-baseline-fixture` | none | ignored private file only | Write observed private baseline rows from existing artifact invariants. |
| `experiment-negative-control-fixture` | none | ignored private file only | Write payload-free synthetic finding-path rows. |
| `experiment-control-fixture` | none | ignored private file only | Write a payload-free, not-executed, all-inconclusive control fixture. |
| `experiment-batch-manifest` | none | ignored private file only | Write the private 3-batch scheduling guard. |
| `validate-experiment-batch-manifest` | none | none | Validate the private batch guard before filled rows. |
| `experiment-intake` | none | none | Gate private filled rows before public sanitized summaries. |
| `experiment-readiness` | none | none | Evaluate whether artifact, control, and safety gates allow filled private experiment rows. |
| `boundary-lock-review` | none | none | Classify boundary-lock markers without source lines or private values. |
| `validate-experiment` | none | none | Validate filled private experiment rows without exposing raw values. |
| `sanitize-experiment` | none | none | Emit public-safe experiment summaries from private rows. |
| `authorized-paper` | bounded / explicit | paper-only artifacts only | Future mode: drive approved target commands or local fixtures under explicit gates. |

Default must be `profile` or `dry-run`. No mode may read `.env`.

Current harness-side inspection commands:

```bash
ash trading-stand --format json
ash trading-stand --mode dry-run --target-path C:/Users/krivo/trading-bot-v2
ash trading-stand --mode offline-fixture
ash trading-stand --mode scenario-catalog
ash trading-stand --mode fixture-template --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/private-fixture.json
ash trading-stand --mode invariant-fixture-template --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/invariant-fixture-template.json
ash trading-stand --mode invariant-baseline-fixture --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root> --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/invariant-baseline.json
ash trading-stand --mode invariant-negative-control-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/invariant-negative-control.json
ash trading-stand --mode invariant-weak-control-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/invariant-weak-control.json
ash trading-stand --mode validate-invariant-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/invariant-baseline.json
ash trading-stand --mode sanitize-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/private-fixture.json
ash trading-stand --mode static-probe --target-path C:/Users/krivo/trading-bot-v2
ash trading-stand --mode boundary-lock --target-path C:/Users/krivo/trading-bot-v2
ash trading-stand --mode boundary-lock-review --target-path C:/Users/krivo/trading-bot-v2
ash trading-stand --mode artifact-probe --target-path C:/Users/krivo/trading-bot-v2
ash trading-stand --mode artifact-probe --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root>
ash trading-stand --mode artifact-invariant-probe --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root>
ash trading-stand --mode artifact-e2e-observation --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root>
ash trading-stand --mode experiment-plan --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root>
ash trading-stand --mode experiment-template --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-template.json
ash trading-stand --mode experiment-baseline-fixture --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root> --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-baseline-2026-07-03.json
ash trading-stand --mode experiment-negative-control-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-negative-control-2026-07-03.json
ash trading-stand --mode experiment-control-fixture --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json
ash trading-stand --mode experiment-batch-manifest --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json
ash trading-stand --mode validate-experiment-batch-manifest --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json
ash trading-stand --mode experiment-intake --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json --manifest-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-batch-manifest-2026-07-03.json
ash trading-stand --mode experiment-readiness --target-path C:/Users/krivo/trading-bot-v2 --artifact-root <private-strategy-lab-root> --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/experiment-control-2026-07-03.json
ash trading-stand --mode validate-experiment --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json
ash trading-stand --mode sanitize-experiment --fixture-path .internal/trading-bot-paper-stand/issue-136/manifests/filled-experiment.json
ash trading-stand --mode authorized-paper --target-path C:/Users/krivo/trading-bot-v2
```

These commands do not run the trading bot, import target modules, read `.env`,
call providers, send Telegram messages, or mutate the target repository. They
only print the profile, scenario batches, read-only preflight status, and
sanitized fixture mapping. `sanitize-fixture` reads private fixture JSON and
prints only a public-safe summary with hash anchors. `fixture-template` writes
only under the ignored private evidence root. `static-probe` reads only the
scenario-catalog observation files and emits file hashes plus marker booleans,
not raw source. `boundary-lock` reads those same allowlisted observation files
and emits only marker counts for secret-environment, provider-call,
Telegram-send, and live-order indicators. It is a pre-experiment lock, not an
exploit scanner. `artifact-probe` reads only allowlisted paper/research artifact
files and emits existence, counts, hashes, and marker booleans, not raw rows.
`invariant-fixture-template` writes a payload-free 7-row private template for
the next paper-only adversarial/invariant layer. `invariant-baseline-fixture`
fills that private shape from the current artifact-invariant probe result so
the evidence pipeline can be tested end-to-end before adversarial rows exist.
`invariant-negative-control-fixture` fills the same private shape with
payload-free synthetic finding rows to prove that finding validation and
sanitization work. It is not a target observation.
`invariant-weak-control-fixture` fills the same private shape with payload-free
synthetic inconclusive rows to prove that weak evidence is not promoted into
either `pass` or `finding`. It is not a target observation.
`validate-invariant-fixture` checks private invariant fixtures before they are
sanitized into public summaries.
When paper artifacts live outside the public target checkout, `--artifact-root`
points to the private paper/research root, `state/`, or `state/derived/`.
`artifact-invariant-probe` maps those allowlisted artifacts to the seven
scenario invariants using JSON keys, booleans, and hashes only; it does not
claim an adversarial benchmark pass.
`artifact-e2e-observation` reads the allowlisted end-to-end paper chain,
summarizes artifact presence/count/hash status, checks paper-only execution
boundaries, and reports evidence-quality findings such as preview-card contract
drift without raw card text, target rows, private values, provider transcripts,
or trading calculations.
`experiment-plan` turns the seven scenario catalog rows and the three
parallel-pressure batches into a controlled paper experiment plan. It may attach
the current `artifact-e2e-observation` gate, but it still does not execute the
target. `experiment-template` writes only empty private slots for raw vectors,
agent scripts, target rows, traces, and calculations under the ignored evidence
root. `experiment-control-fixture` writes a not-executed, all-inconclusive
control fixture so validation and sanitization can be proven before adversarial
rows exist. `experiment-baseline-fixture` writes observed baseline rows from
existing artifact invariants. `experiment-negative-control-fixture` writes
synthetic finding-path rows to prove the sanitizer/validator path without
target execution. `experiment-batch-manifest` writes the ignored private guard
that binds the seven scenario ids to three planned batches, max parallel 4, and
the no-env/no-live/no-provider/no-Telegram gates before filled private rows are
accepted. `validate-experiment-batch-manifest` checks that guard without
exposing private vectors or calculations. `experiment-intake` is the gate
between private rows and public sanitized summaries: baseline/control/template
rows may validate structurally, but they are blocked unless all seven rows are
real target observations under the filled-row contract. `experiment-readiness` combines
target preflight, artifact-chain state, execution-boundary state,
evidence-quality findings, and control-fixture validation into a single
ready/blocked gate. `validate-experiment` checks filled private rows for full seven-scenario
coverage, expected batch ids, result classes, `sha256:` anchors, private slots,
and ignored-root placement. `sanitize-experiment` emits aggregate counts, batch
counts, scenario ids, artifact hashes, and redacted public fields without
copying private slot values.
`boundary-lock-review` is the follow-up to the coarse pre-experiment marker
scan. It reviews only files that `boundary-lock` already marked, classifies
documentation-only markers separately from bounded configuration reads, and
blocks on secret env names, unknown env names, provider calls, Telegram sends,
or live-order sites. It never emits raw source lines or private values.
`authorized-paper` is currently a fail-closed gate report, not an executor.

## Preflight Gates

A future runner must fail closed unless all required gates pass:

| Gate | Required state |
|---|---|
| Target path | Explicit path supplied; no implicit path guessing. |
| Git state | Dirty files reported; runner does not edit target repo. |
| Secret boundary | `.env` and secret files are not read. |
| Execution boundary | `AUTO_TRADE` not enabled; no live/order scripts selected. |
| Network boundary | Network mode declared; default `off`. |
| Provider boundary | External LLM providers not called for adversarial scenarios. |
| Telegram boundary | Send paths disabled. |
| Evidence boundary | Raw vectors and traces written only to ignored/private locations. |
| Stop condition | Any live-path, credential, provider, or Telegram risk aborts the batch. |
| Boundary lock | Allowlisted observation files must be reviewed when environment/provider/Telegram/live markers are present. |
| Boundary review | Current marked files must have no secret env reads, no unknown env reads, no provider calls, no Telegram sends, and no live-order sites. |

## Observation Contract

The runner should map target observations into ASH result classes:

| ASH class | Trading-stand meaning |
|---|---|
| `pass` | The declared boundary held and the target emitted auditable safe behavior. |
| `finding` | A declared invariant failed with sufficient evidence. |
| `inconclusive` | The target output was missing, stale, too weak, or semantically ambiguous. |
| `error` | Adapter/runtime/preflight failed; do not score as pass/finding. |

Provider timeout, malformed JSON, stale rows, and missing artifacts are evidence
quality or runtime errors until an invariant-level failure is proven.

## Scenario Batch Shape

The target-profile batch scheduler should support three or four isolated
scenario classes per batch:

```text
batch_id:
  target_profile: trading-bot-v2-paper-stand
  mode: dry-run | offline-fixture | artifact-e2e-observation | experiment-plan | authorized-paper
  contours:
    - data_vs_instruction_boundary
    - authority_escalation
    - audit_tampering
    - provider_fault_recovery
  stop_gates:
    - no_env_read
    - no_live_execution
    - no_external_provider_attack
    - no_telegram_send
  private_slots:
    - raw_vector
    - raw_agent_script
    - raw_target_rows
    - private_calculation_note
    - raw_trace
```

Raw scenario payloads remain private. Public artifacts should expose scenario
ids and component paths, not payload bodies.

`provider_fault_recovery` is an auxiliary stand stress class, not an eighth
core contour. It is included because provider timeouts, malformed JSON, and
missing responses are common ways boundary evidence becomes ambiguous.

## Adapter Architecture

The future adapter should be split into small pieces:

| Component | Responsibility |
|---|---|
| `TargetProfile` | Static metadata, allowed surfaces, forbidden surfaces, contours. |
| `Preflight` | Read-only safety checks. No `.env`. No target mutation. |
| `ScenarioPlanner` | Map ASH contours to target-specific observation points. |
| `FixtureRunner` | Replay sanitized target-like records through mapping logic. |
| `PaperRunner` | Future approved mode that executes bounded paper-only target commands. |
| `EvidenceWriter` | Writes private raw evidence and public sanitized summaries separately. |
| `ObservationMapper` | Converts target behavior into ASH trace/finding/inconclusive/error records. |

Do not let the adapter directly import or execute live trading modules.

## Private Evidence Layout

Recommended owner-side layout:

```text
.internal/trading-bot-paper-stand/
  issue-136/
    batches/
    raw-vectors/
    traces-private/
    calculations/
    emergent-vectors/
```

Public committed artifacts should contain only sanitized aggregates, hashes, and
scenario metadata.

The public-safe evidence contract is documented in
[trading-bot-private-evidence-contract.md](trading-bot-private-evidence-contract.md).

## First Implementation Slice

The first code slice should not touch the live target. It adds:

1. target profile data structure;
2. dry-run scenario planner;
3. preflight result model;
4. offline fixture mapper for `pass`, `finding`, `inconclusive`, and `error`;
5. fail-closed `authorized-paper` gate report;
6. private fixture template generator;
7. public-safe private fixture sanitizer;
8. read-only static probe over allowlisted target source files;
9. read-only boundary-lock marker scan over allowlisted target source files;
9a. boundary-lock marker review that separates documentation markers from
    bounded configuration reads without source lines or private values;
10. read-only artifact probe over allowlisted paper/research artifact files;
11. private invariant control fixtures for baseline, finding, and inconclusive
    paths;
12. read-only real paper artifact observation over the allowlisted end-to-end
    chain;
13. controlled experiment planning and private payload-free experiment
    templates for the next adversarial paper-only layer;
14. private all-inconclusive experiment control fixtures for validation/sanitizer
    round-trips;
15. experiment readiness gates over target preflight, artifact state, evidence
    quality, and control validation;
16. private experiment validation and public-safe sanitization for future filled
    rows;
17. private batch-manifest validation for the three controlled agentic batches;
18. private filled-row intake gating so baseline/control/template rows are not
    promoted into public adversarial experiment evidence;
19. tests proving no `.env`, provider, Telegram, or live execution path exists.

Only after that should an `authorized-paper` executor be considered.
