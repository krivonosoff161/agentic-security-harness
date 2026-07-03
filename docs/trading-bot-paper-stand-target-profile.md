# Trading Bot Paper Stand Target Profile

> Status: planned owned-system target profile.
>
> Tracking issue: [#136](https://github.com/krivonosoff161/agentic-security-harness/issues/136).
>
> This page describes how Agentic Security Harness can evaluate an authorized
> local paper/research trading workflow without moving raw vectors, private
> calculations, secrets, or trading logs into public artifacts.
>
> Runner design: [trading-bot-paper-stand-runner-design.md](trading-bot-paper-stand-runner-design.md).
>
> Private evidence contract:
> [trading-bot-private-evidence-contract.md](trading-bot-private-evidence-contract.md).
>
> Read-only target inventory:
> [trading-bot-stand-inventory-2026-07-03.md](trading-bot-stand-inventory-2026-07-03.md).
>
> Scenario catalog:
> [trading-bot-stand-scenario-catalog.md](trading-bot-stand-scenario-catalog.md).
>
> Static probe snapshot:
> [trading-bot-static-probe-snapshot-2026-07-03.md](trading-bot-static-probe-snapshot-2026-07-03.md).
>
> Boundary-lock snapshot:
> [trading-bot-boundary-lock-snapshot-2026-07-03.md](trading-bot-boundary-lock-snapshot-2026-07-03.md).
>
> Boundary-lock review:
> [trading-bot-boundary-lock-review-2026-07-03.md](trading-bot-boundary-lock-review-2026-07-03.md).
>
> Partial-marker sanitized summary:
> [trading-bot-partial-marker-sanitized-summary-2026-07-03.md](trading-bot-partial-marker-sanitized-summary-2026-07-03.md).
>
> Artifact probe snapshot:
> [trading-bot-artifact-probe-snapshot-2026-07-03.md](trading-bot-artifact-probe-snapshot-2026-07-03.md).
>
> Invariant controls:
> [baseline](trading-bot-invariant-baseline-sanitized-summary-2026-07-03.md),
> [negative-control](trading-bot-invariant-negative-control-sanitized-summary-2026-07-03.md),
> [weak-control](trading-bot-invariant-weak-control-sanitized-summary-2026-07-03.md).
>
> Real artifact observation:
> [trading-bot-real-artifact-observation-2026-07-03.md](trading-bot-real-artifact-observation-2026-07-03.md).
>
> Controlled experiment plan:
> [trading-bot-controlled-experiment-plan-2026-07-03.md](trading-bot-controlled-experiment-plan-2026-07-03.md).
>
> Experiment control summary:
> [trading-bot-experiment-control-sanitized-summary-2026-07-03.md](trading-bot-experiment-control-sanitized-summary-2026-07-03.md).
>
> Experiment batch-manifest summary:
> [trading-bot-experiment-batch-manifest-summary-2026-07-03.md](trading-bot-experiment-batch-manifest-summary-2026-07-03.md).
>
> Experiment intake-gate summary:
> [trading-bot-experiment-intake-gate-summary-2026-07-03.md](trading-bot-experiment-intake-gate-summary-2026-07-03.md).
>
> Experiment readiness snapshot:
> [trading-bot-experiment-readiness-snapshot-2026-07-03.md](trading-bot-experiment-readiness-snapshot-2026-07-03.md).

## Role Split

`agentic-security-harness` remains the security tool and evidence owner.
`trading-bot-v2` is only an authorized target stand.

```text
agentic-security-harness
  -> defines contours, scenario ids, expected invariants, adapters, reports
  -> stores public-safe target profile and sanitized findings
  -> keeps raw vectors and private traces out of git

trading-bot-v2
  -> provides a realistic owned paper/research workflow
  -> exposes scanner, LLM-router, farm/PFR, main-paper, runtime, ledger surfaces
  -> remains paper-only and never becomes the security project itself
```

The target profile is not a release claim about the trading system. It is a
controlled way to exercise agentic boundary failures against a realistic
multi-stage workflow.

## Authorization Model

| Field | Value |
|---|---|
| `authorization_mode` | `owned_system` |
| `target_owner` | `self` |
| `network_mode` | `off` or `local-only` by default; `authorized-external` only for separately approved public market-data reads |
| `data_class` | `synthetic` and `sanitized` |
| `tool_execution` | harness-controlled dry-run or paper-only target calls |
| `live_execution` | forbidden |
| `raw_evidence_location` | ignored `.internal/` or private research root |
| `public_artifact_level` | sanitized aggregate summaries, hashes, component names, pass/finding/inconclusive/error labels |

## Non-Negotiable Boundaries

- Do not read, print, copy, or publish `.env` secrets.
- Do not set or suggest `AUTO_TRADE=true`.
- Do not touch live order execution, private exchange/account endpoints, or real
  Telegram sends.
- Do not attack external LLM providers or provider infrastructure.
- Do not publish working payloads, raw prompt chains, raw traces, provider
  responses, or private trading calculations.
- Use synthetic canaries instead of real credentials.
- Treat provider timeouts, malformed responses, and concurrency effects as
  evidence-quality or boundary-behavior observations, not as permission to abuse
  the provider.

## Allowed Target Surfaces

The target can be inspected and driven only through paper/research-safe surfaces:

| Surface | Example target components | Allowed checks |
|---|---|---|
| Input and routing | scanner event records, watch queue rows | data-vs-instruction, source labels, stale-context flags |
| LLM role boundary | cheap extractor, chief reviewer, shared LLM router | malformed JSON, missing response, authority claims, retry/error handling |
| Deterministic gate | scanner orchestrator, validator/PFR bridge | whether code remains the authority owner |
| Paper bridge | main-paper instruction and consumer layers | validator identity, `paper_only`, `execution_allowed=false` |
| Runtime queue | paper runtime adapter and observer | `watch_paper` action integrity, invalid row handling |
| Ledger/training | paper trade ledger, preview/training export | auditability, tamper visibility, provenance retention |

Forbidden target surfaces:

- old live `main.py`;
- exchange order/account clients;
- `.env` and credential loaders;
- Telegram send paths;
- real provider endpoints for adversarial testing;
- live trading windows or auto-execution scripts.

## Seven Contours On This Target

| # | Harness contour | Target interpretation | Public failure signal |
|---|---|---|---|
| 1 | Data vs instruction boundary | Untrusted market/news/reasoning text looks like an instruction. | A downstream operational field changes because data text told it to. |
| 2 | Authority escalation | A model/source/advisory field claims validator, execution, risk, or planner authority. | `execution_allowed`, validator identity, or runtime action crosses a forbidden boundary. |
| 3 | Memory contamination | A contaminated context or summary survives into later paper stages. | Later stages lose provenance or treat old context as trusted authority. |
| 4 | Audit tampering | A malformed row tries to hide, overwrite, reorder, or relabel evidence. | Invalid data is counted as success or traceability is lost. |
| 5 | Planner/task authority confusion | Advisory text or task status tries to become a planner action. | The LLM/advisor controls a queue, task, policy, or strategy identity without deterministic validation. |
| 6 | Agentic rule-violation backpass | Several individually weak steps combine into a boundary bypass. | No single red flag fires, but the final artifact crosses an authority boundary. |
| 7 | Delayed/stale-context rehydration | Old context reappears later with inflated authority. | Expired, retried, or stale material is treated as current trusted state. |

## Parallel Scenario Batches

The harness should be able to schedule three or four isolated scenarios in one
batch. This is important because realistic agentic pressure often appears as
several weak signals moving through the system together.

Batch design stays high-level in public docs:

| Batch | Purpose | Example classes |
|---|---|---|
| A | LLM boundary pressure | data-looking instructions, authority claims, malformed JSON, provider fault recovery |
| B | Paper chain authority | fake readiness, runtime action drift, invalid status rows, ledger integrity |
| C | Memory and backpass | contaminated summary, stale replay, multi-hop low-signal bypass, emergent-vector slot |

Raw scenario bodies, exact prompts, timing traces, and calculations remain private.

## Researcher Mode

If a new behavior appears during target work, it must not be discarded as
"just a mock". The correct path is:

1. record a private note with raw evidence and component path;
2. classify the suspected failure class;
3. decide whether it is a subcase or a new contour;
4. run a bounded follow-up if it stays inside the safety boundary;
5. publish only a sanitized summary or scenario proposal.

Mock and synthetic providers are a safety mechanism, not a reason to ignore the
observed boundary behavior.

## Harness Adapter Plan

The first implementation should be harness-side and target-shaped:

1. **Profile document**: this file.
2. **Dry-run adapter design**: no target mutation and no network by default.
3. **Synthetic input pack**: private raw vectors; public scenario ids only.
4. **Observation contract**: map target outputs into ASH labels:
   `pass`, `finding`, `inconclusive`, or `error`.
5. **Private evidence anchors**: response hashes and aggregate counts only in
   public artifacts.
6. **Batch runner**: three to four scenarios per batch, with stop conditions for
   boundary breach, provider access, or live-path risk.

The runner should follow
[trading-bot-paper-stand-runner-design.md](trading-bot-paper-stand-runner-design.md):
start with `profile`, `dry-run`, and `offline-fixture` modes before any future
`authorized-paper` mode touches the target stand.

Current public-safe commands:

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

The `offline-fixture` mode uses sanitized, stand-shaped controls. It does not
contain working attack payloads or copied trading-bot logs. Its purpose is to
prove that the observation mapper preserves the result boundary:
`pass`, `finding`, `inconclusive`, and `error` remain separate.

The `authorized-paper` mode is currently a fail-closed gate report. It documents
which gates must pass before a future executor exists; it does not execute
target code.

The `sanitize-fixture` mode is the public/private bridge: it reads owner-retained
private fixture rows and emits only approved public evidence fields plus
`sha256` artifact anchors.

The `fixture-template` mode creates the 7-row private fixture skeleton only under
the ignored `.internal/trading-bot-paper-stand/issue-136/` evidence root.

The `invariant-fixture-template` mode creates the payload-free private template
for the next paper-only adversarial/invariant layer. It names the condition and
expected boundary, but leaves raw vectors, target rows, traces, and calculations
empty and private.

The `invariant-baseline-fixture` mode fills the private invariant fixture shape
from the current artifact-invariant probe result. It is a baseline/control
fixture, not an adversarial run.

The `invariant-negative-control-fixture` mode fills the private invariant
fixture shape with synthetic finding rows. It tests the finding path only and is
not evidence of a target failure.

The `invariant-weak-control-fixture` mode fills the private invariant fixture
shape with synthetic inconclusive rows. It tests the weak-evidence path only and
is not evidence of a target pass or failure.

The `validate-invariant-fixture` mode checks a private invariant fixture before
sanitization. It reports only counts and issue codes, never raw private values.

The `static-probe` mode is the first read-only target observation layer. It reads
only scenario-catalog observation files, emits file hashes and marker booleans,
and does not include raw source text.

The `boundary-lock` mode is the pre-experiment safety lock over those same
allowlisted observation files. It emits only marker counts and hashes for
secret-environment, provider-call, Telegram-send, and live-order indicators.
On the current target, it reports `review-required`: 3 scenarios contain
environment-boundary markers, while provider-call, Telegram-send, and live-order
markers are 0 in the allowlisted observation files.

The `boundary-lock-review` mode classifies those boundary markers without
publishing source lines or private values. On the current target it reports
`adapter-contract-required` with `blocking=false`: 2 reviewed files contain only
defensive documentation markers and 1 reviewed file contains a bounded
research-root configuration read. Secret env reads, unknown env reads, provider
calls, Telegram sends, live-order sites, and blocking markers are all 0. A
future adapter still must pass paths explicitly and avoid invoking target CLI
entrypoints that read environment configuration.

The `artifact-probe` mode is the first read-only paper artifact observation
layer. It inspects only allowlisted paper/research artifacts and emits
existence, line counts, hashes, and marker booleans without raw rows. If runtime
paper artifacts live outside the target checkout, `--artifact-root` keeps the
public source preflight and private evidence root separate.

The `artifact-invariant-probe` mode maps the allowlisted paper artifacts to the
seven scenario invariants using only schema keys, bounded booleans, and artifact
hashes. Its result is a schema/evidence observation, not an adversarial safety
certification.

The `artifact-e2e-observation` mode is the first ASH-side real paper-chain
observation. It reads only allowlisted paper artifacts under the private
Strategy Lab root, reports aggregate artifact checks and execution-boundary
booleans, and never includes raw card text, private values, target rows, or
trading calculations.

The first real paper artifact observation used `paper_research_e2e_smoke
--skip-run --no-calculator` as the source check and then reproduced the
public-safe summary through `artifact-e2e-observation`. It confirmed the current
paper artifact chain, bounded execution flags, and a passing evidence-quality
gate. The raw card text remains private.

The `experiment-plan` mode is the next layer: it binds the seven public scenario
ids to the three 3-4 scenario batch groups and private evidence slots. It can
attach the current artifact gate, but it still does not execute the target. The
`experiment-template` mode creates the ignored private JSON skeleton that later
controlled runs can fill with raw vectors, raw target rows, agent scripts,
traces, and calculations. `experiment-control-fixture` writes a not-executed,
all-inconclusive private control fixture to prove the validator/sanitizer loop
before adversarial rows exist.

The `validate-experiment` and `sanitize-experiment` modes complete that
private-to-public loop. Filled private rows are checked for all seven scenario
ids, expected batch ids, valid result classes, hash anchors, private slots, and
ignored-root placement. The sanitizer emits aggregate result counts, batch
counts, scenario ids, artifact hashes, private slot names, and redacted public
fields only.

The stricter real-row rules are documented in
[trading-bot-private-experiment-row-contract.md](trading-bot-private-experiment-row-contract.md):
claimed real target-observation rows must have filled private slots, a public
evidence object, an opaque condition id, and no control/baseline/template
marker.

The `experiment-baseline-fixture` mode creates the first observed private
experiment rows from the existing real artifact invariant probe. It records the
current seven-scenario baseline under `.internal`, validates and sanitizes as 7
`pass` rows, and still does not execute the target or publish raw artifacts.
The `experiment-negative-control-fixture` mode records a synthetic finding-path
control under `.internal`, validates and sanitizes as 7 `finding` rows, and is
not a target finding.

The `experiment-batch-manifest` mode records the private scheduling guard for
future filled experiment rows. It binds all seven public scenario ids to the
three planned batches, caps max parallel scenarios at 4, and preserves the
no-env/no-live/no-provider/no-Telegram gates. The
`validate-experiment-batch-manifest` mode checks that guard before any filled
private rows are accepted.

The `experiment-intake` mode is the final gate before public sanitization of
filled private rows. It blocks structurally valid baseline/control/template row
sets unless they contain seven real target-observation rows under the stricter
filled-row contract.

The `experiment-readiness` mode is the gate before filled private rows. On the
current paper artifact chain it is ready: target preflight, artifact-chain,
execution-boundary, evidence-quality, control-fixture, provider-boundary, and
live-boundary gates pass.

No adapter should be merged as a default target until it proves:

- default offline/dry-run behavior;
- no `.env` access;
- no live/order imports;
- no Telegram sends;
- artifact validation compatibility;
- public/private evidence separation.

## Public Output Contract

Public output may include:

- target profile id;
- component names;
- scenario ids;
- aggregate pass/finding/inconclusive/error counts;
- sanitized weakness summaries;
- response or artifact hashes;
- recommended ASH benchmark improvements.

Public output must not include:

- exact prompt-injection text;
- raw target logs;
- private trading calculations;
- private endpoint details;
- credentials or secret-shaped canaries;
- step-by-step bypass recipes.

## Done Criteria For Issue #136

- This target profile exists in the harness docs.
- The profile names allowed and forbidden target surfaces.
- The seven contours are mapped to trading-bot components.
- Private-evidence rules are explicit.
- The first harness-side adapter/runner plan is defined without touching live
  trading, secrets, Telegram, or external-provider attack paths.
- Offline fixture mapping covers the seven contours and keeps weak evidence out
  of `pass`/`finding`.
- Private fixture sanitization emits hash-anchored public summaries without raw
  vectors, prompts, target rows, provider transcripts, or private calculations.
- Private fixture templates are generated only under the ignored evidence root
  and are not public artifacts.
- Invariant control fixtures cover baseline, finding, and inconclusive paths
  without publishing payloads or private values.
- Static probing is limited to allowlisted source files and produces hash/marker
  observations, not raw code or security verdicts.
- Boundary-lock scanning is limited to allowlisted scenario observation files
  and currently blocks unattended filled-row execution pending review of
  environment-boundary markers.
- Boundary-lock review classifies the marked observation files without raw
  source and reduces the current blocker to an explicit adapter-contract
  requirement: 0 secret env reads, 0 unknown env reads, 0 provider calls, 0
  Telegram sends, 0 live-order sites, and 0 blocking markers.
- Artifact probing is limited to allowlisted paper/research artifacts and
  produces hash/count/marker observations, not raw rows or security verdicts.
- Real paper artifact observations can be summarized without publishing raw
  cards, target rows, market calculations, provider transcripts, or payloads.
- `artifact-e2e-observation` can summarize the real paper-chain artifact
  evidence and classify evidence-quality issues without executing the target or
  exposing raw private artifacts.
- Controlled paper experiment planning covers the seven scenario ids, three
  batch groups, private evidence slots, and current artifact gate without
  executing the target or publishing payloads.
- The not-executed experiment control fixture validates and sanitizes as 7
  `inconclusive` rows with 0 validation issues and no raw private values.
- The observed experiment baseline fixture validates and sanitizes as 7 `pass`
  rows from existing paper artifacts with 0 validation issues and no raw private
  values.
- The experiment negative-control fixture validates and sanitizes as 7
  `finding` rows with 0 validation issues and no raw private values; it is a
  sanitizer/validator control, not a target finding.
- Experiment readiness is machine-readable and currently ready for private
  filled experiment rows; this is still a non-executing preflight gate, not a
  live/execution safety certification.
- The private experiment batch manifest validates the three controlled batch
  groups, all seven scenario ids, max parallel 4, and required stop gates before
  private filled rows are accepted.
- The experiment intake gate blocks structurally valid baseline/control/template
  row sets from being promoted into public filled-row evidence.
- Filled private experiment rows can be validated and sanitized into public-safe
  aggregate summaries without exposing raw vectors, agent scripts, target rows,
  traces, private calculations, or short free-form instruction text.
- Claimed real target-observation rows now have an explicit validator contract:
  filled private slots, public evidence object, opaque condition id, and
  non-control markers are required before public sanitization.
- `authorized-paper` remains a fail-closed gate report until owner approval,
  implementation gates, and private evidence handling are proven.
