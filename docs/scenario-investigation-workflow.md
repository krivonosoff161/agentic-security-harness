# Scenario investigation workflow

This workflow keeps scenario design, observed weak spots, confirmed findings, and
deeper variations separate. The separation is important: a weak local model timeout is
not the same thing as a benchmark finding, and a planned variation is not shipped
coverage.

## Evidence pipeline

```text
scenario family
  -> bounded probe
  -> artifact validation
  -> weak spot / finding / problem ledger
  -> reviewed deepening variations
  -> implementation issue / PR
```

## Four ledgers

| Ledger | What it stores | Source of truth | Public claim |
|---|---|---|---|
| Scenario matrix | What can be tested and under which topology. | Scenario docs + `scenarios.py`. | "This is the planned/implemented test surface." |
| Weak spots | Inconclusive, flaky, timeout, JSON-contract, runtime, or evidence-quality limits. | `external_summary.json`, `external_results.json`, raw responses, run logs. | "The run produced weak evidence; needs recovery or rerun." |
| Findings | Deterministic finding or stable external finding with trace evidence. | `traces.json`, `scorecard.json`, `external_summary.json`, deterministic cross-check. | "This modeled failure was observed in this run." |
| Deepening backlog | Next variations selected from a weak spot or finding. | Human-reviewed issue or docs row. | "This is the next bounded check, not shipped evidence yet." |

## Status vocabulary

| Status | Meaning |
|---|---|
| `planned` | Designed but not implemented. |
| `implemented` | Code/docs exist, but no public showcase artifact yet. |
| `validated-example` | A committed example validates with `ash validate`. |
| `local-scratch` | A maintainer local run exists under `reports/`; not committed public evidence. |
| `weak-spot` | Evidence quality/runtime/contract issue observed. |
| `finding` | Modeled failure observed and validated. |
| `needs-deepening` | Needs bounded follow-up variations before a stronger claim. |

## What counts as a weak spot

Weak spots are useful, but they are not findings:

- timeout / adapter error;
- invalid JSON or contradictory JSON;
- many `inconclusive` results;
- high latency on a small local model;
- missing runtime metadata;
- missing raw-response file;
- weak recovery guidance;
- scenario too broad for a single model run.

Weak spot wording:

> The local Prometheus smoke run produced valid artifacts but weak evidence:
> 2 inconclusive results and 2 adapter errors. This is a runtime/evidence-quality
> problem, not a model safety pass or security finding.

## What counts as a finding

A finding needs a clear invariant and artifact evidence:

1. scenario and pattern id;
2. expected boundary invariant;
3. observed behavior;
4. deterministic validator or stable external cross-check;
5. artifact path and reproduce command;
6. remediation/control family;
7. residual risk.

If any of those is missing, record it as `weak-spot` or `needs-deepening`, not as a
finding.

## Deepening variation rules

Do not expand by full cross-product. Pick variations from the observed evidence.

Allowed variation axes:

| Axis | Examples | Cap |
|---|---|---|
| Time / step depth | single-turn, multi-turn, delayed trigger, delayed recall | 3 per scenario |
| Source trust | trusted user, untrusted source, tool output, memory recall | 3 per scenario |
| Authority shape | direct user, delegated agent, claimed supervisor, missing approval | 3 per scenario |
| Context pressure | short context, noisy context, conflicting instruction, long summary | 2 per scenario |
| Runtime profile | deterministic target, weak local model, stronger local/API model | 2 per pass |
| Repeats | 1 smoke, 3 reliability, 5+ only for selected unstable cases | 5 by default |

Rejected variation axes:

- provider x model x prompt wording x language x country x retry count full grid;
- live third-party target without authorization;
- tool execution before an adapter contract and safety gate exist;
- committing raw local scratch reports as public evidence without curation.

## Triage decision

| Observation | Next action |
|---|---|
| `adapter_error` | Fix runtime/profile or increase timeout; repeat same scenario before adding new scenarios. |
| `inconclusive` | Inspect raw response; improve prompt/JSON contract or rerun with a stronger JSON-following model. |
| stable pass | Try one adjacent variation only if the scenario is important. |
| stable finding | Create a failure card and one deepening issue. |
| flaky | Increase repeats or narrow the scenario; do not score as pass/finding. |

## Required issue shape for deepening work

Every deepening issue should include:

```text
Scenario:
Pattern(s):
Observed weak spot/finding:
Invariant:
Variation axis:
Max variants:
Runtime target:
Expected artifact:
Stop condition:
Non-goals:
```

This keeps the project from turning into an unbounded prompt pile.
