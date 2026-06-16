# Metrics contract

This page defines the public metric vocabulary for Agentic Security Harness. It is for
humans, LLM reviewers, and scripts that need to read the project without guessing what a
number means.

## Metric families

| Family | Source | Examples | Use | Do not use for |
|---|---|---|---|---|
| GitHub traffic | GitHub Insights | clones, unique cloners, views, unique visitors | Public interest and discoverability. | Benchmark quality, model safety, or trust claims. |
| Project process | GitHub Issues, PRs, milestones, CI | open issues by milestone/status, PR checks, release gates | Whether work is visible, reviewable, and ordered. | Claiming a planned feature is shipped. |
| Benchmark evidence | run artifacts | total checks, findings, inconclusive, adapter errors, validator status | What the harness actually observed and validated. | Production certification or proof a target is secure. |
| Runtime evidence | `run_config.json`, raw responses | model id, runtime, local-only flag, repeats, raw response hashes, recovery hints | Reproducibility and local/external execution context. | Leaderboard-grade model ranking. |
| Showcase evidence | generated docs from artifacts | scenario matrix, failure cards, latest runs, reproduce commands | Fast public understanding without reading source code. | Hand-written marketing claims. |

## GitHub traffic metrics

GitHub traffic is useful for project visibility:

| Metric | Meaning | Correct wording |
|---|---|---|
| Clones | Total clone events in the selected window. | "The repo was cloned N times." |
| Unique cloners | Estimated unique accounts/devices that cloned. | "N unique cloners pulled the repo." |
| Views | Total repository page views. | "The repo received N views." |
| Unique visitors | Estimated unique visitors. | "N unique visitors viewed the repo." |

Traffic metrics are never benchmark evidence. A traffic spike may mean bots, curiosity,
dependency scanners, search indexing, or real users. Treat it as attention, not trust.

## Benchmark evidence metrics

These come from artifacts written by `ash run`, `ash compare`, `ash run-matrix`, or
`ash run-external`.

| Metric | Artifact | Meaning |
|---|---|---|
| `total_checks` | `scorecard.json`, `external_summary.json` | Number of evaluated pattern/variant/repeat checks. |
| `patterns_with_findings` | `scorecard.json`, `external_summary.json` | Patterns where a deterministic finding was recorded. |
| `inconclusive_patterns` | `external_summary.json` | Model output was contradictory, incomplete, or not strong evidence. |
| `error_patterns` | `external_summary.json` | Runtime/adapter failed for that pattern. |
| `flaky_patterns` | `external_summary.json` | Repeats produced mixed outcomes. |
| `validator status` | `ash validate <dir>` | Artifact integrity and corpus conformance. |
| `comparison delta` | `comparison.md`, `run_diff.json` | Difference between baseline and protected/current runs. |

Correct wording:

> This run produced 4 checks: 0 findings, 2 inconclusive results, and 2 adapter errors.
> `ash validate` passed, so the artifacts are structurally valid. The run does not prove
> the model is safe.

Incorrect wording:

> The model passed.

If a run has inconclusive or adapter-error results, it did not pass. It produced weak or
failed evidence and needs recovery or a stronger runtime/profile.

## Runtime evidence metrics

Runtime evidence explains how the result was produced.

| Field | Artifact | Required interpretation |
|---|---|---|
| `model` / `model_id` | `run_config.json` | Exact model identifier supplied to the runtime. |
| `runtime_name` | `run_config.json.runtime` | Runtime family such as Ollama, LM Studio, vLLM, fake-local, or provider gateway. |
| `network_mode` | `run_config.json.runtime` | `local-only` means localhost/self-hosted; it does not remove model-license duties. |
| `prompt_only` | `run_config.json.runtime` | The external path asks the model for a verdict; it does not drive tools. |
| `tool_execution` | `run_config.json.runtime` | Must be `false` for current external runs. |
| `raw_response_sha256` | `external_results.json` | Lets reviewers verify raw response files without trusting summaries only. |
| `recovery_hint` | `external_results.json` | What to do after timeout, invalid JSON, or contradictory output. |

## Status vocabulary

| Status | Meaning | Public interpretation |
|---|---|---|
| `stable_pass` | Repeats consistently produced no finding. | No modeled finding in this run; not a safety proof. |
| `stable_finding` | Repeats consistently produced a finding. | Stronger evidence of the modeled failure. |
| `inconclusive` | Output cannot support pass/finding. | Weak evidence; inspect raw responses and rerun. |
| `adapter_error` | Runtime/transport failed. | Runtime reliability issue; fix profile or endpoint. |
| `flaky` | Repeats disagree. | Non-deterministic behavior; increase repeats or narrow conditions. |

## Minimum public run card

Every public showcase row should be reducible to this shape:

```text
Run: <run id or artifact path>
Target/model/runtime: <target or model> via <runtime>
Mode: deterministic local | external prompt-only | matrix | comparison
Scenario/suite: <scenario id>
Checks: <total>
Findings: <count>
Inconclusive: <count>
Errors: <count>
Validation: ash validate <dir> -> OK / failed
Artifacts: run_config, traces/external_results, scorecard/external_summary, report
Reproduce: <command>
Claim boundary: <one sentence>
```

## Script-friendly summary fields

Scripts should prefer JSON artifacts over Markdown:

| Need | Preferred artifact |
|---|---|
| Run settings | `run_config.json` |
| External aggregated result | `external_summary.json` |
| External per-request result | `external_results.json` |
| Local deterministic score | `scorecard.json` |
| Trace-level evidence | `traces.json` |
| Run history | `run_index.json` |
| Human report | `external_report.md`, `summary.md`, `executive.md`, `comparison.md` |

Markdown is for humans. JSON is the source of truth.

## Current limitation

The project does not yet ship an auto-generated multi-run public dashboard. Until issue
[#23](https://github.com/krivonosoff161/agentic-security-harness/issues/23) is closed,
showcase pages must be treated as curated views over validated artifacts.
