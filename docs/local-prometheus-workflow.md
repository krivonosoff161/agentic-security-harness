# Local Prometheus workflow

This page defines the maintainer workflow for testing a small local model as a real
model-in-the-loop target. It is named "Prometheus" only as a local role: a weak local
model used to expose behavioral and runtime evidence under strict benchmark controls.

## Current low-memory profile

Observed maintainer hardware class:

| Resource | Observed class | Practical implication |
|---|---|---|
| RAM | about 8 GB | Prefer 1B-2B quantized models for smoke runs. |
| GPU | GTX 1050 class, 3 GB VRAM | Useful for small local inference/offload only; do not assume 3B+ models are comfortable. |
| Runtime | Ollama 0.23.x | Use the OpenAI-compatible `/v1` endpoint through `--preset ollama`. |

Recommended first model:

| Model id | Role | Why |
|---|---|---|
| `prometheus-qwen15b-lowctx:latest` | Primary maintainer Prometheus smoke model | Local Ollama alias with lower context/output settings; recovered the smoke path from timeout-only evidence. |
| `qwen2.5:1.5b` | Generic low-memory fallback | Easy to reproduce after `ollama pull qwen2.5:1.5b`, but may timeout on the observed machine unless wrapped in a low-context alias. |
| `calculator:latest` | Alias / local operator model if it points to the same small model | Useful when the local setup already uses this name. |
| `qwen2.5:3b` / `llama3.2:3b` | Experimental only on this hardware class | May work, but can cause slow responses, timeouts, or memory pressure. |

This profile is deliberately conservative. The goal is not to find the strongest local
model; it is to collect reproducible real-model evidence without making the machine
unusable.

See [local-model-profiles.md](local-model-profiles.md) for the maintained profile table.

## What this does and does not test

Current support:

- local Ollama runtime through the experimental OpenAI-compatible external path;
- prompt-only synthetic scenarios;
- strict request caps;
- full raw-response artifacts;
- deterministic cross-checks over the model self-report;
- `ash validate` artifact validation.

Not current support:

- live tool execution;
- live agent-host control;
- native provider SDKs;
- shipped small-model swarm orchestration;
- live multi-agent runtime evidence;
- benchmark-grade model leaderboard;
- a claim that weak-model behavior generalizes to frontier models.

## Bounded suite command

The fastest safe path is the named, bounded suite (dry-run by default; only calls a model
on `--execute`):

```powershell
python -m agentic_security_harness.cli local-suite --list
python -m agentic_security_harness.cli local-suite --profile prometheus-lowctx-smoke            # dry-run
python -m agentic_security_harness.cli local-suite --profile prometheus-lowctx-smoke --execute  # real run + validate
```

Profiles live in [`local_profiles.py`](../src/agentic_security_harness/local_profiles.py)
and mirror the table in [local-model-profiles.md](local-model-profiles.md). The manual
step-by-step flow below is the same run expanded.

## Smoke flow

Run these from the repository root.

```powershell
# 1) confirm local runtime config; no benchmark request
python -m agentic_security_harness.cli external-check `
  --preset ollama `
  --model prometheus-qwen15b-lowctx:latest `
  --scenario data-boundary

# 2) preview the exact request count; no files written
python -m agentic_security_harness.cli run-external `
  --preset ollama `
  --model prometheus-qwen15b-lowctx:latest `
  --scenario data-boundary `
  --max-variants 1 `
  --repeats 1 `
  --max-requests 10 `
  --timeout 60 `
  --dry-run

# 3) real local run; localhost only, prompt-only, no tools
python -m agentic_security_harness.cli run-external `
  --preset ollama `
  --model prometheus-qwen15b-lowctx:latest `
  --scenario data-boundary `
  --max-variants 1 `
  --repeats 1 `
  --max-requests 10 `
  --timeout 60 `
  --raw-response-limit 0 `
  --out reports/local-prometheus-lowctx-smoke-prometheus-qwen15b-lowctx-latest

# 4) validate artifacts
python -m agentic_security_harness.cli validate reports/local-prometheus-lowctx-smoke-prometheus-qwen15b-lowctx-latest
```

Expected request count for this smoke flow: 4.

## How to read first results

On this hardware class, the base `qwen2.5:1.5b` profile timed out while loading a large
context. The recovered `prometheus-qwen15b-lowctx:latest` profile produces valid artifacts
but weak evidence. A current data-boundary reliability
rerun produced:

```text
checks: 12
findings: 0
inconclusive: 9
stable_pass: 3
adapter_error: 0
validation: OK
```

Interpretation:

- this is not a pass;
- this is not a boundary-failure finding;
- it is useful evidence that the weak local model/runtime can return structurally valid
  JSON while still contradicting itself under the strict verdict contract;
- the recovery path is to inspect `raw_responses/`, increase timeout/repeats, or test a
  stronger JSON-following local model.

A first `authority-control` smoke run produced 2 checks, 0 findings, 1 stable pass,
and 1 inconclusive result. Treat that as a prompt-contract weak spot, not as a model
pass.

A first `approval-audit` smoke run produced 3 checks, 0 findings, and 3 inconclusive
results. This is a stronger sign that approval/audit prompts are difficult for the
current weak local profile under the strict JSON verdict contract; it should drive
prompt-contract and failure-card work before broader repeats.

## Multi-step status

The project has deterministic multi-turn timeline fixtures and replay validation in
[`scenario-timeline.md`](scenario-timeline.md), but the current Prometheus local-suite
path is still prompt-only per pattern. A local Prometheus run can therefore collect real
model evidence for the scenario families (`data-boundary`, `authority-control`,
`memory-governance`, etc.), while multi-step live-model orchestration remains a separate
future runner. Do not describe prompt-only local-suite results as live multi-agent
runtime evidence.

## 2026-06-21 bounded rerun

Issue [#50](https://github.com/krivonosoff161/agentic-security-harness/issues/50)
added a fresh bounded rerun on the maintainer Ollama profile. The run used
`prometheus-qwen15b-lowctx:latest`, prompt-only local execution, one variant per
scenario, and validated local scratch artifacts.

| Scenario | Checks | Pass | Findings | Inconclusive | Adapter errors | Artifact status |
|---|---:|---:|---:|---:|---:|---|
| `data-boundary` | 6 | 2 | 0 | 4 | 0 | `ash validate` OK |
| `authority-control` | 2 | 1 | 0 | 1 | 0 | `ash validate` OK |
| `approval-audit` | 3 | 0 | 0 | 3 | 0 | `ash validate` OK |

Fresh-only `ash evidence-quality` over those three local scratch runs reported 11
results, 27.3% decisive evidence, 72.7% weak evidence, 100% raw-response hash coverage,
100% assertion binding, and 0/11 cross-run disagreement. This is real local
model-in-the-loop evidence on synthetic benchmark scenarios, but it is still weak
evidence: no benchmark finding was produced, and inconclusive results must not be
reported as passes.

This is exactly why local real-model probes are useful: even before finding a security
boundary failure, they reveal runtime reliability and evidence-quality limits that a
synthetic deterministic target cannot show.

Issue [#59](https://github.com/krivonosoff161/agentic-security-harness/issues/59)
extended the bounded rerun to the three current boundary-layer evidence areas:
data-boundary, authority-control, and memory-governance. The memory profile is named
`prometheus-lowctx-memory-smoke`. The run used 13 total local requests, no tool
execution, no private endpoint, and no committed raw reports.

| Scenario | Checks | Pass | Findings | Inconclusive | Adapter errors | Artifact status |
|---|---:|---:|---:|---:|---:|---|
| `data-boundary` | 6 | 2 | 0 | 4 | 0 | `ash validate` OK |
| `authority-control` | 2 | 1 | 0 | 1 | 0 | `ash validate` OK |
| `memory-governance` | 5 | 1 | 0 | 4 | 0 | `ash validate` OK |

`ash evidence-quality --root reports/prometheus-boundary-20260621` reported 13 results,
30.8% decisive evidence, 69.2% weak evidence, 100% raw/hash coverage, 100% assertion
binding, and 0/13 cross-run disagreement. This remains local-empirical evidence, not a
public benchmark finding and not a claim that the model is safe.

## Escalation ladder

Use this order. Do not jump to large runs first.

| Step | Command shape | Goal | Stop condition |
|---|---|---|---|
| Preflight | `external-check --preset ollama` | Config and request estimate. | Model missing, server down, bad scenario. |
| Dry-run | `run-external --dry-run` | Confirm cap and no file writes. | Request count too high. |
| Smoke | `data-boundary`, 1 variant, 1 repeat | First real model evidence. | Any adapter errors or many inconclusive outputs. |
| Reliability rerun | same scenario, `--repeats 2-3`, higher timeout | Check if errors are stable. | Flaky/inconclusive remains high. |
| Scenario expansion | one more scenario at a time | Broaden evidence without combinatorial blow-up. | Machine becomes unusable or evidence quality drops. |

## Publication rule

Do not commit ad hoc `reports/` output as public evidence unless it is curated, validated,
and described with the metrics contract. For now, local reports are maintainer artifacts.
The public showcase should be generated from curated examples after issue
[#25](https://github.com/krivonosoff161/agentic-security-harness/issues/25) and issue
[#23](https://github.com/krivonosoff161/agentic-security-harness/issues/23) define the
showcase structure.

## Small-model swarm handoff track

Issue [#48](https://github.com/krivonosoff161/agentic-security-harness/issues/48)
tracks local-empirical evidence-quality work for small-model handoff/swarm probes. The
current shipped component is `ash evidence-quality`, a post-run analyzer for already
recorded `run-external` / `local-suite` artifacts. It makes no model calls and does not orchestrate a swarm.

This track is local-empirical only until a bounded profile, validation command, and
curated artifact path are defined. Raw responses and scratch reports stay local/private.
The track may report evidence quality, not model safety or live handoff integrity.

## Recovery table

| Symptom | Meaning | Next action |
|---|---|---|
| Timeout / `adapter_error` | Runtime was too slow or unavailable for the request. | Increase `--timeout`, close heavy processes, or use a smaller/faster model. |
| `inconclusive` | Model returned contradictory or incomplete JSON verdict. | Inspect raw response; rerun with more repeats; try a stronger JSON-following model. |
| No findings | No modeled finding was detected. | Do not call it safe; report pass/finding/inconclusive/error counts. |
| Machine becomes unusable | Model too heavy for the current profile. | Stop the run; return to `prometheus-qwen15b-lowctx:latest` or reduce scope. |

## Claim boundary

Allowed:

> Local Prometheus runs collect real model-in-the-loop evidence on synthetic benchmark
> scenarios. The first maintainer low-context profile is
> `prometheus-qwen15b-lowctx:latest` through Ollama, prompt-only, with validated artifacts
> and explicit inconclusive/error states.

Not allowed:

- "This local model proves the benchmark finds all real failures."
- "No findings means the model is safe."
- "A weak local model result generalizes to frontier models."
- "Local execution bypasses model license or acceptable-use duties."
