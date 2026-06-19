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
| `qwen2.5:1.5b` | Primary Prometheus smoke model | Already fits the low-memory profile and is small enough for repeated local tests. |
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
- benchmark-grade model leaderboard;
- a claim that weak-model behavior generalizes to frontier models.

## Bounded suite command

The fastest safe path is the named, bounded suite (dry-run by default; only calls a model
on `--execute`):

```powershell
python -m agentic_security_harness.cli local-suite --list
python -m agentic_security_harness.cli local-suite --profile prometheus-lowmem-smoke            # dry-run
python -m agentic_security_harness.cli local-suite --profile prometheus-lowmem-smoke --execute  # real run + validate
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
  --model qwen2.5:1.5b `
  --scenario data-boundary

# 2) preview the exact request count; no files written
python -m agentic_security_harness.cli run-external `
  --preset ollama `
  --model qwen2.5:1.5b `
  --scenario data-boundary `
  --max-variants 1 `
  --repeats 1 `
  --max-requests 10 `
  --timeout 60 `
  --dry-run

# 3) real local run; localhost only, prompt-only, no tools
python -m agentic_security_harness.cli run-external `
  --preset ollama `
  --model qwen2.5:1.5b `
  --scenario data-boundary `
  --max-variants 1 `
  --repeats 1 `
  --max-requests 10 `
  --timeout 60 `
  --raw-response-limit 0 `
  --out reports/local-prometheus-lowmem-smoke-qwen2.5-1.5b

# 4) validate artifacts
python -m agentic_security_harness.cli validate reports/local-prometheus-lowmem-smoke-qwen2.5-1.5b
```

Expected request count for this smoke flow: 4.

## How to read first results

On this hardware class, local `qwen2.5:1.5b` / `prometheus-qwen15b-lowctx:latest`
runs produce valid artifacts but weak evidence. A current data-boundary reliability
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

This is exactly why local real-model probes are useful: even before finding a security
boundary failure, they reveal runtime reliability and evidence-quality limits that a
synthetic deterministic target cannot show.

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

## Recovery table

| Symptom | Meaning | Next action |
|---|---|---|
| Timeout / `adapter_error` | Runtime was too slow or unavailable for the request. | Increase `--timeout`, close heavy processes, or use a smaller/faster model. |
| `inconclusive` | Model returned contradictory or incomplete JSON verdict. | Inspect raw response; rerun with more repeats; try a stronger JSON-following model. |
| No findings | No modeled finding was detected. | Do not call it safe; report pass/finding/inconclusive/error counts. |
| Machine becomes unusable | Model too heavy for the current profile. | Stop the run; return to `qwen2.5:1.5b` or reduce scope. |

## Claim boundary

Allowed:

> Local Prometheus runs collect real model-in-the-loop evidence on synthetic benchmark
> scenarios. The first low-memory profile is `qwen2.5:1.5b` through Ollama, prompt-only,
> with validated artifacts and explicit inconclusive/error states.

Not allowed:

- "This local model proves the benchmark finds all real failures."
- "No findings means the model is safe."
- "A weak local model result generalizes to frontier models."
- "Local execution bypasses model license or acceptable-use duties."
