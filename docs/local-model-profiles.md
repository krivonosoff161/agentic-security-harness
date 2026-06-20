# Local model profiles

This page records hardware-safe local model profiles for the Prometheus role. Prometheus
is a weak local model used for real model-in-the-loop probes, not a judge and not a
leaderboard target.

## Observed maintainer hardware class

| Resource | Observed class | Profile impact |
|---|---|---|
| RAM | about 8 GB | Keep smoke runs small; avoid broad scenario sweeps. |
| GPU | GTX 1050 class, 3 GB VRAM | Use small quantized models; expect partial/offloaded inference only. |
| Runtime | Ollama 0.23.x | Use `--preset ollama` and the OpenAI-compatible `/v1` endpoint. |

## Recommended profiles

| Profile | Model | Scenario scope | Timeout | Repeats | Expected use |
|---|---|---|---|---|---|
| `prometheus-lowctx-smoke` | `prometheus-qwen15b-lowctx:latest` | one scenario, one variant | 60s | 1 | Maintainer low-context Ollama profile; recovered the first smoke from timeout-only evidence. |
| `prometheus-lowctx-reliability` | `prometheus-qwen15b-lowctx:latest` | same scenario/variant | 90s | 2-3 | Repeat the recovered low-context profile and classify stable pass/inconclusive/error states. |
| `prometheus-lowmem-smoke` | `qwen2.5:1.5b` | one scenario, one variant | 60s | 1 | First local evidence; should fit this machine class. |
| `prometheus-lowmem-reliability` | `qwen2.5:1.5b` | same scenario/variant | 90s | 2-3 | Check if inconclusive/timeout states repeat. |
| `prometheus-3b-experimental` | `qwen2.5:3b` or `llama3.2:3b` | one pattern or one variant only | 120s | 1 | Only if the machine remains responsive. |
| `fake-local-control` | `fake-model` via bundled fake server | one scenario | 30s | 1 | Verify the external artifact path without model variability. |

The `prometheus-lowctx-*` profiles assume the maintainer has created a local Ollama model
alias with lower context/output settings, for example:

```text
FROM qwen2.5:1.5b
PARAMETER num_ctx 2048
PARAMETER num_predict 128
PARAMETER temperature 0
```

```powershell
ollama create prometheus-qwen15b-lowctx -f Modelfile.prometheus-lowctx
```

The generic `prometheus-lowmem-*` profiles remain documented because they are easier for a
new user to reproduce after `ollama pull qwen2.5:1.5b`, but on the maintainer hardware the
low-context alias is the preferred recovery profile.

## Bounded suite command

These profiles are implemented as named, bounded configurations in
[`local_profiles.py`](../src/agentic_security_harness/local_profiles.py) and run through one
command. It is **dry-run by default** (no network, no files) and only calls a model on
explicit `--execute`:

```powershell
# list the bounded profiles
python -m agentic_security_harness.cli local-suite --list

# preview (dry-run): estimate requests, no network, no files written
python -m agentic_security_harness.cli local-suite --profile prometheus-lowctx-smoke

# real local run, then auto-validate and generate failure cards
python -m agentic_security_harness.cli local-suite --profile prometheus-lowctx-smoke --execute --showcase
```

The command resolves the profile's preset/model/scenario/repeats/timeout/request-cap,
enforces the request cap before any call, writes artifacts to a derived `reports/local-...`
path, validates them, and reports the weak-model classification
(`stable_pass`/`inconclusive`/`adapter_error`). It never executes tools.

## Manual equivalent

The suite above is equivalent to:

```powershell
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

python -m agentic_security_harness.cli validate reports/local-prometheus-lowctx-smoke-prometheus-qwen15b-lowctx-latest
```

## How to interpret weak local models

| Result | Interpretation | Next step |
|---|---|---|
| `stable_finding` | Stronger evidence for the modeled failure. | Create failure card and one deepening variation. |
| `stable_pass` | No modeled finding in this run. | Do not generalize; optionally test adjacent variation. |
| `inconclusive` | Model did not produce coherent evidence. | Inspect raw response; rerun with repeats or stronger model. |
| `adapter_error` | Runtime/profile problem. | Fix timeout/model/server before expanding scenario scope. |
| `flaky` | Behavior changes across repeats. | Increase repeats or narrow the scenario. |

## Stop conditions

Stop the local run series when:

- the machine becomes unusable;
- adapter errors repeat after a timeout increase;
- inconclusive results dominate at repeat count 3;
- raw responses show the model cannot follow the JSON contract;
- a larger model causes swapping or long stalls.

## What can be claimed

Allowed:

> This profile collected real local model-in-the-loop evidence under strict request caps.
> Results are classified as finding, pass, inconclusive, adapter_error, or flaky.

Not allowed:

- "The local model is safe."
- "The local model is unsafe in general."
- "This is a leaderboard."
- "Local execution removes model license or acceptable-use obligations."
