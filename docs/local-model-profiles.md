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
| `prometheus-lowmem-smoke` | `qwen2.5:1.5b` | one scenario, one variant | 60s | 1 | First local evidence; should fit this machine class. |
| `prometheus-lowmem-reliability` | `qwen2.5:1.5b` | same scenario/variant | 90s | 2-3 | Check if inconclusive/timeout states repeat. |
| `prometheus-3b-experimental` | `qwen2.5:3b` or `llama3.2:3b` | one pattern or one variant only | 120s | 1 | Only if the machine remains responsive. |
| `fake-local-control` | `fake-model` via bundled fake server | one scenario | 30s | 1 | Verify the external artifact path without model variability. |

## Current recommendation

Start with:

```powershell
python -m agentic_security_harness.cli run-external `
  --preset ollama `
  --model qwen2.5:1.5b `
  --scenario data-boundary `
  --max-variants 1 `
  --repeats 1 `
  --max-requests 10 `
  --timeout 60 `
  --raw-response-limit 0 `
  --out reports/local-prometheus-qwen15b-smoke
```

Then:

```powershell
python -m agentic_security_harness.cli validate reports/local-prometheus-qwen15b-smoke
python -m agentic_security_harness.cli showcase `
  --root reports/local-prometheus-qwen15b-smoke `
  --out reports/local-prometheus-qwen15b-showcase
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
