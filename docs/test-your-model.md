# Test your own model/runtime

> **Agentic Security Harness** — experimental external adapter path.
> Evaluate an authorized OpenAI-compatible endpoint with safe synthetic prompts.

## What this mode is

- **Experimental.** Not a benchmark-grade vendor comparison.
- **Prompt-based evaluation only.** The model receives a synthetic scenario and responds
  with a structured JSON decision. No tools are executed.
- **Safe.** Prompts use placeholders only. No real secrets, no harmful payloads, no
  network calls unless you explicitly invoke `ash run-external`.
- **Explicit.** Network calls happen only when you run the command without `--dry-run`.

## Quick dry-run (no money, no network)

```bash
ash run-external --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model your-model \
  --scenario data-boundary \
  --dry-run
```

This shows what would happen without making any network calls:
- how many requests would be sent
- which patterns and variants would be tested
- the configuration that would be used

## Check configuration before a real run

Use `external-check` before spending money or calling a local runtime:

```bash
ash external-check --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model your-model \
  --scenario data-boundary \
  --repeats 3 \
  --max-variants 1
```

Add `--live` only when you want one real test request:

```bash
ash external-check --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model your-model \
  --scenario data-boundary \
  --live
```

## Local fake server demo (free, no API key)

Start a fake local server in one terminal:

```bash
python examples/fake_openai_server.py
```

Then run the external adapter against it:

```bash
ash run-external --adapter openai-compatible \
  --base-url http://127.0.0.1:8766/v1 \
  --model fake-model \
  --scenario data-boundary \
  --out reports/external-demo
```

Inspect the generated reports:

```bash
cat reports/external-demo/external_report.md
cat reports/external-demo/external_summary.json
```

PowerShell equivalent:

```powershell
python examples/fake_openai_server.py
```

Then, in a second PowerShell terminal:

```powershell
ash run-external --adapter openai-compatible `
  --base-url http://127.0.0.1:8766/v1 `
  --model fake-model `
  --scenario data-boundary `
  --out reports/external-demo

Get-Content reports/external-demo/external_report.md
```

Do not use the trailing bash `&` form in PowerShell. Open a second terminal or use
`Start-Process` if you want a background process.

## Test an OpenAI-compatible endpoint

```bash
# Set your API key (never commit this)
export ASH_EXTERNAL_API_KEY=your_key_here

ash run-external --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model deepseek-chat \
  --scenario data-boundary \
  --repeats 3 \
  --api-key-env ASH_EXTERNAL_API_KEY \
  --out reports/external-deepseek
```

PowerShell:

```powershell
$env:ASH_EXTERNAL_API_KEY = "your_key_here"

ash run-external --adapter openai-compatible `
  --base-url http://localhost:8000/v1 `
  --model deepseek-chat `
  --scenario data-boundary `
  --repeats 3 `
  --api-key-env ASH_EXTERNAL_API_KEY `
  --out reports/external-deepseek
```

## Test a DeepSeek-compatible endpoint

```bash
export ASH_EXTERNAL_API_KEY=your_deepseek_key

ash run-external --adapter openai-compatible \
  --base-url https://api.deepseek.com/v1 \
  --model deepseek-chat \
  --scenario data-boundary \
  --repeats 3 \
  --api-key-env ASH_EXTERNAL_API_KEY \
  --out reports/external-deepseek
```

## Test an Alibaba/Qwen-compatible endpoint

```bash
export ASH_EXTERNAL_API_KEY=your_dashscope_key

ash run-external --adapter openai-compatible \
  --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
  --model qwen-plus \
  --scenario data-boundary \
  --repeats 3 \
  --api-key-env ASH_EXTERNAL_API_KEY \
  --out reports/external-qwen
```

## Test a local vLLM server

```bash
# Start vLLM separately, then:
ash run-external --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model your-model-name \
  --scenario data-boundary \
  --out reports/external-vllm
```

No `--api-key-env` needed for local servers that don't require auth.

## Request count and cost warning

The number of requests is:

```text
requests = patterns_in_scenario x variants x repeats
```

For example, `data-boundary` has 4 patterns. With 1 variant and 3 repeats:
4 x 1 x 3 = **12 requests**.

The `--max-variants` flag controls how many variants are tested. Default is 1.

Use `--dry-run` first to see the estimated request count before spending money.

### Safety cap

`run-external` refuses to start if the estimated request count exceeds
`--max-requests` (default **50**). This is a cost guardrail, not a quality limit.
If you intentionally want a larger run, raise it explicitly:

```bash
ash run-external --adapter openai-compatible \
  --base-url http://localhost:8000/v1 \
  --model your-model \
  --scenario all --max-variants 4 \
  --max-requests 100 \
  --dry-run
```

`external-check` shows whether your current scope is within the cap before you run.

## How to read artifacts

After a run, you get:

| File | What it shows |
|---|---|
| `run_config.json` | Configuration used: adapter, model, redacted base_url, scenario, repeats, `request_count`. API key env **name** only, never the value. |
| `external_results.json` | Per-evaluation result: decision, reason, would_preserve_boundary, structured `error`. |
| `external_summary.json` | Aggregated counts: pass/finding/inconclusive/flaky per pattern, plus `findings_by_pattern` and `findings_by_control_family`. |
| `external_report.md` | Human-readable report: configuration, results, control-family table, and **control recommendations** (quick / engineering / architecture fix, verification, residual risk) for any finding. |

Start with `external_report.md` for the overview and recommendations, then
`external_summary.json` for machine-readable counts.

Findings are aggregated to control families using the harness's canonical
pattern→family map (deterministic), not the model's self-reported
`control_family` field. Recommendations reduce a *class* of benchmark findings;
they do not by themselves make a system safe.

## Troubleshooting

**"API key env X is not set"**

```bash
export X=your_key_here
# or omit --api-key-env for local servers that don't need auth
```

PowerShell:

```powershell
$env:X = "your_key_here"
```

**"HTTP 401" or "HTTP 403"**

Your API key is invalid or the endpoint requires a different auth method.

**"Network error connecting to ..."**

The base URL is wrong or the server is not running. Check:
- Is the server started?
- Is the port correct?
- Is there a firewall blocking localhost?

**"Invalid JSON response"**

The model returned non-JSON text. This is recorded as `inconclusive` in the report.
Try a different model or lower temperature.

**"repeats must be between 1 and 10"**

The `--repeats` flag accepts values from 1 to 10.

## What to include in a bug report

When reporting an issue, include:

1. The command you ran (without secrets)
2. `run_config.json` (already redacted)
3. `external_summary.json`
4. The error message you saw

**Never include:** API keys, full base URLs with credentials, raw prompts with secrets.
