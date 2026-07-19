# Connect your model or runtime

> **Agentic Security Harness** - connector recipes for the experimental external
> evaluation path. Everything here uses **synthetic, sanitized prompts** against an
> **authorized** OpenAI-compatible endpoint. No real secrets, no harmful payloads,
> no tool execution.

## 1. Overview

The harness ships **one** external adapter: **`openai-compatible`**. It speaks the
OpenAI Chat Completions wire format (`POST {base_url}/chat/completions`). Anything that
exposes that format - a cloud API, a local server, or a gateway/proxy in front of
another provider - can be evaluated through the same path.

This is **prompt-based evaluation only**: the model receives a synthetic benchmark
scenario and returns a structured JSON verdict. **No tools are executed**, no agent host
is driven, and no streaming is used. See [What is not supported yet](#13-what-is-not-supported-yet).

Every model-evidence path applies the same fail-closed response contract. The top-level
`model` value must exactly match the requested model id, and
`choices[0].message.content` must be a nonblank string. Missing or mismatched identity,
missing content, and whitespace-only content are `adapter_error`; they are never hashed
or counted as model behavior. This is an application integrity check, not cryptographic
runtime authentication.

### Presets (optional shortcut)

`ash external-presets` lists connection presets that fill a default `base_url` and suggest
a credential env-var **name**. A preset is only a convenience - it does not add a provider
SDK, change the transport, or hide a network call.

```bash
ash external-presets
ash external-check --preset ollama --model llama3.1 --scenario data-boundary
ash run-external  --preset fake-local --model fake-model --scenario data-boundary --dry-run
```

Presets: `fake-local`, `vllm`, `ollama`, `lm-studio`, `deepseek`,
`alibaba-qwen-compatible`, `generic-openai-compatible`. An explicit `--base-url` always
overrides the preset; `generic-openai-compatible` requires you to pass your own
`--base-url`. Vendor URLs are starting points - confirm the current value in the
provider's docs.

Every new `run-external` artifact records a `runtime` block in `run_config.json` with:

- `runtime_name` / `runtime_family`;
- `network_mode` (`local-only` for Ollama, LM Studio, vLLM, localhost, and the fake server;
  `authorized-external` for cloud or remote OpenAI-compatible endpoints);
- `authorization_mode` (`local_runtime`, `demo_synthetic`, or `authorized_external`);
- `model_id` and a model license / policy note;
- `prompt_only=true` and `tool_execution=false`;
- recovery guidance for server-not-running, model-not-found, invalid JSON, timeout, and
  inconclusive output.

### Stochastic models and repeats

A single response is not a verdict. Stochastic models can answer differently each call.

- Use `--temperature 0.0` (the default) for the most repeatable behaviour.
- Use `--repeats N` (2-10) for stochastic models. Each `(pattern, variant)` group is
  then summarised with an explicit **status**:
  `stable_pass`, `stable_finding`, `flaky` (mixed outcomes across repeats),
  `inconclusive` (no usable JSON verdict), or `adapter_error` (the call failed).
- Treat `flaky` and `inconclusive` as "needs more data", not as pass or fail.
- Do **not** compare two models from a single run each - re-run with the same scenario,
  variants, and repeats, and compare the per-status counts.

## 2. Safety and cost model

The number of network requests a run makes is exactly:

```text
request_count = patterns_in_scenario x variants x repeats
```

- `run-external` **refuses to start** if `request_count` exceeds `--max-requests`
  (default **50**). Raise it explicitly for larger runs.
- `external-check` and `run-external --dry-run` make **no benchmark network calls**.
- `external-check --live` makes **exactly one** request to verify connectivity.
- HTTP redirects are refused. A configured endpoint cannot silently redirect a request,
  prompt, or bearer credential to another URL.
- Ambient proxy discovery is disabled. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and OS proxy
  settings do not silently become an additional request route; configure an explicitly
  authorized gateway as the final `base_url` instead.
- The API key is read from an **environment variable by name**. The key **value** is
  never logged, never printed, and never written to any artifact. `run_config.json`
  records only whether a credential variable was configured, never its name or value.
- `base_url` is redacted before it is stored, so embedded credentials never land in a
  report.
- Local runtime metadata is stored in `run_config.json`, `external_report.md`, and
  `run_index.json`; the full endpoint is still redacted and credential values are never
  stored.

Scenario sizes (use these to estimate cost):

| Scenario | Patterns | Default variants |
|---|---|---|
| `instruction-integrity` | 2 | 3 |
| `data-boundary` | 6 | 3 |
| `memory-governance` | 5 | 3 |
| `tool-selection` | 3 | 3 |
| `authority-control` | 2 | 2 |
| `approval-audit` | 3 | 3 |
| `budget-control` | 2 | 2 |
| `perception-boundary` | 1 | 2 |
| `all` | 24 | 4 |

`--max-variants 1` (the external default) keeps runs small. Run `ash scenarios --verbose`
for the exact variant ids.

## 3. Universal flow

Every recipe below follows the same five steps:

```text
external-check         # validate config, see request estimate + cost cap (no network)
run-external --dry-run # preview exact request count (no network, no files)
run-external --execute # small live run against the endpoint
ash validate <out>     # confirm the artifacts are well-formed
open external_report.md# read results + control recommendations
```

> The recipes below omit `--adapter openai-compatible` because it is the **default**.
> You can add it explicitly (as the README examples do); both forms are equivalent.

## 4. Connection matrix

| Stack | Endpoint type | Base URL (example) | Auth | Model (example) | Status |
|---|---|---|---|---|---|
| Local fake server (bundled) | OpenAI-compatible | `http://127.0.0.1:8766/v1` | none | `fake-model` | supported |
| vLLM | OpenAI-compatible (native) | `http://localhost:8000/v1` | none / token | served model id | supported via OpenAI-compatible |
| DeepSeek API | OpenAI-compatible (native) | `https://api.deepseek.com/v1` | API key | `deepseek-chat` | supported via OpenAI-compatible |
| Alibaba Model Studio (Qwen) | OpenAI compatible-mode | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | API key | `qwen-plus` | supported via OpenAI-compatible |
| Generic OpenAI-compatible gateway | OpenAI-compatible | `https://YOUR-ENDPOINT/v1` | depends | provider model id | supported via OpenAI-compatible |
| Ollama | OpenAI-compatible (native) | `http://localhost:11434/v1` | none | `llama3.1` | supported via OpenAI-compatible |
| LM Studio | OpenAI-compatible (native) | `http://localhost:1234/v1` | none | loaded model id | supported via OpenAI-compatible |
| Native provider SDKs / tool execution / streaming / agent hosts | - | - | - | - | future |

> Provider URLs change over time. Where a row shows a vendor host, treat it as a
> starting point and confirm against the provider's current API docs. For anything
> uncertain, use the generic template `https://YOUR-ENDPOINT/v1`.

The columns below (env command, preflight, dry-run, live, artifacts) are identical in
shape for every row; the recipes spell them out.

## 5. Windows PowerShell quickstart

```powershell
# (only for authenticated endpoints) set the key by ENV VAR NAME
$env:ASH_EXTERNAL_API_KEY = "REDACTED_VALUE"

# 1) preflight (no network)
ash external-check --base-url https://YOUR-ENDPOINT/v1 --model your-model `
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY

# 2) dry-run (no network, no files)
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model `
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --dry-run

# 3) small live run
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model `
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY `
  --execute `
  --out .internal/external-run

# 4) validate + read
ash validate .internal/external-run
Get-Content .internal/external-run/external_report.md
```

PowerShell notes:
- Use the backtick `` ` `` for line continuation, **not** the bash `\`.
- Do **not** use the trailing `&` background form. Start background processes in a
  second terminal or with `Start-Process`.
- Set env vars with `$env:NAME = "value"`, read them as `$env:NAME`.

## 6. Linux/macOS bash quickstart

```bash
# (only for authenticated endpoints) set the key by ENV VAR NAME
export ASH_EXTERNAL_API_KEY=REDACTED_VALUE

# 1) preflight (no network)
ash external-check --base-url https://YOUR-ENDPOINT/v1 --model your-model \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY

# 2) dry-run (no network, no files)
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --dry-run

# 3) small live run
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY \
  --execute \
  --out .internal/external-run

# 4) validate + read
ash validate .internal/external-run
cat .internal/external-run/external_report.md
```

## 7. Recipe: local fake server (free, no key)

The bundled fake server returns deterministic responses, so you can exercise the whole
flow with zero cost and no network egress.

```bash
# terminal 1 - start the server (Ctrl+C to stop)
python examples/fake_openai_server.py
```

```bash
# terminal 2 - run against it
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external  --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --dry-run
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario perception-boundary --execute --out .internal/external-demo
ash validate .internal/external-demo
```

On Windows, start the server in a separate PowerShell window (no trailing `&`).

## 8. Recipe: vLLM (local, OpenAI-compatible)

vLLM serves a native OpenAI-compatible API. Start it separately, then point the harness
at it. No key is needed unless you launched vLLM with `--api-key`.

```bash
# vLLM is started separately, e.g.:
#   python -m vllm.entrypoints.openai.api_server --model <your-model>
ash external-check --base-url http://localhost:8000/v1 --model <served-model-id> --scenario data-boundary
ash run-external  --base-url http://localhost:8000/v1 --model <served-model-id> --scenario data-boundary --dry-run
ash run-external --base-url http://localhost:8000/v1 --model <served-model-id> --scenario data-boundary --execute --out .internal/external-vllm
ash validate .internal/external-vllm
```

If you started vLLM with an API key, set `export ASH_EXTERNAL_API_KEY=...` and add
`--credential-env ASH_EXTERNAL_API_KEY`. Use the exact model id vLLM reports (it is the
`--model` you launched it with).

## 9. Recipe: DeepSeek API

DeepSeek exposes an OpenAI-compatible API. Confirm the current base URL and model ids in
the DeepSeek API docs.

```bash
export ASH_EXTERNAL_API_KEY=REDACTED_VALUE
ash external-check --base-url https://api.deepseek.com/v1 --model deepseek-chat \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY
ash run-external  --base-url https://api.deepseek.com/v1 --model deepseek-chat \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --dry-run
ash run-external --base-url https://api.deepseek.com/v1 --model deepseek-chat \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --execute --out .internal/external-deepseek
ash validate .internal/external-deepseek
```

## 10. Recipe: Alibaba Cloud Model Studio (Qwen, compatible-mode)

Model Studio offers an OpenAI **compatible-mode** endpoint. The host differs by region
(international vs. mainland China) and can change - confirm yours in the Model Studio
docs. International example:

```bash
export ASH_EXTERNAL_API_KEY=REDACTED_VALUE
ash external-check \
  --base-url https://dashscope-intl.aliyuncs.com/compatible-mode/v1 \
  --model qwen-plus --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY
ash run-external \
  --base-url https://dashscope-intl.aliyuncs.com/compatible-mode/v1 \
  --model qwen-plus --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --dry-run
ash run-external \
  --base-url https://dashscope-intl.aliyuncs.com/compatible-mode/v1 \
  --model qwen-plus --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY \
  --execute \
  --out .internal/external-qwen
ash validate .internal/external-qwen
```

Mainland-China host (confirm in the docs):
`https://dashscope.aliyuncs.com/compatible-mode/v1`.

## 11. Recipe: generic OpenAI-compatible gateway

Any gateway/proxy that exposes `/chat/completions` works. Substitute your endpoint and
auth.

```bash
export ASH_EXTERNAL_API_KEY=REDACTED_VALUE   # omit if the gateway needs no auth
ash external-check --base-url https://YOUR-ENDPOINT/v1 --model your-model-id \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY
ash run-external  --base-url https://YOUR-ENDPOINT/v1 --model your-model-id \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --dry-run
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model-id \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY --execute --out .internal/external-gw
ash validate .internal/external-gw
```

The harness appends `/chat/completions` if your `--base-url` does not already end with
it, so both `https://host/v1` and `https://host/v1/chat/completions` work.

## 12. Recipe: Ollama / LM Studio / local desktop runtimes

Both **Ollama** and **LM Studio** expose a native OpenAI-compatible server, so they use
the same path with **no API key**.

For the low-memory maintainer smoke profile, start with
[local-prometheus-workflow.md](local-prometheus-workflow.md). It uses the
`prometheus-qwen15b-lowctx:latest` Ollama profile with strict request caps and explains
how to read inconclusive/error results.

Treat local runtime evaluation as a **local authorized lab**. Running a model on your own
machine removes cloud-provider runtime dependency, but it does not remove model-license
terms, acceptable-use policies, or the requirement to test only synthetic, owned, or
authorized targets. See [authorized testing paths](authorized-testing-paths.md).

For local presets whose effective URL is loopback, `run_config.json` records
`network_mode=local-only`, `authorization_mode=local_runtime`, `prompt_only=true`, and
`tool_execution=false`. Network classification follows the effective URL, not the preset
label: overriding a local preset with a non-loopback URL is recorded as
`authorized-external`, while a remote preset pointed at loopback is recorded as a generic
local runtime. If the server is down, the model is not loaded, or the model returns
non-JSON / contradictory output, the result is `adapter_error` or `inconclusive` with a
recovery hint; it is not a pass.

Ollama (default port `11434`, OpenAI-compatible endpoint under `/v1`):

```bash
# Ollama running locally, model already pulled (e.g. `ollama pull llama3.1`)
ash external-check --base-url http://localhost:11434/v1 --model llama3.1 --scenario data-boundary
ash run-external  --base-url http://localhost:11434/v1 --model llama3.1 --scenario data-boundary --dry-run
ash run-external --base-url http://localhost:11434/v1 --model llama3.1 --scenario data-boundary --execute --out .internal/external-ollama
ash validate .internal/external-ollama
```

LM Studio (start its local server; default port `1234`):

```bash
ash external-check --base-url http://localhost:1234/v1 --model <loaded-model-id> --scenario data-boundary
ash run-external --base-url http://localhost:1234/v1 --model <loaded-model-id> --scenario data-boundary --execute --out .internal/external-lmstudio
ash validate .internal/external-lmstudio
```

Small local models often return prose instead of strict JSON. The harness records those
as `inconclusive` (not `pass`/`finding`). Lower `--temperature 0.0` and prefer a model
that follows JSON instructions if you see many inconclusive results.

Recommended artifact note for local runs: review the generated `runtime` block before
publishing results, and keep a private note of the exact model license/policy you checked
if the model card or local registry metadata is not public.

## 13. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Credential environment variable 'X' is not set` | env var not exported in this shell | set `X` in the current shell; or omit `--credential-env` for keyless local servers |
| `Network error connecting to ...` / connection refused | server not running, wrong port/host | start the server; check the port; confirm `http`/`https` |
| `HTTP 401` / `HTTP 403` | wrong/missing key, or wrong auth style | verify the key and that the endpoint expects `Authorization: Bearer` |
| `HTTP 404` | wrong base URL path | most endpoints want `.../v1`; the harness adds `/chat/completions` |
| `HTTP 301` / `HTTP 302` / other redirect error | endpoint or gateway redirects to another URL | configure the final authorized OpenAI-compatible base URL directly; redirects are intentionally refused |
| `Invalid JSON response from ...` | endpoint returned non-JSON (HTML error page, proxy notice) | check the URL/gateway; try `external-check --live` to see the raw failure |
| `response model identity mismatch` | endpoint omitted or rewrote the requested model id | configure the endpoint to return the exact requested id; do not alias silently in the gateway |
| `blank assistant content` | response JSON had no usable assistant text | check the endpoint schema and ensure a nonblank `choices[0].message.content` is returned |
| many `inconclusive` results | model returned prose, not the JSON verdict schema | set `--temperature 0.0`; use a stronger instruction-following model |
| `estimated N requests exceeds the safety cap` | scope too large for the cap | reduce `--max-variants`/`--repeats`/scenario, or raise `--max-requests` |
| `repeats must be between 1 and 10` | `--repeats` out of range | choose 1-10 |
| `unknown variant '...'` | bad `--variant` id | run `ash run-matrix --scenario <s> --list-variants` or `ash scenarios --verbose` |

A connectivity failure during a real run is recorded as a **structured error** per
pattern in `external_results.json` (and counted in `error_patterns`), not a crash.

## 14. What is not supported yet

These are **future** tracks, intentionally not implemented:

- Native provider SDK adapters (Anthropic, OpenAI Responses, Google, etc.).
- **Tool execution** / real agent-host integration (the external path evaluates model
  decisions, it does not drive an agent that calls tools).
- Streaming responses.
- Multi-turn agent conversations.
- Non-OpenAI wire formats without a compatible-mode gateway in front.

Do not interpret a clean external run as proof that a *deployed agent* is safe - it
evaluates model decision boundaries on synthetic prompts only. See
[docs/threat-model.md](threat-model.md).

## 15. How to add a new adapter later

The benchmark's stable unit is `pattern -> adapter -> trace -> scorecard -> validation`, so
new runtimes plug in without changing the corpus. The contract and the metadata models
for future adapters are described in
[docs/adapter-contract.md](adapter-contract.md). A new adapter must:

- accept a sanitized `DefensivePattern` and return observed behavior in the common trace
  model (or, for prompt-only adapters, a structured verdict);
- emit reproducibility metadata (adapter name/version, model, settings);
- never log or store secret **values**;
- default to no network and require explicit, authorized opt-in.

## See also

- [docs/test-your-model.md](test-your-model.md) - the external path in depth, artifact
  reference, and full troubleshooting.
- [docs/bring-your-own-target.md](bring-your-own-target.md) - local/synthetic target
  adapters.
- [docs/reporting-flow.md](reporting-flow.md) - what each artifact contains.
