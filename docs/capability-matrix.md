# Capability / coverage matrix

What each target and mode does, so you can pick the right one and read its result
correctly. Built-in/local modes are deterministic and offline; the external path is the
only one that touches the network, and only with explicit `--execute`/`--live` opt-in.

For broader system shapes a target adapter may represent, see
[evaluation-topologies.md](evaluation-topologies.md). This page is the shipped mode matrix;
the topology page is the methodology map.

## Targets and modes

| Mode | Command | Network (default) | Uses a model/provider | Determinism | Corpus scope | Repeats | Scenario variants | Writes `run_index.json` | `ash validate` |
|---|---|---|---|---|---|---|---|---|---|
| First-user quickstart | `quickstart --out <dir>` | offline | no | deterministic | full (24), baseline vs protected | no | no | yes | runs automatically |
| `mock` | `run --target mock` | offline | no | deterministic | full (24) | no | no | yes | yes |
| `demo-agent` | `run --target demo-agent` | offline | no | deterministic | full (24) | no | no | yes | yes |
| `protected-demo-agent` | `run --target protected-demo-agent` | offline | no | deterministic | full (24) | no | no | yes | yes |
| `toy-local-function` | `run --target toy-local-function` | offline | no | deterministic | full (24) | no | no | yes | yes |
| `toy-rag` | `run --target toy-rag` | offline | no | deterministic | full (24) | no | no | yes | yes |
| `toy-tools` | `run --target toy-tools` | offline | no | deterministic | full (24) | no | no | yes | yes |
| `toy-multi-agent` | `run --target toy-multi-agent` | offline | no | deterministic | full (24) | no | no | yes | yes |
| Scenario matrix | `run-matrix --target <t> --scenario <s>` | offline | no | deterministic | subset (scenario) x variants | no | yes | yes | yes |
| External (OpenAI-compatible) | `run-external --base-url ... --model ... --execute` | **opt-in only** | yes (prompt-only) | stochastic possible | subset (scenario) x variants | yes | yes | yes | yes |
| Offline provider tool-envelope normalization | Python API | offline | no | deterministic | not a corpus run | no | four retained envelope families | privacy-minimized gateway audit | n/a |
| Native live provider adapter | - | - | - | - | - | - | - | - | **future** |
| Agent-host / tool-use adapter | - | - | - | - | - | - | - | - | **future** |
| Runtime Gateway synthetic contour | `gateway-serve --config <toml>` | local listener | no | deterministic built-ins | not a corpus run | no | fixed policy paths | privacy-minimized audit chain | n/a |

## What each is good for / does not cover

| Mode | Good for | Does not cover |
|---|---|---|
| First-user quickstart | Reproducing the `24 modeled findings -> 0` local comparison from an installed package, validating it, and rendering one complete evidence bundle. | A real model, production control, or independent safety certification. |
| `mock` | Fast smoke check that the pipeline and a full-FAIL baseline work. | Realistic agent behavior. |
| `demo-agent` | The vulnerable-by-design baseline (FAILs all 24). | A real agent. |
| `protected-demo-agent` | The controlled baseline (PASSes all 24); the before/after story via `compare`. | Proof a real control works in production. |
| `toy-local-function` | Trivial neutral adapter that PASSes everything; a template for new adapters. | Any real surface. |
| `toy-rag` | Showing the harness on a retrieval/memory/injection surface (partial coverage). | Tool/authority/budget/audit surfaces (PASS by construction). |
| `toy-tools` | Showing the harness on a tool/authority surface (partial coverage). | Data/memory surfaces (PASS by construction). |
| `toy-multi-agent` | Showing coordinator/worker handoff traces for label stripping and capability delegation drift (partial coverage). | Live agent hosts, real tools, provider handoffs, emergent multi-agent behavior. |
| Scenario matrix | Stability across variants; stable vs variant-sensitive failures; coverage heatmap. | Stochastic behavior (variants are deterministic replay metadata). |
| External (OpenAI-compatible) | Asking a model to judge synthetic scenarios; repeats + stochastic status. | Tool execution, agent-host behavior, or a real deployment. |
| Agent Host V1 record/replay | Canonical offline inspection of authority-free retained host observations. | Does not execute a host/tool or authenticate the producer. |
| Agent Host Evaluator V1 | Deterministically maps a closed terminal vocabulary over a complete causal recording to `pass`, `finding`, `inconclusive`, or `adapter_error` for all 24 corpus patterns. | Evaluates only an unattested recording contract; does not prove the action occurred, certify security, or enforce policy. |
| Agent Host owned-workflow V1 | Explicit digest-only Python instrumentation plus a built-in 48-case no-network quickstart and atomically validated evidence bundle. | The CLI does not load or execute an arbitrary host; native provider transport and producer authentication are not shipped. |
| Native / live agent-host collectors | (future) driving real provider SDKs or tool-executing agents. | Not shipped - do not assume it exists. |
| Runtime Gateway synthetic contour | Exercising pre-dispatch allow/deny/approval decisions, OpenAI-compatible integration shape, a bounded stateless MCP 2026-07-28 subset, strict HTTP/header parsing, safe audit, dashboard, and container operation. | No live provider, credential broker, arbitrary tool, full MCP extension/SDK conformance, authenticated approval, production IAM, deployment, certification, or security guarantee. |
| Offline provider tool-envelope normalization | Converting retained OpenAI Responses, Anthropic Messages, Google Interactions, and MCP tool calls into the same closed gateway policy without SDK or credential access. | No provider transport, streaming, producer authentication, arbitrary tool execution, or full provider/MCP conformance. |

## Notes

- "Corpus scope" full = all 24 patterns in one pass; subset = the patterns in the chosen
  scenario (see `ash scenarios --verbose`).
- "Repeats" applies only to the external path (`--repeats`); local/matrix runs are
  deterministic so a single pass is definitive.
- Every mode writes a `run_index.json` manifest, so `ash list-runs` and `ash report`
  work uniformly across them.
- Result words (PASS / FINDING / INCONCLUSIVE / FLAKY / ADAPTER_ERROR) and what
  `ash validate` does and does not prove are defined in
  [benchmark-semantics.md](benchmark-semantics.md).
