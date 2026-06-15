# Capability / coverage matrix

What each target and mode does, so you can pick the right one and read its result
correctly. Built-in/local modes are deterministic and offline; the external path is the
only one that touches the network, and only on explicit opt-in.

For broader system shapes a target adapter may represent, see
[evaluation-topologies.md](evaluation-topologies.md). This page is the shipped mode matrix;
the topology page is the methodology map.

## Targets and modes

| Mode | Command | Network (default) | Uses a model/provider | Determinism | Corpus scope | Repeats | Scenario variants | Writes `run_index.json` | `ash validate` |
|---|---|---|---|---|---|---|---|---|---|
| `mock` | `run --target mock` | offline | no | deterministic | full (22) | no | no | yes | yes |
| `demo-agent` | `run --target demo-agent` | offline | no | deterministic | full (22) | no | no | yes | yes |
| `protected-demo-agent` | `run --target protected-demo-agent` | offline | no | deterministic | full (22) | no | no | yes | yes |
| `toy-local-function` | `run --target toy-local-function` | offline | no | deterministic | full (22) | no | no | yes | yes |
| `toy-rag` | `run --target toy-rag` | offline | no | deterministic | full (22) | no | no | yes | yes |
| `toy-tools` | `run --target toy-tools` | offline | no | deterministic | full (22) | no | no | yes | yes |
| Scenario matrix | `run-matrix --target <t> --scenario <s>` | offline | no | deterministic | subset (scenario) x variants | no | yes | yes | yes |
| External (OpenAI-compatible) | `run-external --base-url ... --model ...` | **opt-in only** | yes (prompt-only) | stochastic possible | subset (scenario) x variants | yes | yes | yes | yes |
| Native provider adapter | - | - | - | - | - | - | - | - | **future** |
| Agent-host / tool-use adapter | - | - | - | - | - | - | - | - | **future** |

## What each is good for / does not cover

| Mode | Good for | Does not cover |
|---|---|---|
| `mock` | Fast smoke check that the pipeline and a full-FAIL baseline work. | Realistic agent behavior. |
| `demo-agent` | The vulnerable-by-design baseline (FAILs all 22). | A real agent. |
| `protected-demo-agent` | The controlled baseline (PASSes all 22); the before/after story via `compare`. | Proof a real control works in production. |
| `toy-local-function` | Trivial neutral adapter that PASSes everything; a template for new adapters. | Any real surface. |
| `toy-rag` | Showing the harness on a retrieval/memory/injection surface (partial coverage). | Tool/authority/budget/audit surfaces (PASS by construction). |
| `toy-tools` | Showing the harness on a tool/authority surface (partial coverage). | Data/memory surfaces (PASS by construction). |
| Scenario matrix | Stability across variants; stable vs variant-sensitive failures; coverage heatmap. | Stochastic behavior (variants are deterministic replay metadata). |
| External (OpenAI-compatible) | Asking a model to judge synthetic scenarios; repeats + stochastic status. | Tool execution, agent-host behavior, or a real deployment. |
| Native / agent-host adapters | (future) driving real provider SDKs or tool-executing agents. | Not shipped - do not assume it exists. |

## Notes

- "Corpus scope" full = all 22 patterns in one pass; subset = the patterns in the chosen
  scenario (see `ash scenarios --verbose`).
- "Repeats" applies only to the external path (`--repeats`); local/matrix runs are
  deterministic so a single pass is definitive.
- Every mode writes a `run_index.json` manifest, so `ash list-runs` and `ash report`
  work uniformly across them.
- Result words (PASS / FINDING / INCONCLUSIVE / FLAKY / ADAPTER_ERROR) and what
  `ash validate` does and does not prove are defined in
  [benchmark-semantics.md](benchmark-semantics.md).
