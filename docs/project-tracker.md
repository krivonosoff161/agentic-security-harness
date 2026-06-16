# Project tracker

This page explains how public project work is tracked. It is intentionally small:
GitHub Issues and milestones are the source of truth for work in progress; repository
docs describe the current shipped state.

## Current evidence milestone

Active public-development track:

| Milestone | Purpose |
|---|---|
| [v0.17 public evidence showcase and local model probes](https://github.com/krivonosoff161/agentic-security-harness/milestone/5) | Make benchmark evidence easy to inspect before reading code, then add bounded local real-model probes. |

The milestone is not a release claim. It is a work tracker for the next credibility
slice: public evidence pages, local Prometheus/Ollama probes, scenario timelines,
failure cards, and metrics contracts.

## Open work in this track

| Issue | Track | Exit focus |
|---|---|---|
| [#25 docs: public evidence showcase](https://github.com/krivonosoff161/agentic-security-harness/issues/25) | Showcase | A reviewer can see scenarios, latest example runs, failure cards, artifacts, and reproduce commands without reading source code. |
| [#19 feature: local Prometheus suite](https://github.com/krivonosoff161/agentic-security-harness/issues/19) | Local runtime | Real local model-in-loop smoke run through Ollama/OpenAI-compatible runtime, with strict caps and validated artifacts. |
| [#20 feature: scenario timeline](https://github.com/krivonosoff161/agentic-security-harness/issues/20) | Corpus / multi-turn | Multi-turn, delayed-trigger, context-overload, and handoff scenarios described as timelines with invariants and validators. |
| [#21 feature: trace replay and failure cards](https://github.com/krivonosoff161/agentic-security-harness/issues/21) | Reports | Human-readable failure cards generated from trace artifacts, not hand-written marketing summaries. |
| [#22 docs: metric contract](https://github.com/krivonosoff161/agentic-security-harness/issues/22) | Metrics | A stable vocabulary for GitHub traffic metrics, benchmark evidence metrics, runtime evidence, and project process metrics. |
| [#23 feature: showcase generator](https://github.com/krivonosoff161/agentic-security-harness/issues/23) | Reports / automation | Generate showcase markdown from JSON artifacts instead of manually copying results. |
| [#24 research: local model profiles](https://github.com/krivonosoff161/agentic-security-harness/issues/24) | Local runtime | Hardware-safe model/runtime profiles and recovery guidance for weak local models. |

Supporting docs:

- [metric-contract.md](metric-contract.md) defines how traffic, benchmark, runtime, and
  process metrics should be read.
- [inter-agent-handoff-integrity.md](inter-agent-handoff-integrity.md) defines the
  design-first track for provenance-preserving worker-to-senior agent handoffs. It is
  planned work, not shipped benchmark coverage.
- [local-prometheus-workflow.md](local-prometheus-workflow.md) defines the low-memory
  Ollama smoke workflow for real local model probes.
- [local-model-profiles.md](local-model-profiles.md) records hardware-safe local model
  profiles and stop conditions.
- [showcase/index.md](showcase/index.md) is the public evidence entry point.
- [scenario-investigation-workflow.md](scenario-investigation-workflow.md) keeps
  scenario design, weak spots, findings, and deepening variations separate.
- [scenario-timeline.md](scenario-timeline.md) defines the multi-turn timeline contract.
- `ash showcase --root reports --out docs/showcase/generated` generates a Markdown
  reviewer view from run artifacts.

## How to read labels

| Label family | Meaning |
|---|---|
| `type:*` | Work type: docs, feature, research, test, infra, security. |
| `area:*` | Project area: reports, corpus, local runtime, adapters, multi-agent, recovery path, standards mapping. |
| `priority:*` | Scheduling priority, not severity of a vulnerability. |
| `status:*` | Current implementation state: ready, needs design, experimental, blocked. |
| `showcase` | Work that directly improves public first-impression evidence. |

For LLM/code agents: do not infer capability from an open issue. Shipped capability is
documented in [current-state.md](current-state.md) and [capability-matrix.md](capability-matrix.md).

## Traffic metrics vs benchmark evidence

GitHub traffic graphs are useful, but they do not prove benchmark quality.

| Metric family | Examples | What it means | What it does not mean |
|---|---|---|---|
| GitHub traffic | clones, unique cloners, views, visitors | People or tools are looking at the repository. | The benchmark is correct, reproducible, or trusted. |
| Benchmark evidence | scenario count, run count, findings, inconclusive checks, validator coverage | What the harness actually measured and validated. | A target is secure in production. |
| Runtime evidence | model, runtime, local-only flag, raw responses, repeats, recovery path | How a real or fake runtime was exercised. | A leaderboard-grade model comparison. |
| Project process | open issues by milestone, labels, status, PRs, CI | Whether work is visible and reviewable. | That every planned feature is shipped. |

## Correct order of work

1. Keep the GitHub tracker honest: every large idea becomes an issue with labels,
   milestone, scope, non-goals, and exit gate.
2. For new methodology tracks such as inter-agent handoff integrity, write the design
   track and exit gates before adding code or corpus cases.
3. Build the evidence showcase from existing deterministic artifacts first.
4. Add local Prometheus/model-in-loop probes only after the showcase can explain how to
   read evidence and limitations.
5. Generate failure cards and metrics from artifacts. Do not hand-write conclusions that
   are stronger than the trace/scorecard data.
6. Only then expand scenario timelines and local model profiles.

## Local verification before claiming progress

For docs-only tracker updates:

```bash
python -m pytest tests/test_documentation_contract.py
python -m ruff check .
git diff --check
```

For evidence/showcase code:

```bash
python -m pytest
ash validate examples/
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

## Claim boundary

Allowed:

> The project publicly tracks the next evidence/showcase and local-runtime work through
> GitHub Issues and milestones, with exit gates tied to validated artifacts.

Not allowed:

- claiming local real-model probes are shipped before issue #19 is closed;
- treating GitHub clone/view spikes as benchmark validation;
- presenting weak local model runs as a universal model-safety conclusion;
- presenting manually written showcase text as evidence without trace/scorecard links.
