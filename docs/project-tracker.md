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
slice: local Prometheus/Ollama probes, scenario timelines, failure cards, and the
design-led inter-agent handoff integrity track.

## Open work in this track

| Issue | Track | Current focus |
|---|---|---|
| [#61 research: add bounded local swarm runner](https://github.com/krivonosoff161/agentic-security-harness/issues/61) | Local swarm / runtime | In PR #62; deterministic local-swarm runner and claim boundary are implemented, pending repository review gate. |
| [#63 research: expand bounded local swarm evidence suite](https://github.com/krivonosoff161/agentic-security-harness/issues/63) | Local swarm / evidence | In PR #62; ten-scenario deterministic suite and committed example are implemented, pending repository review gate. |
| [#64 research: add local-swarm evidence-quality calculations](https://github.com/krivonosoff161/agentic-security-harness/issues/64) | Local swarm / evidence quality | Extend `ash evidence-quality` to calculate local-swarm contract coverage, transcript hash coverage, and adapter error rates from recorded artifacts. |

## Open maintenance work

None currently tracked.

## Recently completed in this track

| Issue | Track | Delivered focus |
|---|---|---|
| [#19 feature: local Prometheus suite](https://github.com/krivonosoff161/agentic-security-harness/issues/19) | Local runtime | `ash local-suite` runs bounded named local-model profiles through the prompt-only OpenAI-compatible path; the low-context Prometheus profile is first-class, dry-run is the default, real runs validate artifacts, and weak evidence remains explicitly pass/finding/inconclusive/adapter_error. |
| [#20 feature: scenario timeline](https://github.com/krivonosoff161/agentic-security-harness/issues/20) | Corpus / multi-turn | `ScenarioTimeline` fixtures cover delayed activation, context overload, and handoff provenance; each has an invariant, deterministic validator expectation, and `replay_timeline()` shows the vulnerable finding/protected PASS decision step. |
| [#21 feature: trace replay and failure cards](https://github.com/krivonosoff161/agentic-security-harness/issues/21) | Reports | `ash showcase` generates artifact-driven failure cards with trace replay steps, trace/remediation artifact references, reproduce commands, and explicit non-claims; committed generated example is reproducible from `examples/demo-agent-report`. |
| [#29 fix: clarify external run diff status labels](https://github.com/krivonosoff161/agentic-security-harness/issues/29) | Reports / maintenance | Run-diff labels split decisive `finding_fixed`/`new_finding` from non-decisive `inconclusive_error_drift`/`stable_inconclusive`/`stable_error`; `error`/`adapter_error` transitions are never reported as security fixes. |
| [#25 docs: public evidence showcase](https://github.com/krivonosoff161/agentic-security-harness/issues/25) | Showcase | Public showcase entry point and evidence pages exist for reviewer navigation. |
| [#22 docs: metric contract](https://github.com/krivonosoff161/agentic-security-harness/issues/22) | Metrics | Stable vocabulary for GitHub traffic, benchmark evidence, runtime evidence, and project-process metrics. |
| [#23 feature: showcase generator](https://github.com/krivonosoff161/agentic-security-harness/issues/23) | Reports / automation | `ash showcase` generates reviewer-facing Markdown from JSON artifacts. |
| [#24 research: local model profiles](https://github.com/krivonosoff161/agentic-security-harness/issues/24) | Local runtime | Hardware-safe local model profiles and stop conditions are documented. |
| [#31 docs: correct inter-agent handoff research source map](https://github.com/krivonosoff161/agentic-security-harness/issues/31) | Standards / research | Broken citations fixed; adjacent work acknowledged; shipped-vs-planned claims kept conservative. |
| [#32 research: formalize handoff verifier decisions and risk scoring](https://github.com/krivonosoff161/agentic-security-harness/issues/32) | Multi-agent / reports | Deterministic blocker verdicts are separated from normalized severity scoring. |
| [#33 research: define minimal typed handoff envelope](https://github.com/krivonosoff161/agentic-security-harness/issues/33) | Multi-agent / recovery | Envelope fields and payload-type requirements are explicit before fixtures/tests are added. |
| [#30 research: design inter-agent handoff integrity contract](https://github.com/krivonosoff161/agentic-security-harness/issues/30) | Multi-agent / research | Design contract, claim boundary, failure classes, verifier outcomes, and staged work order are documented. |
| [#34 feature: add deterministic toy topology for handoff integrity](https://github.com/krivonosoff161/agentic-security-harness/issues/34) | Multi-agent / corpus | Local synthetic verifier topology ships vulnerable/protected handoff traces for label loss and authority expansion. |
| [#48 research: measure local small-model swarm evidence quality](https://github.com/krivonosoff161/agentic-security-harness/issues/48) | Local empirical / evidence quality | `ash evidence-quality` summarizes recorded external/local artifacts for schema adherence, raw-response/hash coverage, deterministic-validator agreement, inconclusive/error/flaky split, and cross-run disagreement without creating a model leaderboard. |
| [#50 research: rerun local Prometheus probes and publish evidence-quality summary](https://github.com/krivonosoff161/agentic-security-harness/issues/50) | Local runtime / evidence quality | Fresh bounded Prometheus/Ollama rerun recorded 11 local-model checks across `data-boundary`, `authority-control`, and `approval-audit`; docs summarize 3 pass, 8 inconclusive, 0 findings, and fresh-only evidence-quality metrics with raw responses kept local/private. |
| [#53 research: deepen authority delegation public evidence](https://github.com/krivonosoff161/agentic-security-harness/issues/53) | Multi-agent / authority | Authority delegation evidence now covers issuer, scope, purpose, TTL, and delegation-depth non-expansion in verifier tests and public theory docs; revocation remains explicitly out of scope. |
| [#54 research: publish inter-agent handoff toy evidence](https://github.com/krivonosoff161/agentic-security-harness/issues/54) | Multi-agent / handoff | `examples/handoff-toy-comparison/` is a committed public artifact for toy coordinator/worker handoff evidence, validated by `ash validate examples/handoff-toy-comparison`. |
| [#55 research: define memory-governance invariant layer](https://github.com/krivonosoff161/agentic-security-harness/issues/55) | Memory governance / theory | `memory_governance.py` adds executable synthetic checks for TTL-from-write, envelope drift, provenance metadata, trust floor, trust precedence, and scope isolation, with public theory docs and tests. |
| [#57 research: harden boundary layer evidence matrices](https://github.com/krivonosoff161/agentic-security-harness/issues/57) | Boundary-layer research | `boundary-layer-evidence-matrix.md` ties 22 declared handoff, authority, and memory-governance variation rows to executable tests while keeping private scratch calculations out of public evidence. |

## Recently completed local research closures

These items close local research tasks that were not tracked as GitHub issues. They are
kept separate from the issue table so the public tracker does not imply that a GitHub
issue was closed when no issue number exists.

| Local task | Track | Delivered focus | Public evidence | Private/local note |
|---|---|---|---|---|
| DB-1 | Data boundary / theory | Formalized the envelope restriction relation `E_out <= E_in`, field-level non-expansion rules, and explicit non-claims. | `docs/theory/data-boundary.md`, `docs/research-claims.md`, documentation contract tests. | Owner-retained local derivation note; not committed and not public evidence. |
| DB-2 | Data boundary / corpus | Added `data_boundary_missing_envelope_recovery`, regenerated the then-current examples/golden snapshots, and updated external-run arithmetic. | `examples/comparison-report/`, `docs/showcase/generated/`, `tests/golden/`, `ash validate examples/`. | Owner-retained local verification checklist; not committed and not public evidence. |
| DB-3 | Data boundary / memory read boundary | Added `data_boundary_memory_envelope_drift`, implemented field-level envelope restriction checks, regenerated the 24-pattern examples/golden snapshots, and updated data-boundary theory/claims. | `src/agentic_security_harness/envelope_policy.py`, `tests/test_envelope_policy.py`, `examples/comparison-report/`, `docs/theory/data-boundary.md`, `ash validate examples/`. | Owner-retained local verification checklist; not committed and not public evidence. |

Supporting docs:

- [metric-contract.md](metric-contract.md) defines how traffic, benchmark, runtime, and
  process metrics should be read.
- [inter-agent-handoff-integrity.md](inter-agent-handoff-integrity.md) defines the
  design-first track for provenance-preserving worker-to-senior agent handoffs.
- [handoff-toy-topology.md](handoff-toy-topology.md) documents the first shipped local
  synthetic verifier topology for malformed summary and capability handoffs.
- [research-claims.md](research-claims.md) tracks research claims from hypothesis
  through validated evidence artifacts.
- [boundary-layer-evidence-matrix.md](boundary-layer-evidence-matrix.md) maps the current
  handoff, authority, and memory-governance variation rows to executable tests.
- [local-prometheus-workflow.md](local-prometheus-workflow.md) defines the low-memory
  Ollama smoke workflow for real local model probes.
- [local-model-profiles.md](local-model-profiles.md) records hardware-safe local model
  profiles and stop conditions.
- `ash evidence-quality --root reports --out reports/evidence-quality` summarizes
  evidence quality from recorded external/local/local-swarm artifacts without making
  model calls.
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
4. Keep local Prometheus/model-in-loop probes bounded: named profiles, request caps,
   dry-run first, validated artifacts, and explicit weak-evidence interpretation.
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

- claiming local real-model probes are benchmark-grade or general model-safety evidence;
- treating GitHub clone/view spikes as benchmark validation;
- presenting weak local model runs as a universal model-safety conclusion;
- presenting manually written showcase text as evidence without trace/scorecard links.
