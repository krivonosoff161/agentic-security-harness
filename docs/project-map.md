# Project map

> **Agentic Security Harness.** This guide is for maintainers, reviewers, and non-code
> researchers who need to understand the project without reading every source file.

## One-sentence model

The project turns an agentic AI failure idea into a safe, reproducible benchmark:

```text
problem idea -> boundary invariant -> evaluation topology -> sanitized pattern
-> target adapter -> trace -> scorecard -> validation
```

Built-in/local targets are local, synthetic, deterministic, and offline. There is also an
experimental, opt-in `run-external` path that evaluates an OpenAI-compatible endpoint with
synthetic prompts (prompt-only, no tool execution). The release does not ship native
provider adapters, agent-host/tool-use adapters, or the planned reference gateway.

## What you need to understand first

You do not need to read all code to reason about the project. The core contract is:

1. A **pattern** describes one defensive failure mode with synthetic data.
2. A **vulnerable target** should fail that pattern.
3. A **protected target** should pass that same pattern.
4. A **trace** records what happened in a portable, machine-readable way.
5. A **scorecard** summarizes the traces.
6. `ash validate` checks that the committed reports match the corpus and contain no
   forbidden markers.

If those six points hold, the benchmark is coherent.

## Current working pieces

| Piece | What it does | Where to look |
|---|---|---|
| Corpus | The 22 implemented defensive patterns and their expected outcomes. | [corpus.md](corpus.md), `src/agentic_security_harness/corpus.py` |
| Boundary model | The protection/boundary invariants the corpus is organized around. | [agentic-boundary-model.md](agentic-boundary-model.md) |
| Evaluation topologies | The system shapes a target adapter can represent: local target, agent, memory loop, tool loop, model chain, handoff, provider boundary, recovery path. | [evaluation-topologies.md](evaluation-topologies.md) |
| Corpus expansion plan | Invariant-based backlog for future patterns without full combinatorial expansion. | [corpus-expansion-plan.md](corpus-expansion-plan.md) |
| Patterns | Sanitized test cases the runner sends to targets. | `src/agentic_security_harness/patterns.py` |
| Targets | Local systems under test: `mock`, `demo-agent`, `protected-demo-agent`, and toy adapters `toy-local-function`, `toy-rag`, `toy-tools`, `toy-multi-agent`. | `src/agentic_security_harness/*agent*.py`, `mock_target.py`, `toy_adapters.py` |
| Runner | Converts `pattern + target` into traces. | `src/agentic_security_harness/runner.py` |
| Scenario matrix | Runs scenario variants and aggregates stability (`run-matrix`). | `src/agentic_security_harness/matrix.py` |
| External path | Experimental, opt-in OpenAI-compatible prompt-only model check (`run-external`, `external-check`, `external-presets`). | `src/agentic_security_harness/external_runner.py`, `presets.py`, [connect-models.md](connect-models.md) |
| Reports | Writes `traces.json`, `scorecard.json`, `summary.md`, `executive.md`, remediation, comparison, and static HTML (`report`). | `src/agentic_security_harness/reporting.py`, `html_report.py`, `examples/` |
| Run diff | `diff-runs` compares two same-kind runs (`run_diff.json` / `run_diff.md`); `compare-models` wraps this for external model artifacts. | `src/agentic_security_harness/run_diff.py`, [run-diff.md](run-diff.md) |
| Run history | `run_index.json` manifest per run; `list-runs` lists them; `index-runs` builds a local SQLite metadata index; `stats` summarizes history; `retention` plans cleanup. | `src/agentic_security_harness/run_manifest.py`, `rundb.py`, `stats.py` |
| Schemas | Every JSON artifact carries a `schema_version` from one registry. | `src/agentic_security_harness/schema_versions.py`, [artifact-schemas.md](artifact-schemas.md) |
| Validation | Checks report/external/manifest/diff artifacts, schema versions, and standards-mapping consistency. | `src/agentic_security_harness/validation.py` |
| Diagnostics | `doctor` checks the environment (no network by default). | `src/agentic_security_harness/doctor.py` |
| CLI | `run`, `compare`, `run-matrix`, `run-external`, `external-check`, `external-presets`, `diff-runs`, `compare-models`, `validate`, `report`, `doctor`, `list-runs`, `index-runs`, `stats`, `retention`, `targets`, `scenarios`. | `src/agentic_security_harness/cli.py` |
| Adapter contract | Rules and metadata models for future model/provider/runtime adapters. | [adapter-contract.md](adapter-contract.md), `models.py` |
| Reporting design | How executive and technical reports should be shaped. | [reporting.md](reporting.md) |

## Network model (important)

- **Built-in/local targets** (`mock`, `demo-agent`, `protected-demo-agent`, toy adapters)
  and `run-matrix`: deterministic and **offline** - no network, no provider calls.
- **`run-external` / `external-check --live`**: make OpenAI-compatible calls, but **only
  on explicit opt-in** (a real run without `--dry-run`, or `--live`). Prompt-only; no
  tool execution.
- Everything is no-network **by default**.

## What is not implemented today

- No native provider SDK adapter (the external path is generic OpenAI-compatible only).
- No agent-host / tool-use adapter (the external path does not execute tools).
- No streaming, multi-turn agent host, or MCP server adapter.
- No multimodal/audio generation.
- No HTTP reference gateway runtime.
- No database, persistent trace store, or web dashboard.

These are roadmap or future-track items. They should not be described as shipped behavior.

## Glossary in plain language

- **Failure mode:** a class of thing that can go wrong in an agentic AI workflow.
- **Pattern:** the safe test case that represents that failure mode.
- **Data envelope:** a policy label attached to data, such as allowed recipients, purpose,
  storage rules, forwarding rules, and TTL. It is not encryption.
- **Target:** the system being tested. Current targets are local and synthetic.
- **Trace:** the machine-readable record of one test run.
- **Finding:** the recorded failure inside a trace.
- **Scorecard:** a deterministic summary of many traces.
- **Comparison:** baseline target vs protected target on the same corpus.
- **Validation:** a check that reports are internally consistent and safe to commit.

## How to inspect the project without reading code

Start here by role:

| Role | Read first | Why |
|---|---|---|
| First-time user | [Getting started](getting-started.md), [User journey](user-journey.md) | Run the deterministic local path and inspect output. |
| Project status reviewer | [Current state](current-state.md), [Capability matrix](capability-matrix.md), [Roadmap](roadmap.md), [Project tracker](project-tracker.md) | Separate shipped, experimental, planned, blocked work, and visible GitHub issue flow. |
| Benchmark reviewer | [Benchmark protocol](benchmark-protocol.md), [Benchmark semantics](benchmark-semantics.md), [Artifact schemas](artifact-schemas.md) | Understand what the benchmark proves and what it does not prove. |
| Adapter author | [Custom adapter tutorial](custom-adapter-tutorial.md), [Adapter contract](adapter-contract.md), [Bring your own target](bring-your-own-target.md) | Implement a target without forking the benchmark model. |
| Report reviewer | [Examples index](../examples/README.md), [Comparison example](../examples/comparison-report/README.md), [Reporting](reporting.md) | Inspect committed proof artifacts before running anything. |
| Local model reviewer | [Local Prometheus workflow](local-prometheus-workflow.md), [Metrics contract](metric-contract.md), [Connect models](connect-models.md) | Run a weak local model safely and read inconclusive/error evidence correctly. |
| Safety reviewer | [Research rules](research-rules.md), [Authorized testing paths](authorized-testing-paths.md), [Threat model](threat-model.md), [SECURITY](../SECURITY.md) | Confirm the project stays defensive, synthetic, and authorized. |
| Release reviewer | [Release checklist](release-checklist.md), [Changelog](../CHANGELOG.md), [CI workflow](../.github/workflows/ci.yml) | Verify public packaging and quality gates. |

If you still want the linear path:

1. [README](../README.md) - current status, commands, and high-level positioning.
2. [Current state](current-state.md) - shipped, experimental, planned, and active work.
3. [Benchmark protocol](benchmark-protocol.md) - formal run semantics, scoring limits,
   and claim boundaries.
4. [Positioning](positioning.md) and [boundary model](agentic-boundary-model.md) - the
   operating-environment boundary thesis.
5. [Evaluation topologies](evaluation-topologies.md) - what kinds of systems can sit
   behind a target adapter.
6. [Corpus coverage matrix](corpus.md) - the 22 implemented patterns.
7. [Comparison example](../examples/comparison-report/README.md) - the visible 22 -> 0
   demonstration.
8. [Authorized testing paths](authorized-testing-paths.md) - local, owned, authorized,
   provider-program, and standards-aligned use.
9. [Custom adapter tutorial](custom-adapter-tutorial.md) - the quickest path for a new
   local target.
10. [Adapter contract](adapter-contract.md) - how future targets can implement the benchmark.
11. [Reporting design](reporting.md) - what reviewers should see in reports.
12. [Problem-solution catalog](problem-solution-catalog.md) - larger map of problems,
   mitigations, and planned reference controls.
13. [Corpus expansion plan](corpus-expansion-plan.md) - bounded backlog for future patterns.
14. [Research roadmap](research-roadmap.md) - cleaned intake map for future patterns.
15. [Roadmap](roadmap.md) - what is current, next, and future.

Then run:

```bash
pip install -e ".[dev]"
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

Expected current result: baseline has 22 findings; protected has 0 findings.

## How to add a new research idea safely

Convert the idea into this structure before asking an agent to code:

```text
problem -> boundary invariant -> evaluation topology -> defensive scenario
-> expected vulnerable behavior -> detection signal -> mitigation -> harness test
-> residual risk
```

Rules:

- Use synthetic data only.
- Use mock/demo/authorized targets only.
- Do not include real payloads, real credentials, evasion steps, persistence, or live abuse.
- The vulnerable target must fail for a clear reason.
- The protected target must pass because of a specific control.
- The trace must show where the failure happened.
- The docs must say whether the item is current, planned, or future.
- Do not expand by full cross-product. Use representative, invariant-based patterns.

## Review checklist for agent-generated changes

Before accepting a change from any coding agent, check:

- Scope: does the diff touch only the files required for the task?
- Governance: does the change belong in an issue/decision before code, especially for
  corpus, adapter, or methodology work?
- Safety: no real secrets, real targets, live abuse steps, malware behavior, or unsafe
  instructions.
- Current/planned boundary: planned gateway, real adapters, MCP, and multimodal work are
  not described as shipped.
- Corpus consistency: new patterns update `patterns.py`, `corpus.py`, tests, examples,
  and [corpus.md](corpus.md).
- Artifact consistency: regenerated examples pass `ash validate examples/`.
- Test gates: `pytest`, `ruff`, `mypy`, `ash validate examples/`, and `git diff --check`.
- Claims: no first/only/complete-protection claims.
- Attribution: existing project name, license, and NOTICE are preserved.
- Project process: [GOVERNANCE.md](../GOVERNANCE.md), [MAINTAINERS.md](../MAINTAINERS.md),
  and GitHub issue/PR templates are followed.

## Red flags in future pull requests

- A new adapter makes network or provider calls without a written authorization model.
- A doc says the reference gateway is implemented before gateway code exists.
- A pattern contains operational abuse instructions instead of sanitized test fixtures.
- A scorecard is edited by hand without regenerating traces.
- A protected target passes because the test was weakened, not because a control exists.
- A change hides findings instead of measuring them.

## Owner role vs code role

The project owner does not need to write every module. The owner should define:

- which real-world problems matter;
- what a safe mock scenario should prove;
- what a useful detection signal looks like;
- what mitigation should be measured;
- whether the docs explain the result clearly.

The code should then make that idea reproducible, testable, and reviewable.
