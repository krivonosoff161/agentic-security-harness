# Project map

> **Agentic Security Harness.** This guide is for maintainers, reviewers, and non-code
> researchers who need to understand the project without reading every source file.

## One-sentence model

The project turns an agentic AI failure idea into a safe, reproducible benchmark:

```text
problem idea -> sanitized pattern -> local target -> trace -> scorecard -> validation
```

The current release is local and synthetic. It does not call real LLM providers, does not
test third-party systems, and does not ship the planned reference gateway.

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
| Corpus | The 17 implemented defensive patterns and their expected outcomes. | [corpus.md](corpus.md), `src/agentic_security_harness/corpus.py` |
| Patterns | Sanitized test cases the runner sends to targets. | `src/agentic_security_harness/patterns.py` |
| Targets | Local systems under test: `mock`, `demo-agent`, `protected-demo-agent`. | `src/agentic_security_harness/*agent*.py`, `mock_target.py` |
| Runner | Converts `pattern + target` into traces. | `src/agentic_security_harness/runner.py` |
| Reports | Writes `traces.json`, `scorecard.json`, `summary.md`, and comparison reports. | `src/agentic_security_harness/reporting.py`, `examples/` |
| Validation | Checks report artifacts against the corpus manifest. | `src/agentic_security_harness/validation.py` |
| CLI | User-facing commands. | `src/agentic_security_harness/cli.py` |
| Adapter contract | Rules for future model/provider/runtime adapters. | [adapter-contract.md](adapter-contract.md) |
| Reporting design | How executive and technical reports should be shaped. | [reporting.md](reporting.md) |

## What is not implemented today

- No real LLM/provider adapter.
- No network target.
- No MCP server adapter.
- No multimodal/audio generation.
- No HTTP reference gateway runtime.
- No database or persistent trace store.

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

Start here:

1. [README](../README.md) - current status, commands, and high-level positioning.
2. [Positioning](positioning.md) and [boundary model](agentic-boundary-model.md) - the
   operating-environment boundary thesis.
3. [Corpus coverage matrix](corpus.md) - the 17 implemented patterns.
4. [Comparison example](../examples/comparison-report/README.md) - the visible 17 -> 0
   demonstration.
5. [Adapter contract](adapter-contract.md) - how future targets can implement the benchmark.
6. [Reporting design](reporting.md) - what reviewers should see in reports.
7. [Problem-solution catalog](problem-solution-catalog.md) - larger map of problems,
   mitigations, and planned reference controls.
8. [Research roadmap](research-roadmap.md) - cleaned intake map for future patterns.
9. [Roadmap](roadmap.md) - what is current, next, and future.

Then run:

```bash
pip install -e ".[dev]"
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

Expected current result: baseline has 17 findings; protected has 0 findings.

## How to add a new research idea safely

Convert the idea into this structure before asking an agent to code:

```text
problem -> defensive scenario -> expected vulnerable behavior -> detection signal
-> mitigation -> harness test -> residual risk
```

Rules:

- Use synthetic data only.
- Use mock/demo/authorized targets only.
- Do not include real payloads, real credentials, evasion steps, persistence, or live abuse.
- The vulnerable target must fail for a clear reason.
- The protected target must pass because of a specific control.
- The trace must show where the failure happened.
- The docs must say whether the item is current, planned, or future.

## Review checklist for agent-generated changes

Before accepting a change from any coding agent, check:

- Scope: does the diff touch only the files required for the task?
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
