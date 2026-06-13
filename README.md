# Agentic Security Harness

> **Agentic Security Harness** · open-source · Apache-2.0 · repository `agentic-security-harness`

**A trace-first defensive benchmark for agentic AI failure modes.** It reproduces how LLM
agents, tool chains, and data boundaries fail, captures each run as a **portable failure
trace**, and **measures risk reduction** by replaying a baseline target against a protected one.

- **Trace-first** — every run is a portable, machine-readable failure trace, not just pass/fail.
- **Agentic operating-environment boundary corpus** — 17 deterministic seed patterns for
  how sensitivity labels, recipients, storage, forwarding, audit, budget, delegated
  authority, tool schemas, perception boundaries, ambient authority, approval context,
  and memory governance break in agentic systems.
- **Baseline vs protected replay** — a vulnerable demo agent vs a controlled one, on
  deterministic **local** targets, with a measured before/after scorecard.
- **Standards-aware corpus** - implemented patterns include coarse OWASP Agentic Security
  Initiative mappings; OWASP LLM and MITRE ATLAS mappings remain verification-gated.

No network, no LLM / provider calls, no real targets — synthetic, sanitized, reproducible.

> The **gateway** is an optional **reference defense** component used as a replay target —
> not the main product, and not implemented in the current release.

---

> ### ⚠️ This is an authorized defensive testing harness — not a hacking manual.
>
> Attack chains are documented as **defensive test patterns**: sanitized, reproducible,
> run against **mock / demo / authorized targets only**, with expected vulnerable behavior
> and a mitigation. No real credential theft, no live exploitation, no instructions for
> abusing third-party systems. See [SECURITY.md](SECURITY.md#responsible-use).
>
> It does **risk reduction, observability, and measurement** — not 100% protection.
> Detectors have false negatives. See [docs/threat-model.md](docs/threat-model.md).

---

## Mission

Make agentic AI failure modes **visible, reproducible, measurable, and teachable** — a
defensive **education + measurement lab**, not an offensive toolkit. Full mission:
[docs/mission.md](docs/mission.md).

## Safe research rules

Authorized / mock / demo targets only · synthetic secrets only · no real exfiltration ·
deterministic tests · honest residual risk. Full rules:
[docs/research-rules.md](docs/research-rules.md).

## How to read this repository

- New to the project? Start with the [project map](docs/project-map.md).
- Evaluating it for an AI/security team? Read [use cases](docs/use-cases.md) and the
  [comparison example](examples/comparison-report/README.md).
- Reviewing standards coverage? Read the [standards mapping](docs/standards-mapping.md)
  and [corpus matrix](docs/corpus.md).
- Adding a new idea? Convert it into the safe structure in
  [project map](docs/project-map.md#how-to-add-a-new-research-idea-safely) before coding.
- Prioritizing future patterns? Read the [research roadmap](docs/research-roadmap.md).

## Status

**Pre-release, working.** The harness runs a **17-pattern local corpus centered on
agentic operating-environment boundary failures** — data-boundary, authority, perception,
memory governance, approval, and audit integrity — against deterministic local targets,
with baseline-vs-protected replay (see *What exists today*). Cross-app contamination,
real target adapters, MCP, multi-agent, multimodal, and the reference gateway come later.
See [docs/roadmap.md](docs/roadmap.md).

![status](https://img.shields.io/badge/status-pre--release-orange)
![ci](https://github.com/krivonosoff161/agentic-security-harness/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)

## What exists today

- **Pydantic v2 models** — `DataEnvelope` (a policy label, **not** encryption), `Finding`,
  `TraceStep`, `TargetDescriptor`, `ExploitTrace`, `DefensivePattern`.
- **Seventeen sanitized seed patterns** — indirect prompt injection, data-boundary recipient
  confusion, memory poisoning, classification mutation, handoff label stripping,
  tool-permission abuse, provider-boundary leakage, sleeping-prompt delayed activation,
  audit spam-label abuse, budget loop abuse, capability delegation drift, mock
  tool-schema deception, audit hash-chain tampering, perception-boundary sensor-command
  confusion, ambient authority escalation, approval laundering, and memory governance.
- **Deterministic mock target** — vulnerable-by-design demo target; no LLM, no network.
- **Local demo agent (`demo-agent`)** — a deterministic, synthetic agent (in-memory memory,
  mock tool calls, data-envelope propagation, recipient-control checks); intentionally
  vulnerable for the seed patterns. No network, no LLM.
- **Protected demo agent (`protected-demo-agent`)** — the same agent with simple deterministic
  controls; passes all seventeen seed patterns. `ash compare` measures the reduction in findings.
- **Runner** — `pattern → target → trace` (mock or demo-agent).
- **Scorecard** — a deterministic aggregate derived from traces.
- **Demo CLI (`ash`)** — `ash run --target {mock,demo-agent,protected-demo-agent}`,
  `ash compare --baseline ... --protected ...`, and `ash validate <path>` write/validate
  deterministic reports (see Quickstart). Committed examples under [`examples/`](examples/).
- **Validation (`ash validate examples/`)** — checks committed benchmark artifacts (traces,
  scorecards, summaries, comparison) and corpus consistency, and scans for forbidden
  markers; the examples are **validated benchmark artifacts**, not loose output.
- **Unit tests** — models, runner, scorecard, reporting, validation, and CLI smoke tests.

No gateway, provider calls, network, or real payloads.

## Current vs planned

| Area | Current release | Planned / future track |
|---|---|---|
| Benchmark | 17-pattern deterministic local corpus, traces, scorecards, validation. | Larger corpus, mappings, report quality. |
| Targets | `mock`, `demo-agent`, `protected-demo-agent` only. | Local toy adapters first, then explicitly authorized real adapters. |
| Runtime | CLI-only (`ash run`, `ash compare`, `ash validate`). | Optional HTTP reference gateway after the benchmark stabilizes. |
| Network / providers | None. | Future adapters only with explicit authorization and docs. |
| Storage | Local report files and committed examples. | Optional persistent trace store after v1.0. |

### Verify locally

```bash
pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src tests
ash validate examples/        # validate committed benchmark artifacts
```

## Core capabilities

- **Portable defensive traces** — machine-readable, replayable records of a test run.
- **Agentic operating-environment boundary testing** — verifies whether data envelopes,
  authority scopes, perception trust boundaries, memory governance, approval context,
  and audit integrity survive agent handoffs, memory writes, tool calls, and provider
  routing.
- **Label-propagation measurement** - a conformance-oriented view of whether data-envelope
  fields survive known handoff, memory, tool, and provider-boundary failure shapes.
- **Practical attack graph** — `target → exposed inputs → agents → tools → permissions →
  memory → external data → attack chain → observed behavior → finding → mitigation`.
- **Reproducible cross-target comparison** — replay the same traces against different
  targets / defenses.
- **Cross-agent contamination** (planned) - explicit tests for multi-agent workflows (one
  agent poisoning another).
- **MCP / tool-permission scanning** (planned) - the tools/permissions layer of the graph.
- **Full signal path** (planned) - tests the pre-LLM sensor / input channel (e.g. audio ->
  ASR -> agent action) that text-only gateways typically do not see.
- **Scorecard from traces** — a derived, deterministic aggregate.
- **Reference gateway** (planned) — an optional defense target design for future replay.

Full design: **[docs/harness.md](docs/harness.md)** (flagship document).

## What it helps you test

Agentic failure modes, as sanitized [defensive test patterns](docs/harness.md#attack-pattern-taxonomy):
context flooding / instruction overload · indirect prompt injection via RAG / tool output
· cross-agent contamination · memory poisoning · tool-permission abuse · MCP / tool-schema
deception · simulated data-exfiltration · budget exhaustion / loop abuse · multi-turn
policy bypass · multimodal / sensor-to-agent (audio → ASR) injection · agentic
data-boundary / recipient-control.

Thirteen local seed patterns are implemented today: six data-boundary / recipient-control
patterns, one indirect tool-output injection seed, three v0.6 additions
(sleeping-prompt delayed activation, audit spam-label abuse, budget loop abuse),
three v0.7 authority / integrity additions (capability delegation drift, mock
tool-schema deception, audit hash-chain tampering), and four v0.8 perception /
authority / governance additions (perception-boundary sensor-command confusion,
ambient authority escalation, approval laundering, memory governance). The rest are on the
[roadmap](docs/roadmap.md).

## Reference defense (planned optional component)

The repository's original component is an OpenAI-compatible **gateway** — now positioned
as a planned **reference defense implementation** and a future **defense target** for
replay. It is not shipped in the current release; the current release is CLI-only. When
implemented in the request path, it is expected to produce one of five decisions:

| Status | Meaning |
|---|---|
| `ALLOW` | Clean; forward unchanged. |
| `WARN` | Forward, but annotate / flag for review. |
| `REDACT` | Mask PII/secrets and forward the sanitized version. |
| `QUARANTINE` | Hold; return a `quarantine_id`; await approve/reject (async). |
| `BLOCK` | Reject; return a provider-shaped error. |

See [docs/architecture.md](docs/architecture.md) and the planned
[reference-gateway API design](docs/api-reference.md).

## Quickstart — one-command demo

```bash
pip install -e .

# simple deterministic mock target
ash run --target mock --out reports/demo

# local demo agent: synthetic, closer to real agent mechanics
ash run --target demo-agent --out reports/demo-agent

# protected variant: same agent with simple deterministic controls
ash run --target protected-demo-agent --out reports/protected-demo-agent

# validate the committed benchmark artifacts (or your own runs)
ash validate examples/
```

Each run writes three artifacts:

```text
reports/demo/
├── traces.json       # portable, machine-readable traces (one per pattern)
├── scorecard.json    # deterministic aggregate
└── summary.md        # human-readable summary table
```

`demo-agent` is a deterministic **local, synthetic** agent (in-memory memory, mock tool
calls, data-envelope propagation, recipient-control checks) — still no network, no LLM, and
no real targets — but closer to real agent behavior than `mock`.

Committed example outputs (no install needed to view):
[`examples/demo-report/`](examples/demo-report/) (mock) and
[`examples/demo-agent-report/`](examples/demo-agent-report/) (demo-agent). The main
before/after example is explained in
[`examples/comparison-report/README.md`](examples/comparison-report/README.md).

> Local / synthetic, deterministic, no network or LLM calls.

## Measure risk reduction

`demo-agent` is **vulnerable by design**; `protected-demo-agent` is the same agent with
**simple deterministic controls** (untrusted tool output is not acted on, recipients outside
the data envelope are blocked, `can_store=false` is honored). The `compare` command runs both
against the same patterns and writes a side-by-side report:

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
```

```text
reports/comparison/
  baseline/      traces.json, scorecard.json, summary.md
  protected/     traces.json, scorecard.json, summary.md
  comparison.md
```

In the committed example
([`examples/comparison-report/comparison.md`](examples/comparison-report/comparison.md)) the
baseline fails all 17 patterns (17 findings) and the protected agent passes all 17 (0 findings).

> Educational and synthetic: risk reduction is measured from deterministic mock traces,
> **not** a guarantee of real-world protection.

## Prior art

This project does **not** claim to be the first or only tool in the category. Prior art
exists — **BotGuard** (open-source red-teaming + firewall for AI agents) is the closest
combined work; **garak**, **PyRIT**, and **promptfoo** are established red-team / eval tools;
**Trylon Gateway** is the closest gateway. Its focus is an **opinionated, trace-first
benchmark** for agentic **operating-environment boundary failures**, with portable
traces and deterministic baseline-vs-protected replay. Honest comparison:
[docs/competitors.md](docs/competitors.md).

## Documentation

- **[Harness](docs/harness.md)** — flagship: trace format, attack graph, test patterns, scorecard, replay.
- **[Project map](docs/project-map.md)** — plain-language guide for reviewers and maintainers.
- **[Use cases](docs/use-cases.md)** — how AI/security teams can evaluate and apply the benchmark.
- **[Problem–solution catalog](docs/problem-solution-catalog.md)** — problem → detection → mitigation → harness test → reference control → residual risk.
- **[Corpus coverage matrix](docs/corpus.md)** — the 13 implemented seed patterns, baseline vs protected, and what each touches.
- **[Research roadmap](docs/research-roadmap.md)** - cleaned intake map for future benchmark patterns.
- **[Mission](docs/mission.md)** · **[Safe research rules](docs/research-rules.md)** — what this is for, and how to research safely.
- **Learning** — [agentic security basics](docs/learning/01-agentic-security-basics.md) · [data-boundary failures](docs/learning/02-data-boundary-failures.md).
- [Architecture](docs/architecture.md) — components and data flow.
- [Roadmap](docs/roadmap.md) — the current benchmark roadmap, `v0.1` -> `v1.0`.
- [Threat model](docs/threat-model.md) — what we cover, what we don't, OWASP mapping.
- [Competitors](docs/competitors.md) — landscape (verified, with sources).
- [API reference](docs/api-reference.md) — planned reference-gateway API design.
- [Deployment](docs/deployment.md) · [Development](docs/development.md).

## Responsible use

The harness ships **sanitized defensive test content**. Use it only against systems you own
or are authorized to test. Payloads are sanitized; "sensitive" data in tests are synthetic
markers. Full policy: [SECURITY.md](SECURITY.md#responsible-use).

## Brand and attribution

The project is **Agentic Security Harness** (repository `agentic-security-harness`).

- **Code** is licensed under [Apache-2.0](LICENSE).
- The **project name, logos, and branding** are not granted as trademarks.
- Please **preserve attribution** when referencing the project or its corpus — see [NOTICE](NOTICE).

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — add a test pattern / target adapter / trace detector.
- [SECURITY.md](SECURITY.md) — responsible use + private vulnerability disclosure.

## License

[Apache-2.0](LICENSE).
