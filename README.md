# Agentic Security Harness

> **Repository:** `agentic-security-harness` · **Product name:** _TBD_

**An open-source defensive harness and learning lab for reproducing and measuring agentic
AI failure modes through portable traces, attack graphs, scorecards, and data-boundary tests.**

It runs **defensive test patterns** against an LLM agent, an MCP / tool chain, a
multi-agent workflow, or an AI gateway, records each run as a **portable, machine-readable
trace**, and derives a **scorecard**. Because traces are portable, you can **replay** them
against a defended target and **measure the risk reduction** instead of claiming it.

> The repository is **`agentic-security-harness`**; the product / brand name is still
> **TBD**. The gateway is the **reference defense** component, not the main product.

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

## Status

**Pre-release.** The `v0.1` harness core is implemented (see *What exists today* below);
real target adapters, MCP, multi-agent, multimodal, and the reference gateway come later.
See [docs/roadmap.md](docs/roadmap.md).

![status](https://img.shields.io/badge/status-pre--release-orange)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)

## What exists today (`v0.1` core)

- **Pydantic v2 models** — `DataEnvelope` (a policy label, **not** encryption), `Finding`,
  `TraceStep`, `TargetDescriptor`, `ExploitTrace`, `DefensivePattern`.
- **Three sanitized seed patterns** — indirect prompt injection (via tool output),
  data-boundary recipient confusion, memory poisoning.
- **Deterministic mock target** — vulnerable-by-design demo target; no LLM, no network.
- **Local demo agent (`demo-agent`)** — a deterministic, synthetic agent (in-memory memory,
  mock tool calls, data-envelope propagation, recipient-control checks); intentionally
  vulnerable for the seed patterns. No network, no LLM.
- **Protected demo agent (`protected-demo-agent`)** — the same agent with simple deterministic
  controls; passes all three seed patterns. `ash compare` measures the reduction in findings.
- **Runner** — `pattern → target → trace` (mock or demo-agent).
- **Scorecard** — a deterministic aggregate derived from traces.
- **Demo CLI (`ash`)** — `ash run --target {mock,demo-agent,protected-demo-agent}` and
  `ash compare --baseline ... --protected ...` write deterministic reports (see Quickstart).
  Committed examples under [`examples/`](examples/).
- **Unit tests** — models, runner, scorecard, reporting determinism, and a CLI smoke test.

No gateway, provider calls, network, or real payloads.

### Verify locally

```bash
python -m pytest
python -m ruff check .
python -m mypy src tests
```

## Core capabilities

- **Portable defensive traces** — machine-readable, replayable records of a test run.
- **Agentic data-boundary testing** — verifies whether sensitivity labels, recipients,
  storage rules, and forwarding rules survive agent handoffs, memory writes, tools, and
  provider routing.
- **Practical attack graph** — `target → exposed inputs → agents → tools → permissions →
  memory → external data → attack chain → observed behavior → finding → mitigation`.
- **Reproducible cross-target comparison** — replay the same traces against different
  targets / defenses.
- **Cross-agent contamination** — explicit tests for multi-agent workflows (one agent
  poisoning another).
- **MCP / tool-permission scanning** — the tools/permissions layer of the graph.
- **Full signal path** — tests the pre-LLM sensor / input channel (e.g. audio → ASR →
  agent action) that text-only gateways typically do not see.
- **Scorecard from traces** — a derived, deterministic aggregate.
- **Reference gateway** — an **optional defense target** you can replay traces against.

Full design: **[docs/harness.md](docs/harness.md)** (flagship document).

## What it helps you test

Agentic failure modes, as sanitized [defensive test patterns](docs/harness.md#attack-pattern-taxonomy):
context flooding / instruction overload · indirect prompt injection via RAG / tool output
· cross-agent contamination · memory poisoning · tool-permission abuse · MCP / tool-schema
deception · simulated data-exfiltration · budget exhaustion / loop abuse · multi-turn
policy bypass · multimodal / sensor-to-agent (audio → ASR) injection · agentic
data-boundary / recipient-control.

## Reference defense (optional)

The repository's original component is an OpenAI-compatible **gateway** — now positioned
as a **reference defense implementation** and a **defense target** for replay. When in the
request path it produces one of five decisions:

| Status | Meaning |
|---|---|
| `ALLOW` | Clean; forward unchanged. |
| `WARN` | Forward, but annotate / flag for review. |
| `REDACT` | Mask PII/secrets and forward the sanitized version. |
| `QUARANTINE` | Hold; return a `quarantine_id`; await approve/reject (async). |
| `BLOCK` | Reject; return a provider-shaped error. |

See [docs/architecture.md](docs/architecture.md) and [docs/api-reference.md](docs/api-reference.md).

## Quickstart — one-command demo

```bash
pip install -e .

# simple deterministic mock target
ash run --target mock --out reports/demo

# local demo agent: synthetic, closer to real agent mechanics
ash run --target demo-agent --out reports/demo-agent

# protected variant: same agent with simple deterministic controls
ash run --target protected-demo-agent --out reports/protected-demo-agent
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
[`examples/demo-agent-report/`](examples/demo-agent-report/) (demo-agent).

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
baseline fails all 3 patterns (3 findings) and the protected agent passes all 3 (0 findings).

> Educational and synthetic: risk reduction is measured from deterministic mock traces,
> **not** a guarantee of real-world protection.

## Prior art (no uniqueness claims)

This space is not empty. The closest **combined** prior art is **BotGuard** (open-source
red-teaming + firewall for AI agents), and **garak**, **PyRIT**, and **promptfoo** are
established red-team / eval tools. For gateways, **Trylon Gateway** is the closest prior
art. The intended angle is narrow — **portable traces + attack graph + reproducible
replay + cross-agent contamination**, not "more attacks." Honest comparison:
[docs/competitors.md](docs/competitors.md).

## Documentation

- **[Harness](docs/harness.md)** — flagship: trace format, attack graph, test patterns, scorecard, replay.
- **[Problem–solution catalog](docs/problem-solution-catalog.md)** — problem → detection → mitigation → harness test → reference control → residual risk.
- **[Mission](docs/mission.md)** · **[Safe research rules](docs/research-rules.md)** — what this is for, and how to research safely.
- **Learning** — [agentic security basics](docs/learning/01-agentic-security-basics.md) · [data-boundary failures](docs/learning/02-data-boundary-failures.md).
- [Architecture](docs/architecture.md) — components and data flow.
- [Roadmap](docs/roadmap.md) — `v0.1` → `v1.0`.
- [Threat model](docs/threat-model.md) — what we cover, what we don't, OWASP mapping.
- [Competitors](docs/competitors.md) — landscape (verified, with sources).
- [API reference](docs/api-reference.md) — reference-gateway API.
- [Deployment](docs/deployment.md) · [Development](docs/development.md).

## Responsible use

The harness ships **sanitized defensive test content**. Use it only against systems you own
or are authorized to test. Payloads are sanitized; "sensitive" data in tests are synthetic
markers. Full policy: [SECURITY.md](SECURITY.md#responsible-use).

## Naming

Product / brand name is **TBD**. "Agentic Security Harness" is the working title. The
repository is `agentic-security-harness`; the gateway is the reference-defense component,
not the main product.

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — add a test pattern / target adapter / trace detector.
- [SECURITY.md](SECURITY.md) — responsible use + private vulnerability disclosure.

## License

[Apache-2.0](LICENSE).
