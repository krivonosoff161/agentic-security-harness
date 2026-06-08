# Agentic Security Harness

> **Repository:** `agentic-security-harness` · **Product name:** _TBD_

**An open-source harness for reproducing and measuring agentic exploit chains through
portable traces, attack graphs, and security scorecards.**

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

## Status

**Pre-release — building `v0.1`.** `v0.1` is the harness core: an **attack corpus +
trace schema + a simple runner + a scorecard**, run against a **mock agent**. The
reference gateway and real target adapters come later. See [docs/roadmap.md](docs/roadmap.md).

![status](https://img.shields.io/badge/status-pre--release-orange)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)

## Core capabilities

- **Portable exploit traces** — machine-readable, replayable records of an attack chain.
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

## Quickstart (conceptual, `v0.1` target)

> No CLI is published yet. This describes the intended flow.

1. Point the harness at a **mock agent** target.
2. It runs the defensive test patterns and emits one **trace** per chain.
3. It derives a **scorecard** from the traces.
4. Put the target behind the **reference gateway** and **replay** the same traces to
   compare scorecards — the measured risk-reduction delta.

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
- [Architecture](docs/architecture.md) — components and data flow.
- [Roadmap](docs/roadmap.md) — `v0.1` → `v1.0`.
- [Threat model](docs/threat-model.md) — what we cover, what we don't, OWASP mapping.
- [Competitors](docs/competitors.md) — landscape (verified, with sources).
- [API reference](docs/api-reference.md) — reference-gateway API.
- [Deployment](docs/deployment.md) · [Development](docs/development.md).

## Responsible use

The harness ships offensive **test content** for defensive purposes. Use it only against
systems you own or are authorized to test. Payloads are sanitized; "sensitive" data in
tests are synthetic markers. Full policy: [SECURITY.md](SECURITY.md#responsible-use).

## Naming

Product / brand name is **TBD**. "Agentic Security Harness" is the working title. The
repository is `agentic-security-harness`; the gateway is the reference-defense component,
not the main product.

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — add a test pattern / target adapter / trace detector.
- [SECURITY.md](SECURITY.md) — responsible use + private vulnerability disclosure.

## License

[Apache-2.0](LICENSE).
