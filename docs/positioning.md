# Positioning

## Primary thesis

**Agentic Security Harness** is an opinionated, trace-first benchmark that measures
whether the **agentic operating-environment boundary** holds - whether data envelopes,
authority scopes, and trust boundaries survive agent handoffs, memory writes, tool calls,
and provider routing.

## One-liner

A trace-first defensive benchmark for agentic operating-environment boundary failures.

## What it is

- A **benchmark**, not a firewall, not a scanner, not a defense implementation.
- **Trace-first**: every run produces a portable, machine-readable failure trace.
- **Deterministic**: no network, no LLM, no provider calls. Same input = same output.
- **Baseline-vs-protected**: replay the same patterns against a vulnerable and a protected
  target; measure the delta.
- **Corpus-driven**: 22 deterministic seed patterns targeting boundary failure classes.

## What it is not

- Not a prompt-injection scanner (garak, PyRIT, promptfoo do that better).
- Not a defense implementation (CaMeL, FIDES do that).
- Not a production monitoring tool (ADR/Uber does that).
- Not a comprehensive security assessment. It measures specific boundary failure classes.

## Key design principles

1. **Perception is not permission.** Content arriving through OCR, ASR, HTML parse, or
   other perception channels is observed data, not user intent or system authority.

2. **Content is not authority.** Seeing data does not grant the right to act on it.
   Authority must be explicit, scoped, and auditable.

3. **Tool descriptions are not trusted policy.** Tool schemas, annotations, and metadata
   can drift or be deceptive. Provenance must be pinned and verified.

4. **Memory is not neutral storage.** Memory writes carry provenance, trust level, and TTL.
   Untrusted entries must not overwrite trusted ones.

5. **Audit trails must be tamper-evident.** Append-only, hash-chained, with decision
   context. An audit log that cannot explain why an action happened is not an audit log.

6. **No implicit authority for agent actions.** Every action must be traceable to an
   explicit grant: who issued it, to whom, for what purpose, with what scope, until when.

## Messaging angles

| Angle | When to use |
|---|---|
| **Agentic operating-environment boundary** | Primary thesis. Describes the architectural problem. |
| **No implicit authority** | For ambient_authority and capability_delegation patterns. |
| **Perception is not permission** | For multimodal/sensor-to-agent patterns. |
| **Trace-first benchmark** | For the format and methodology differentiator. |

## How it differs from competitors

| Project | What it does | What we do differently |
|---|---|---|
| garak / PyRIT / promptfoo | Prompt-injection scanning, red-teaming | We test boundary failures, not injection success |
| CaMeL / FIDES | Defense implementations | We benchmark what they defend |
| ADR (Uber) | Production monitoring | We do pre-production benchmark |
| AgentDojo | Tool-output injection benchmark | We test broader environment boundary |
| BotGuard | Agent security platform | We are a focused benchmark, not a platform |

## Complement, not competitor

CaMeL and FIDES implement boundary defenses. We measure whether those boundaries hold.
A team using an information-flow or capability-based defense could use this harness to
replay 22 deterministic seed patterns against its own target adapter and compare the result
with the local baseline/protected examples.
