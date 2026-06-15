# Competitive landscape

> **Verification status:** verified **2026-06-12** against primary sources (inline
> footnotes). A point-in-time snapshot - features, licensing, and ownership change;
> re-check before relying on any single claim. Pricing is intentionally not quoted.
> This project does not claim to be the first or only tool in the category; it competes on
> trace portability, corpus clarity, operating-environment boundary measurement, and
> deterministic replay.

## How to read this

There are three relevant categories:

- **(A) Agentic security testing / red-teaming** - the closest active category.
  Several tools overlap our intent; we name them explicitly.
- **(B) Information-flow / label-propagation defenses** - the most important adjacent
  category for the project's current data-boundary wedge.
- **(C) Gateways / firewalls** - the context for the **reference defense** component only.

Tools we would **integrate** (wrap as detectors/oracles) are marked complementary.

---

## (A) Agentic security testing / red-teaming

> WARNING **Active category.** General red-team scanning and live LLM vulnerability testing are
> already well served by established tools. This project should not compete on "more
> attacks." Its narrower wedge is deterministic, local measurement of whether agentic
> operating-environment boundaries survive handoffs, memory writes, tool calls, approvals,
> audit replay, perception transcripts, provider hops, and delegated authority.

| Project | What it is (verified) | Relation | Source |
|---|---|---|---|
| **BotGuard** | OSS + platform: Scan + Shield + Fix for AI agents | Overlapping combined shape, but less important than mature scanner / benchmark ecosystems for our current wedge | [repo][botguard] |
| **Repello / ARTEMIS** | Commercial automated AI red-teaming; agentic systems, MCP, RAG, multi-agent; OWASP/NIST/MITRE ATLAS | Overlapping (commercial, closed) | [site][repello] |
| **garak** (NVIDIA) | OSS LLM vulnerability scanner; probes / detectors / generators (injection, jailbreak, leakage) | Established OSS; complementary (could supply probes) | [repo][garak] |
| **PyRIT** (Microsoft) | OSS GenAI red-team framework; multi-turn strategies (Crescendo/TAP/Skeleton Key), orchestration, scoring | Established OSS; strong overlap on multi-turn | [docs][pyrit] |
| **promptfoo** | OSS (MIT) test + red-team for prompts/agents/RAG; OWASP LLM Top 10; declarative YAML, CI/CD | Established OSS; strong overlap on agent testing | [repo][promptfoo] |
| **AgentDojo** | MIT benchmark environment for attacks and defenses for LLM agents | Academic benchmark adjacent to our trace format; useful interop target | [repo][agentdojo] |

> Four tools named in early discussion - *AgentSeal, PwnClaw, Inkog Red, OrchSec* - could
> **not** be verified (no product or repo found) and are **omitted** rather than asserted.

---

## (B) Information-flow / label-propagation defenses

This is the strategically important adjacent category. CaMeL and FIDES are defenses, not
benchmarks that ship this repository's trace format. Their existence validates the
importance of information-flow control and label propagation for agents; it does not remove
the need for a small framework-neutral conformance-style benchmark.

| Project | What it is (verified) | Relation | Source |
|---|---|---|---|
| **CaMeL** | Defense that separates control and data flows around an LLM agent and enforces security policies | Validates the data-flow / label-propagation direction; not a competing benchmark artifact | [paper][camel] |
| **FIDES** (Microsoft Agent Framework) | Information-flow control middleware; content carries integrity/confidentiality labels that propagate through tool calls and are checked before sensitive tools run | Strong validation of the label-propagation wedge; a defense that a neutral harness could test | [docs][fides] |

---

## (C) Gateways / firewalls (reference-defense context)

> **Closest gateway prior art - Trylon.** [Trylon Gateway][trylon] is an open-source,
> self-hosted, FastAPI LLM-firewall gateway (multi-provider proxy + guardrails). It is the
> closest prior art for **our reference-defense component** (not the harness).

| Project | What it is (verified) | Relation | Source |
|---|---|---|---|
| **Trylon Gateway** | OSS FastAPI LLM-firewall gateway; multi-provider proxy + guardrails (PII redaction, toxicity, leakage) | Closest **gateway** prior art | [repo][trylon] |
| **LiteLLM** | OSS proxy + SDK; routing/budgets/logging + **native guardrails framework** (Presidio, Lakera, Aporia, Pillar, PromptGuard, Bedrock, OpenAI moderation) | Gateway with real guardrails; routing-first vs security-first | [docs][litellm] |
| **Lakera (Guard)** | Commercial API; prompt injection/jailbreak, content moderation, PII/data-leakage | Commercial detector; could be an optional scanner | [docs][lakera] |
| **LLM Guard** (Protect AI) | OSS (MIT) scanner toolkit; 15 input + 20 output scanners | Complementary - integration target; owner now Palo Alto | [site][llmguard] |
| **Guardrails AI** | OSS framework + Hub (100+ validators) | Complementary - in-process; we can wrap validators | [repo][guardrails] |
| **NeMo Guardrails** (NVIDIA) | OSS (Apache-2.0); Colang DSL; 5 rail types | Complementary - in-process, dialog-centric | [repo][nemo] |
| **Microsoft Presidio** | OSS PII detect/anonymize (Analyzer + Anonymizer) | Complementary - a planned reference-gateway integration | [repo][presidio] |
| **Rebuff** | OSS prompt-injection detector | Reference only - repo **archived/read-only** | [repo][rebuff] |

### Ownership notes (verified)
- **Rebuff** - archived (read-only) by owner **2025-05-16**. [repo][rebuff]
- **Protect AI** (owns LLM Guard) - acquired by **Palo Alto Networks, completed 2025-07-22**. [source][protectai]
- **Prompt Security** - acquired by **SentinelOne**, completed **2025-09-05**. [source][promptsec]

---

## Positioning

The category is occupied. This project does **not** claim to be the first or only tool, and
does **not** compete on "more attacks." It competes on:

1. **portable, machine-readable failure traces** (replayable artifacts, not just reports);
2. **operating-environment boundary measurement** across data envelopes, memory, tools,
   handoffs, approvals, audit, perception transcripts, and provider boundaries;
3. **reproducible cross-target comparison** (replay the same traces against different
   targets / defenses, measure the delta);
4. a **practical attack graph** for agent / tool chains.

Planned differentiators include **cross-app contamination**, richer multi-agent workflows,
and full multimodal adapters. The current CLI release already includes synthetic perception
transcripts, but not live audio/image processing.

garak / PyRIT / promptfoo are established and overlap on red-teaming/eval; AgentDojo is a
strong benchmark adjacent; CaMeL and FIDES validate the information-flow / label-propagation
direction; Trylon is the closest gateway prior art for the reference defense. The public
positioning is **"a focused, open, trace-first conformance-style benchmark for agentic
operating-environment boundary failures,"** not a new category - and the wedge above should
be re-checked as these tools evolve.

[botguard]: https://github.com/botguardai/BotGuard
[repello]: https://repello.ai/
[garak]: https://github.com/NVIDIA/garak/
[pyrit]: https://microsoft.github.io/PyRIT/
[promptfoo]: https://github.com/promptfoo/promptfoo
[agentdojo]: https://github.com/ethz-spylab/agentdojo
[camel]: https://arxiv.org/abs/2503.18813
[fides]: https://learn.microsoft.com/en-us/agent-framework/agents/security
[trylon]: https://github.com/trylonai/gateway
[litellm]: https://docs.litellm.ai/docs/proxy/guardrails/quick_start
[lakera]: https://docs.lakera.ai/docs/prompt-defense
[llmguard]: https://protectai.com/llm-guard
[guardrails]: https://github.com/guardrails-ai/guardrails
[nemo]: https://github.com/NVIDIA-NeMo/Guardrails
[presidio]: https://github.com/microsoft/presidio
[rebuff]: https://github.com/protectai/rebuff
[protectai]: https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai
[promptsec]: https://www.sec.gov/Archives/edgar/data/1583708/000158370825000159/s-20251031.htm
