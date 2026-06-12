# Competitive landscape

> **Verification status:** verified **2026-06-08** against primary sources (inline
> footnotes). A point-in-time snapshot — features, licensing, and ownership change;
> re-check before relying on any single claim. Pricing is intentionally not quoted.
> This project does not claim to be the first or only tool in the category; it competes on
> trace portability, corpus clarity, data-boundary measurement, and deterministic replay.

## How to read this

There are two relevant categories:

- **(A) Agentic security testing / red-teaming** — the project's **primary** category.
  It is **crowded and active**. Several tools overlap our intent; we name them honestly.
- **(B) Gateways / firewalls** — the context for the **reference defense** component only.

Tools we would **integrate** (wrap as detectors/oracles) are marked complementary.

---

## (A) Agentic security testing / red-teaming

> ⚠️ **Closest combined prior art — BotGuard.** [BotGuard][botguard] is an open-source
> red-teaming **+** firewall for AI agents: it scans an endpoint with 70+ OWASP-aligned
> scenarios and returns a **scored report with reproduction steps**, plus a real-time
> "Shield" firewall; it covers AI agents, MCP integrations, and RAG. That combination
> (harness + reference defense + MCP/RAG + reproducible findings) is **very close to this
> project's shape** and must be acknowledged up front.

| Project | What it is (verified) | Relation | Source |
|---|---|---|---|
| **BotGuard** | OSS + platform: Scan (70+ OWASP scenarios → scored report **with reproduction steps**) + Shield (real-time firewall) + Fix; covers agents, MCP, RAG; Py/Node SDKs | **Closest combined prior art** — overlaps harness *and* reference defense | [repo][botguard] |
| **Repello / ARTEMIS** | Commercial automated AI red-teaming; agentic systems, MCP, RAG, multi-agent; OWASP/NIST/MITRE ATLAS | Overlapping (commercial, closed) | [site][repello] |
| **garak** (NVIDIA) | OSS LLM vulnerability scanner; probes / detectors / generators (injection, jailbreak, leakage) | Established OSS; complementary (could supply probes) | [repo][garak] |
| **PyRIT** (Microsoft) | OSS GenAI red-team framework; multi-turn strategies (Crescendo/TAP/Skeleton Key), orchestration, scoring | Established OSS; strong overlap on multi-turn | [docs][pyrit] |
| **promptfoo** | OSS (MIT) test + red-team for prompts/agents/RAG; OWASP LLM Top 10; declarative YAML, CI/CD | Established OSS; strong overlap on agent testing | [repo][promptfoo] |

> Four tools named in early discussion — *AgentSeal, PwnClaw, Inkog Red, OrchSec* — could
> **not** be verified (no product or repo found) and are **omitted** rather than asserted.

---

## (B) Gateways / firewalls (reference-defense context)

> **Closest gateway prior art — Trylon.** [Trylon Gateway][trylon] is an open-source,
> self-hosted, FastAPI LLM-firewall gateway (multi-provider proxy + guardrails). It is the
> closest prior art for **our reference-defense component** (not the harness).

| Project | What it is (verified) | Relation | Source |
|---|---|---|---|
| **Trylon Gateway** | OSS FastAPI LLM-firewall gateway; multi-provider proxy + guardrails (PII redaction, toxicity, leakage) | Closest **gateway** prior art | [repo][trylon] |
| **LiteLLM** | OSS proxy + SDK; routing/budgets/logging + **native guardrails framework** (Presidio, Lakera, Aporia, Pillar, PromptGuard, Bedrock, OpenAI moderation) | Gateway with real guardrails; routing-first vs security-first | [docs][litellm] |
| **Lakera (Guard)** | Commercial API; prompt injection/jailbreak, content moderation, PII/data-leakage | Commercial detector; could be an optional scanner | [docs][lakera] |
| **LLM Guard** (Protect AI) | OSS (MIT) scanner toolkit; 15 input + 20 output scanners | Complementary — integration target; owner now Palo Alto | [site][llmguard] |
| **Guardrails AI** | OSS framework + Hub (100+ validators) | Complementary — in-process; we can wrap validators | [repo][guardrails] |
| **NeMo Guardrails** (NVIDIA) | OSS (Apache-2.0); Colang DSL; 5 rail types | Complementary — in-process, dialog-centric | [repo][nemo] |
| **Microsoft Presidio** | OSS PII detect/anonymize (Analyzer + Anonymizer) | Complementary - a planned reference-gateway integration | [repo][presidio] |
| **Rebuff** | OSS prompt-injection detector | Reference only — repo **archived/read-only** | [repo][rebuff] |

### Ownership notes (verified)
- **Rebuff** — archived (read-only) by owner **2025-05-16**. [repo][rebuff]
- **Protect AI** (owns LLM Guard) — acquired by **Palo Alto Networks, completed 2025-07-22**. [source][protectai]
- **Prompt Security** — SentinelOne announced **intent to acquire** **2025-08-05** (expected close Q3 FY2026; **not** confirmed completed). [source][promptsec]

---

## Positioning

The category is occupied. This project does **not** claim to be the first or only tool, and
does **not** compete on "more attacks." It competes on:

1. **portable, machine-readable failure traces** (replayable artifacts, not just reports);
2. a **practical attack graph** for agent / tool chains;
3. **reproducible cross-target comparison** (replay the same traces against different
   targets / defenses, measure the delta);
4. **cross-agent contamination** in multi-agent workflows;
5. **agentic data-boundary / recipient control** — whether sensitivity labels, recipients,
   and storage / forwarding rules survive agent handling (the lead wedge).

Planned differentiators include the **full signal path** including pre-LLM sensor channels
(for example audio → ASR). That track is not implemented in the current CLI release.

BotGuard is the closest combined prior art and is named honestly; garak / PyRIT / promptfoo
are established and overlap on red-teaming/eval; Trylon is the closest gateway prior art for
the reference defense. The honest framing is **"a focused, open, trace-first take,"** not a
new category — and the wedge above should be re-checked against these tools as they evolve.

[botguard]: https://github.com/botguardai/BotGuard
[repello]: https://repello.ai/
[garak]: https://github.com/NVIDIA/garak/
[pyrit]: https://microsoft.github.io/PyRIT/
[promptfoo]: https://github.com/promptfoo/promptfoo
[trylon]: https://github.com/trylonai/gateway
[litellm]: https://docs.litellm.ai/docs/proxy/guardrails/quick_start
[lakera]: https://docs.lakera.ai/docs/prompt-defense
[llmguard]: https://protectai.com/llm-guard
[guardrails]: https://github.com/guardrails-ai/guardrails
[nemo]: https://github.com/NVIDIA-NeMo/Guardrails
[presidio]: https://github.com/microsoft/presidio
[rebuff]: https://github.com/protectai/rebuff
[protectai]: https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai
[promptsec]: https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security-to-advance-genai-security/
