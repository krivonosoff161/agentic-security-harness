# Competitive landscape

> **Verification status:** partially verified — **last reviewed: 2026-06-08.**
> Rebuff, Protect AI, Prompt Security, and the OWASP numbering are verified with primary
> sources (see the table and link footnotes). Trylon, Lakera, NeMo Guardrails, and
> Presidio specifics are still pending.
> This document must be re-checked against each project's live state (features, license,
> ownership, pricing) before it is relied on. Claims that are not directly verified are
> marked **needs verification**. Do not present anything here as fact until confirmed
> with a primary source.

## How to read this

The goal is honest positioning, not marketing. Where this project's scope overlaps a
tool, that tool is "complementary" (an integration target) or "competing" (same problem,
same form factor). Several listed tools are things this gateway would **integrate**, not
displace.

## Landscape

| Project | Form factor | Focus (as understood) | Relation | Verification |
|---|---|---|---|---|
| **Rebuff** | OSS library/SDK | Prompt-injection detection (heuristics, LLM, vector DB of known attacks, canary tokens) | Reference only — the concept is complementary, but the repo is **archived/read-only**, so not a live dependency | ✅ Archived by owner 2025-05-16 ([repo][rebuff]) |
| **Trylon Gateway** | Vendor (gateway/guardrails) | LLM guardrails | Unclear overlap | **Low confidence — needs verification of scope/features before any comparison** |
| **Guardrails AI** | OSS Python framework + Hub | In-process validators ("guards") on input/output | Complementary — in-process, app-embedded; this gateway is the network/enforcement layer and can wrap validators | Confirm current API/Hub details |
| **LiteLLM** | OSS proxy + SDK | Unify many providers; routing, logging, budgets; some guardrail hooks | Closest *infrastructural* analog (an LLM gateway), but security is **not** its primary lens — routing/cost/observability is | Confirm current guardrail capabilities |
| **Lakera (Guard)** | Commercial SaaS/API | Prompt-injection & content moderation API; red-teaming | Commercial, API-based; could be called as an optional scanner | Confirm product scope/pricing |
| **Protect AI** | Vendor; OSS pieces (LLM Guard, Rebuff) | AI security platform | LLM Guard is an OSS scanner toolkit we can integrate (note the ownership change) | ✅ Acquisition by Palo Alto Networks **completed 2025-07-22** ([source][protectai]) |
| **Prompt Security** | Commercial | Enterprise GenAI security gateway/proxy | Architecturally similar (proxy), but closed-source | ⚠️ SentinelOne announced **intent to acquire** 2025-08-05 (expected close Q3 FY2026; **not** confirmed completed) ([source][promptsec]) |
| **Microsoft Presidio** | OSS library | PII detection / anonymization | Complementary — we **integrate** it (optional `[pii]` extra), not compete | Confirm current detector coverage |

Also worth naming when this is finalized: **NVIDIA NeMo Guardrails** (OSS, in-process,
dialog rails) and **Protect AI LLM Guard** (OSS scanner set) — both complementary
integration targets, not competitors. **Both need verification.**

## Positioning

The intended wedge: **open-source + self-hosted + _gateway_ form factor + first-class
quarantine, audit, and cost control.**

- Commercial gateways (e.g. Prompt Security, Lakera) are closed-source.
- The OSS tools (Guardrails AI, NeMo Guardrails, LLM Guard, Rebuff, Presidio) are mostly
  in-process libraries or single-purpose detectors.
- The OSS infra gateway (LiteLLM) is not security-first.

That intersection — an open, self-hosted, security-first gateway with quarantine and
audit — is the gap this project targets. **This positioning claim itself depends on the
verifications above; revisit it whenever the landscape shifts.**

[rebuff]: https://github.com/protectai/rebuff
[protectai]: https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai
[promptsec]: https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security-to-advance-genai-security/
