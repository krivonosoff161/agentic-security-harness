# Threat model

> Product name TBD; referred to here as "the gateway".
> The honest framing: **risk reduction, observability, policy enforcement, quarantine,
> audit, and cost control — not 100% protection.**

## What we protect

- **Integrity** of the LLM interaction — resist hijacking via injection.
- **Confidentiality** of data crossing the boundary — PII, secrets, internal context.
- **Safety** of agent actions — gate dangerous tool calls before side effects.
- **Accountability** — a comprehensive audit trail of requests, findings, and decisions
  (hash-chain integrity hardening lands in v1.0; see [Residual risk](#residual-risk)).
- **Cost** — token/spend budgets.

## Who / what we protect against

- **Untrusted input content** reaching the model — including **indirect** injection
  from RAG documents, web pages, emails, and tool outputs (the dangerous, underrated case).
- **A manipulated model output** triggering side effects or leaking data.
- **Careless or abusive callers** — accidental PII submission, cost blowups.

Out of scope: a malicious operator with DB access, OS-level host compromise, or a
malicious LLM provider. These are different trust domains.

## Trust boundaries

```
[ untrusted: user input, RAG docs, web/tool content ] ─► boundary 1 ─►
[ semi-trusted: the app/agent calling the gateway ]   ─► boundary 2 ─►
[ TRUSTED control plane: gateway + policy + audit ]   ─► boundary 3 ─►
[ external: LLM provider ]
```

Boundary 1 is the critical one — everything to its left is hostile by default, and the
scanners live there. At boundary 3 the gateway minimizes what crosses (redaction) and
inspects what comes back.

## Attacks we aim to cover (with caveats)

- Direct prompt injection (known patterns; classifier from v0.5).
- Indirect / second-order injection (flag completions driven by untrusted content; quarantine).
- Encoding-based evasion: base64, zero-width Unicode, homoglyphs (normalizer + encoding scanner).
- PII / secret exfiltration outbound; secret / system-prompt leakage inbound.
- Dangerous tool calls (argument inspection + policy).
- Cost abuse (budgets, from v0.4).

## Attacks we do NOT cover

- Novel / obfuscated injections that defeat current detectors — **false negatives are expected.**
- Semantic attacks that are individually benign but harmful in aggregate.
- Multimodal injections (image/audio) until those scanners exist.
- Provider-side or model-weights compromise; training-time poisoning.
- Host / OS compromise; an insider with database access.
- Anything requiring the model to be *correct* — the gateway does not fix
  hallucination / misinformation, only flags policy-relevant signals.

## Residual risk

The gateway reduces the probability and blast radius of these threats; it does not
eliminate them. It is **one defense-in-depth layer**. Detector precision/recall is
measured and published per release, and policy should be tuned to the org's risk
appetite. Keep application-level authz and least-privilege tool design regardless.

Two deliberate limitations to call out:

- **Audit integrity:** through v0.5 the audit log is normal append-only logging.
  **Tamper-evidence (hash chaining) arrives in v1.0.** Until then, audit integrity
  depends on the host's access controls.
- **No self-learning:** the gateway does not adapt its own rules at runtime. This is a
  deliberate trade — a self-mutating security control is hard to audit. Feedback labels
  are collected for future, human-reviewed adaptive rules only.

## Why the system prompt is not a security boundary

The system prompt is sent **to the model** alongside user input and shapes behavior
probabilistically. A sufficiently adversarial input can coerce the model into ignoring,
revealing, or contradicting it (this is exactly LLM07 below). Therefore:

- **Never** put secrets, credentials, or access-control logic in the system prompt.
- The system prompt is **UX / behavior shaping**, not enforcement.
- Real boundaries are enforced **outside** the model: in the gateway's deterministic
  policy, in the app's authz, in tool permissions. The gateway can *detect*
  system-prompt leakage as a signal, but the correct fix is "don't rely on it being secret."

## Mapping to OWASP Top 10 for LLM Applications

> ✅ Verified against the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/):
> the LLM01–LLM10 codes and titles below match the official 2025 list (last checked 2026-06-08).

| OWASP LLM (2025) | Gateway coverage |
|---|---|
| **LLM01 Prompt Injection** | Deterministic + classifier scanners; quarantine for indirect injection. *(Primary focus.)* |
| **LLM02 Sensitive Information Disclosure** | PII/secret detection + `REDACT` inbound; leakage detection outbound. |
| **LLM03 Supply Chain** | Out of scope at runtime; we provide SBOM/dependency scanning for the gateway itself. |
| **LLM04 Data & Model Poisoning** | Out of scope (training-time); the gateway is runtime. |
| **LLM05 Improper Output Handling** | Response scanner + tool-call gating before side effects. |
| **LLM06 Excessive Agency** | Tool-call inspection + policy gate on dangerous arguments. *(Core feature.)* |
| **LLM07 System Prompt Leakage** | Detect leakage as a signal — **and** the design stance above (don't treat it as a boundary). |
| **LLM08 Vector & Embedding Weaknesses** | Partial — flag untrusted RAG content; not a vector-store fix. |
| **LLM09 Misinformation** | Out of scope (no factuality verification); the audit trail aids review. |
| **LLM10 Unbounded Consumption** | Token/cost budgets + rate limiting. *(Core feature.)* |
