# Threat model

> **Agentic Security Harness.** This threat model covers both roles: the **harness** that *probes*
> these risks (recording each as a [trace](harness.md#exploit-trace-format)) and the
> **reference gateway** that *mitigates* them.
> The honest framing: **risk reduction, observability, and measurement — not 100%
> protection.** The harness only tests **mock / demo / authorized** targets (see
> [Responsible use](../SECURITY.md#responsible-use)).

## What we protect

- **Integrity** of the LLM interaction — resist hijacking via injection.
- **Confidentiality** of data crossing the boundary — PII, secrets, internal context.
- **Data boundary / recipient control** — that a data item's envelope (class, recipients,
  store / forward rules, TTL) survives agent handoffs, memory writes, tools, and provider
  routing.
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
[ untrusted: user input, sensors (audio/image), RAG docs, tool outputs ] ─► boundary 1 ─►
[ target under test: agent / tool chain / multi-agent workflow ]          ─► boundary 2 ─►
[ harness control plane: runner + traces + scorecard ]                    ─► boundary 3 ─►
[ optional defense: reference gateway ]  ─►  [ external: LLM provider ]
```

Boundary 1 is the critical one — everything to its left is hostile by default, **including
sensor inputs**, not just text. The harness drives only **mock / demo / authorized**
targets (boundary 2). The reference gateway, when present, sits between the target and the
provider — it is where envelope / redaction enforcement happens and what it minimizes
crossing to the provider.

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
- **Generating** adversarial / ultrasonic audio or other weaponized signals — out of
  scope by design. (The harness *does* test multimodal / sensor-to-agent injection, but
  only with **sanitized, pre-recorded fixtures** — see
  [harness.md](harness.md#multimodal-and-sensor-to-agent-injection).)
- Provider-side or model-weights compromise; training-time poisoning.
- Host / OS compromise; an insider with database access.
- Anything requiring the model to be *correct* — the project does not fix
  hallucination / misinformation, only flags policy-relevant signals.

## Residual risk

The harness **measures** these risks and the reference gateway **reduces** them; neither
eliminates them. Treat the reference gateway as **one defense-in-depth layer**. Detector
precision/recall is measured and published per release. Keep application-level authz and
least-privilege tool design regardless.

Two deliberate limitations to call out:

- **Audit integrity:** through v0.5 the audit log is normal append-only logging.
  **Tamper-evidence (hash chaining) arrives in v1.0.** Until then, audit integrity
  depends on the host's access controls.
- **No self-learning:** the harness does not adapt its own patterns or detectors at
  runtime. This is a deliberate trade — a self-mutating security tool is hard to audit.
  Feedback labels are collected for future, human-reviewed adaptive rules only.

## Why the system prompt is not a security boundary

The system prompt is sent **to the model** alongside user input and shapes behavior
probabilistically. A sufficiently adversarial input can coerce the model into ignoring,
revealing, or contradicting it (this is exactly LLM07 below). Therefore:

- **Never** put secrets, credentials, or access-control logic in the system prompt.
- The system prompt is **UX / behavior shaping**, not enforcement.
- Real boundaries are enforced **outside** the model: in the reference gateway's
  deterministic policy, in the app's authz, in tool permissions. The reference gateway can
  *detect* system-prompt leakage as a signal, but the correct fix is "don't rely on it being secret."

## Mapping to OWASP Top 10 for LLM Applications

> ✅ Verified against the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/):
> the LLM01–LLM10 codes and titles below match the official 2025 list (last checked 2026-06-08).

Each risk is **probed** by the harness as a reproducible trace and, where applicable,
**mitigated** by the reference gateway:

| OWASP LLM (2025) | Coverage — harness probes / reference gateway mitigates |
|---|---|
| **LLM01 Prompt Injection** | Deterministic + classifier scanners; quarantine for indirect injection. *(Primary focus.)* |
| **LLM02 Sensitive Information Disclosure** | PII/secret detection + `REDACT` inbound; leakage detection outbound. |
| **LLM03 Supply Chain** | Out of scope at runtime; we provide SBOM/dependency scanning for the project itself. |
| **LLM04 Data & Model Poisoning** | Out of scope (training-time); the project is runtime. |
| **LLM05 Improper Output Handling** | Response scanner + tool-call gating before side effects. |
| **LLM06 Excessive Agency** | Tool-call inspection + policy gate on dangerous arguments. *(Core feature.)* |
| **LLM07 System Prompt Leakage** | Detect leakage as a signal — **and** the design stance above (don't treat it as a boundary). |
| **LLM08 Vector & Embedding Weaknesses** | Partial — flag untrusted RAG content; not a vector-store fix. |
| **LLM09 Misinformation** | Out of scope (no factuality verification); the audit trail aids review. |
| **LLM10 Unbounded Consumption** | Token/cost budgets + rate limiting. *(Core feature.)* |
