# Threat model

> **Agentic Security Harness.** This threat model covers two roles: the **current harness**
> that *probes* these risks (recording each as a [trace](harness.md#failure-trace-format))
> and the **planned reference gateway** that may later *mitigate* them as an optional
> defense target.
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
- **Accountability** — an audit trail of requests, findings, and decisions
  (future trace integrity via hash-chain hardening; see [Residual risk](#residual-risk)).
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
[ future optional defense: reference gateway ]  ─►  [ external: LLM provider ]
```

Boundary 1 is the critical one — everything to its left is hostile by default, **including
sensor inputs**, not just text. The harness drives only **mock / demo / authorized**
targets (boundary 2). The planned reference gateway, when implemented, would sit between
the target and the provider — it is the future place for envelope / redaction enforcement
and for minimizing what crosses to the provider.

## Attacks we aim to cover (with caveats)

- Direct prompt injection (known patterns; future classifier).
- Indirect / second-order injection (flag completions driven by untrusted content; quarantine).
- Encoding-based evasion: base64, zero-width Unicode, homoglyphs (normalizer + encoding scanner).
- PII / secret exfiltration outbound; secret / system-prompt leakage inbound.
- Dangerous tool calls (argument inspection + policy).
- Cost abuse (future reference gateway budgets).

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

The current harness **measures** these risks. The planned reference gateway is one future
place to **reduce** them, but neither role eliminates risk. Treat any gateway as one
defense-in-depth layer. Current validation checks artifact consistency and conservative
forbidden-marker patterns; detector precision/recall should be measured when detector
components ship. Keep application-level authz and least-privilege tool design regardless.

Two deliberate limitations to call out:

- **Audit integrity:** the current release records normal append-only traces.
  **Future trace integrity (tamper-evidence via hash chaining) is planned.** Until then,
  audit integrity depends on the host's access controls.
- **No self-learning:** the harness does not adapt its own patterns or detectors at
  runtime. This is a deliberate trade — a self-mutating security tool is hard to audit.
  Feedback labels are collected for future, human-reviewed adaptive rules only.

## Why the system prompt is not a security boundary

The system prompt is sent **to the model** alongside user input and shapes behavior
probabilistically. A sufficiently adversarial input can coerce the model into ignoring,
revealing, or contradicting it (this is exactly LLM07 below). Therefore:

- **Never** put secrets, credentials, or access-control logic in the system prompt.
- The system prompt is **UX / behavior shaping**, not enforcement.
- Real boundaries are enforced **outside** the model: in application authz, tool
  permissions, and future gateway policy. A gateway can *detect* system-prompt leakage as
  a signal, but the correct fix is "don't rely on it being secret."

## Mapping to OWASP Top 10 for LLM Applications

> ✅ Verified against the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/):
> the LLM01–LLM10 codes and titles below match the official 2025 list (last checked 2026-06-08).

Each risk is **probed** by the harness as a reproducible trace and, where applicable,
mapped to a planned reference-gateway mitigation:

| OWASP LLM (2025) | Coverage — current harness probes / planned gateway mitigates |
|---|---|
| **LLM01 Prompt Injection** | Current: deterministic indirect-injection pattern. Planned: classifier and quarantine for indirect injection. *(Primary focus.)* |
| **LLM02 Sensitive Information Disclosure** | Current: provider-boundary leakage and data-envelope patterns. Planned: PII/secret detection and `REDACT` controls. |
| **LLM03 Supply Chain** | Out of scope at runtime; use normal dependency review for this project. |
| **LLM04 Data & Model Poisoning** | Out of scope (training-time); the project is runtime. |
| **LLM05 Improper Output Handling** | Current: tool-permission abuse pattern. Planned: response scanner and tool-call gating before side effects. |
| **LLM06 Excessive Agency** | Current: tool-permission pattern and protected local control. Planned: broader policy gate on dangerous arguments. |
| **LLM07 System Prompt Leakage** | Current: design stance above (do not treat it as a boundary). Planned: leakage detection as a signal. |
| **LLM08 Vector & Embedding Weaknesses** | Partial future track: untrusted RAG content patterns; not a vector-store fix. |
| **LLM09 Misinformation** | Out of scope (no factuality verification); the audit trail aids review. |
| **LLM10 Unbounded Consumption** | Planned: token/cost budgets and rate limiting; not implemented in the current benchmark release. |
