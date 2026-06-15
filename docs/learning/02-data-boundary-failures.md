# Data-boundary failures (educational)

> Educational, sanitized, **mock-only**. Synthetic data; authorized targets only. See the
> [safe research rules](../research-rules.md).

The data-boundary / recipient-control wedge asks one question: **do a data item's rules
survive the agent's internal handling+** Five common ways they do not - each with a safe,
mock-only test idea, a detection signal, and a mitigation.

## 1. A user pastes sensitive company data into an AI assistant
- **Problem:** sensitive data entered into a shared/assistant context persists and reaches
  unintended readers or tools.
- **Safe mock test idea:** seed a **synthetic** "confidential" marker into a mock assistant;
  observe whether it surfaces outside the allowed recipients.
- **Detection signal:** a sensitive `data_class` appears for a recipient not in
  `allowed_recipients`; `can_store=false` data is persisted.
- **Mitigation:** data envelope + egress redaction + per-recipient scoping.

## 2. A sleeping instruction changes priority / classification
- **Problem:** content stored earlier carries an instruction that later alters how data is
  classified or prioritized.
- **Safe mock test idea:** store a benign doc containing a **sanitized placeholder**; on a
  later mock turn, check whether the classification changed.
- **Detection signal:** classification changes from a non-trusted `classification_source`;
  a downgrade event.
- **Mitigation:** `classification_mutable=false`; only a trusted source may relabel; log changes.

## 3. A handoff strips recipient labels
- **Problem:** when one agent hands data to another, the envelope/labels are dropped, so the
  receiver treats restricted data as unrestricted.
- **Safe mock test idea:** pass a synthetic labelled item between two mock agents; check that
  the envelope survives the handoff.
- **Detection signal:** envelope fields missing after a handoff; the receiver acts outside
  `allowed_purpose`.
- **Mitigation:** propagate the envelope across handoffs; per-agent trust.

## 4. Memory keeps data despite no-store / TTL
- **Problem:** data marked `can_store=false` or past its `ttl` is retained and influences
  later turns.
- **Safe mock test idea:** write a synthetic `can_store=false` item to mock memory; verify it
  is not retained or used later.
- **Detection signal:** a `can_store` / `ttl` violation; decisions change after an untrusted write.
- **Mitigation:** enforce `can_store` and `ttl`; treat memory as untrusted; re-check at read.

## 5. Provider / tool routing violates allowed recipient / purpose
- **Problem:** data marked not-for-external is routed to an external provider or tool.
- **Safe mock test idea:** mark a synthetic item `can_forward=false`; induce a **mock**
  provider call; confirm it is blocked.
- **Detection signal:** `can_forward=false` data crosses to a provider/tool; a restricted
  `data_class` appears in an outbound payload.
- **Mitigation:** egress envelope check; redact before routing; keep restricted classes local.

---

Each scenario maps to a harness **test pattern** and, where applicable, a **reference-defense
control** - see the [problem-solution catalog](../problem-solution-catalog.md).
