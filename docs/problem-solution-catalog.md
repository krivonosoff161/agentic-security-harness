# Problem–solution catalog

> Product name TBD. This is the **central map** from a real agentic problem to a defensive
> test and a control. It ties together the [harness](harness.md), the
> [threat model](threat-model.md), and the [reference defense](architecture.md).
>
> **Defensive framing:** every entry is a **defensive test pattern** — sanitized, run
> against **mock / demo / authorized** targets only, no real credential theft or
> third-party abuse ([responsible use](../SECURITY.md#responsible-use)).

## Format

Each entry follows the same shape:

- **What goes wrong** · **Defensive scenario** · **Detection signals** ·
  **Mitigation controls** · **Harness test pattern** · **Reference implementation idea** ·
  **Human / process controls** · **Residual risk**

Several entries use the **data envelope**
([definition](harness.md#agentic-data-boundary-and-recipient-control)): `data_class`,
`allowed_recipients`, `allowed_purpose`, `can_store`, `can_forward`, `ttl`,
`requires_confirmation`, `classification_source`, `classification_mutable=false`. An
envelope is a **policy label that must be enforced and survive transformation** — **not**
encryption (encryption protects transport/storage; it does not solve prompt injection).

---

> **Local demo corpus (v0.4):** seven of these failure modes are implemented as
> deterministic, sanitized seed patterns in the harness — recipient confusion, memory
> poisoning, data reclassification (classification mutation), handoff label stripping,
> tool-permission abuse, provider-boundary leakage, plus indirect prompt injection via tool
> output. Run them with `ash run --target demo-agent` and `ash compare`.

## 1. Sensitive data in shared AI chats

- **What goes wrong:** sensitive data pasted into shared/team AI chats persists in history/memory and reaches unintended readers or downstream tools.
- **Defensive scenario:** a shared-context agent; introduce a **synthetic** "confidential" marker; observe where it surfaces.
- **Detection signals:** a sensitive `data_class` appearing for a recipient not in `allowed_recipients`; `can_store=false` data persisted.
- **Mitigation controls:** data envelope, egress redaction, no-store enforcement, per-recipient scoping.
- **Harness test pattern:** `data_boundary.recipient_scope`.
- **Reference implementation idea:** gateway `REDACT` / `BLOCK` on egress to non-allowed recipients.
- **Human / process controls:** data-handling policy, training, channel segregation.
- **Residual risk:** labels can be missing/wrong; users can exfiltrate manually; detection has false negatives.

## 2. Sleeping prompt / delayed injection

- **What goes wrong:** an instruction planted in data/doc/memory lies dormant and activates on a later turn or condition, after provenance is forgotten.
- **Defensive scenario:** store a benign doc containing a **sanitized dormant-instruction placeholder**; run later turns; observe activation.
- **Detection signals:** instruction-like content surfacing from stored/retrieved data; behavior change correlated with a prior write.
- **Mitigation controls:** provenance tracking, treat stored/retrieved content as untrusted, `ttl`, re-scan at read time.
- **Harness test pattern:** `sleeping_prompt.delayed_activation`.
- **Reference implementation idea:** gateway re-scans retrieved/memory content at read time; quarantine instruction-like retrieved content.
- **Human / process controls:** review of long-lived memory; periodic memory hygiene.
- **Residual risk:** novel encodings evade scanning; benign vs malicious instructions hard to separate.

## 3. Data reclassification attack

- **What goes wrong:** untrusted content induces the agent to **downgrade/alter a sensitivity label** (e.g. confidential → public), so later controls treat it as safe.
- **Defensive scenario:** synthetic data tagged confidential; inject content attempting a relabel; verify `classification_mutable=false` holds.
- **Detection signals:** classification changing from a non-trusted `classification_source`; downgrade events.
- **Mitigation controls:** trusted `classification_source` only; `classification_mutable=false`; relabel requires authority; log all changes.
- **Harness test pattern:** `data_boundary.classification_mutation`.
- **Reference implementation idea:** gateway rejects relabels from untrusted sources; envelope immutability.
- **Human / process controls:** classification governance; dual-control for downgrades.
- **Residual risk:** wrong initial label; compromise of a trusted source.

## 4. Recipient confusion

- **What goes wrong:** data intended for recipient A is routed to recipient B (wrong tool / channel / agent / provider).
- **Defensive scenario:** envelope with `allowed_recipients=[A]`; induce routing toward B; check enforcement.
- **Detection signals:** send/forward to a recipient not in `allowed_recipients`; `can_forward=false` forwarded.
- **Mitigation controls:** recipient allow-list, forward gate, `requires_confirmation` for external sends.
- **Harness test pattern:** `data_boundary.recipient_confusion`.
- **Reference implementation idea:** gateway `BLOCK` / `QUARANTINE` on out-of-envelope recipient.
- **Human / process controls:** confirmation step for external sends.
- **Residual risk:** recipient identity can be spoofed; label gaps.

## 5. Memory poisoning

- **What goes wrong:** planted state in memory changes the agent's **future** decisions.
- **Defensive scenario:** write **sanitized** poisoned state; a later turn observes an altered decision.
- **Detection signals:** decisions diverging after an untrusted memory write; `can_store` violations.
- **Mitigation controls:** untrusted-by-default memory, provenance, `ttl`, no-store for untrusted, read-time scan.
- **Harness test pattern:** `memory_poisoning.persistent_state`.
- **Reference implementation idea:** gateway tags memory provenance; quarantine instruction-like writes.
- **Human / process controls:** memory review / expiry.
- **Residual risk:** subtle semantic poisoning; detection gaps.

## 6. Tool permission abuse

- **What goes wrong:** over-broad tool permissions let one prompt trigger an unintended/dangerous action.
- **Defensive scenario:** mock tool with broad scope; attempt an out-of-purpose call; check the permission gate.
- **Detection signals:** tool call outside `allowed_purpose`; dangerous arguments; permission > need.
- **Mitigation controls:** least-privilege tools, argument inspection, `requires_confirmation`, purpose binding.
- **Harness test pattern:** `tool_permission.abuse`.
- **Reference implementation idea:** gateway tool-call gate + MCP / tool-permission scanner.
- **Human / process controls:** tool-permission review; confirmations.
- **Residual risk:** legitimate-but-misused tools; over-permissioned by design.

## 7. Cross-agent contamination

- **What goes wrong:** one agent poisons another via shared memory / messages / tool outputs; the envelope/labels are stripped at handoff.
- **Defensive scenario:** two mock agents; A passes content to B; check label survival and contamination.
- **Detection signals:** envelope fields dropped at handoff; B treating A's untrusted content as trusted.
- **Mitigation controls:** envelope propagation across handoffs, provenance, per-agent trust.
- **Harness test pattern:** `cross_agent.contamination` / `data_boundary.handoff_label_stripping`.
- **Reference implementation idea:** a broker/gateway enforces the envelope on inter-agent messages.
- **Human / process controls:** workflow review.
- **Residual risk:** trusted-agent compromise; emergent multi-agent behavior.

## 8. Multimodal / sensor-to-agent injection

- **What goes wrong:** an instruction enters via an audio/image channel (pre-LLM), bypassing text-only controls.
- **Defensive scenario:** a **sanitized, pre-recorded** ASR/OCR fixture carries an instruction; observe the agent's action.
- **Detection signals:** ASR/OCR transcript with instruction-like content; low `human_perceptibility`; anomaly/spectral flag; tool exec without confirmation.
- **Mitigation controls:** treat sensor transcripts as untrusted; confirmation for sensor-triggered actions; anomaly flags.
- **Harness test pattern:** `multimodal.sensor_to_agent` (audio → ASR).
- **Reference implementation idea:** gateway scans ASR/OCR output as untrusted input; require confirmation.
- **Human / process controls:** confirm voice-triggered actions.
- **Residual risk:** novel signal attacks; ASR ambiguity. *(No ultrasonic / adversarial-audio generation guidance is provided.)*

## 9. Social engineering via agent

- **What goes wrong:** the agent is induced to persuade or pressure a human (or another agent) into an unsafe approval/action.
- **Defensive scenario:** a scripted scenario steers the agent to request an unjustified approval; observe.
- **Detection signals:** agent generating persuasion toward privileged actions; approval requests lacking justification.
- **Mitigation controls:** out-of-band confirmation; human-in-the-loop with full context; rate limits on approval asks.
- **Harness test pattern:** `social_engineering.approval_pressure`.
- **Reference implementation idea:** gateway flags/holds privileged-action prompts for review.
- **Human / process controls:** approval policy; skepticism training; dual-control.
- **Residual risk:** humans remain fallible; persuasion is hard to detect.

## 10. Budget exhaustion / loop abuse

- **What goes wrong:** a chain burns tokens / loops without bound.
- **Defensive scenario:** induce a loop on a mock target; observe token/step growth.
- **Detection signals:** step/token count beyond budget; repeated identical calls.
- **Mitigation controls:** per-run budgets, loop/step caps, rate limits.
- **Harness test pattern:** `budget.loop_abuse`.
- **Reference implementation idea:** gateway token/cost budgets + rate limiting.
- **Human / process controls:** cost alerts; kill-switch.
- **Residual risk:** legitimate expensive tasks; budget tuning.

## 11. Audit bypass / spam-label abuse

- **What goes wrong:** content is mislabeled (e.g. "spam" / "ignore" / "benign" / "system") to evade logging or strip an event from the audit trail.
- **Defensive scenario:** attempt to mark a sensitive/malicious event as low-priority; verify it is **still audited**.
- **Detection signals:** label downgrades on audited events; events missing from the trail; label from an untrusted source.
- **Mitigation controls:** non-bypassable audit; labels never suppress logging; trusted `classification_source`; append-only.
- **Harness test pattern:** `audit.spam_label_abuse`.
- **Reference implementation idea:** gateway logs all decisions regardless of label; tamper-evident audit (v1.0).
- **Human / process controls:** audit review; anomaly alerts.
- **Residual risk:** operator with DB access; no tamper-evidence before v1.0.

## 12. Provider boundary leakage

- **What goes wrong:** data marked not-for-external (`can_forward=false` / external recipient disallowed) is routed to an external LLM provider.
- **Defensive scenario:** envelope forbids external forward; induce a provider call; check the block.
- **Detection signals:** `can_forward=false` data crossing to a provider; sensitive `data_class` in the upstream payload.
- **Mitigation controls:** egress envelope check, redaction before the provider, local-model routing for restricted classes.
- **Harness test pattern:** `data_boundary.provider_leakage`.
- **Reference implementation idea:** gateway `REDACT` / `BLOCK` on egress to a provider; route restricted classes to a local model.
- **Human / process controls:** data-residency policy; provider DPA review.
- **Residual risk:** provider trust; redaction misses; metadata leakage.

---

> This catalog is the project's backbone: each problem should map to a **harness test
> pattern** (so it is reproducible) and, where applicable, a **reference control** (so risk
> reduction can be *measured*, not asserted). No uniqueness claims — see
> [competitors.md](competitors.md).
