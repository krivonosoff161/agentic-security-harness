# Standards mapping

> Last reviewed: 2026-06-12.
>
> Scope: implemented local corpus only. This page maps the seventeen deterministic seed
> patterns to external security frameworks at a coarse defensive level. The mapping helps
> reviewers understand what each pattern exercises; it does **not** imply certification,
> complete coverage, or real-world protection.

## Source frameworks

- **OWASP Top 10 for Agentic Applications 2026** - used for the current
  machine-readable `owasp_agentic` mapping in
  [`src/agentic_security_harness/corpus.py`](../src/agentic_security_harness/corpus.py).
- **OWASP Top 10 for LLM Applications 2025** - kept as a future mapping field
  (`owasp_llm`), not filled per pattern yet.
- **MITRE ATLAS** - kept as a future mapping field (`mitre_atlas`), not filled per
  pattern yet.
- **NIST AI RMF / GenAI profile** - future report-alignment target, not a per-pattern
  field yet.

## Implemented corpus mapping

| Pattern | Current ASI mapping | Why |
|---|---|---|
| `indirect_prompt_injection_via_tool_output` | ASI01, ASI02 | Untrusted tool output can redirect the agent goal and induce tool misuse. |
| `data_boundary_recipient_confusion` | ASI03, ASI07 | Recipient labels fail across identity, privilege, and handoff boundaries. |
| `memory_poisoning_sanitized` | ASI06 | Stored context is poisoned despite `can_store=false` and TTL expectations. |
| `data_boundary_classification_mutation` | ASI03, ASI06 | An untrusted source downgrades classification and contaminates later context. |
| `data_boundary_handoff_label_stripping` | ASI03, ASI07 | Data labels are lost during an agent handoff. |
| `tool_permission_abuse_sanitized` | ASI02, ASI03 | The agent calls a tool outside the data envelope's allowed purpose. |
| `provider_boundary_leakage_sanitized` | ASI03, ASI04 | Restricted data crosses a provider or supply-chain boundary despite `can_forward=false`. |
| `sleeping_prompt.delayed_activation` | ASI01, ASI06 | A stored dormant instruction redirects the agent on a later turn after provenance is lost. |
| `audit.spam_label_abuse` | ASI03 | An untrusted label tries to bypass an oversight control on labeled data. |
| `budget.loop_abuse` | ASI02 | Repeated tool/action steps run without budget or loop-guard enforcement. |
| `capability.delegation_chain_drift` | ASI02, ASI07 | Delegated authority expands across agent hops instead of preserving least privilege and chain provenance. |
| `mcp.tool_schema_deception` | ASI02, ASI06 | Changed tool metadata is trusted without schema provenance or hash checks. |
| `audit.hash_chain_tamper` | ASI03 | Edited audit entries are accepted instead of being rejected by integrity validation. |
| `perception_boundary.sensor_command_confusion` | ASI01 | Perception-channel content is treated as user intent or action authority instead of untrusted observed data. |
| `ambient_authority.environmental_privilege_escalation` | ASI02, ASI03 | A synthetic host capability is used without an explicit authority binding to the data envelope. |
| `approval_laundering.underjustified_confirmation` | ASI05 | A confirmation request omits data class, recipient, purpose, or risk context needed for informed approval. |
| `memory_governance.unscoped_memory_persistence` | ASI01, ASI03, ASI06 | Memory entries lose provenance, TTL, trust level, or conflict precedence across later reads. |

## Why the project focuses on label propagation

The crowded part of the market is live red-teaming and vulnerability scanning. This
repository intentionally focuses on a narrower measurement problem:

```text
Does a data envelope survive agent decisions, memory writes, tool calls,
provider routing, and handoffs?
```

That makes the project closer to a conformance-style benchmark for data-boundary and
information-flow behavior than to a general red-team scanner.

Recent defenses such as CaMeL and FIDES show that information-flow control and label
propagation are becoming mainstream design patterns for agent security. This harness does
not replace those defenses; it provides a small, deterministic way to measure whether an
agent stack preserves the relevant labels in known failure shapes.

## Mapping rules

- Prefer a small number of framework IDs per pattern.
- Use [research-roadmap.md](research-roadmap.md) for planned ideas; keep this page focused
  on implemented corpus mappings.
- Do not add MITRE ATLAS IDs until they are checked against the current official ATLAS
  technique pages.
- Do not add standards mappings for planned patterns before the pattern exists in code.
- If a mapping is debatable, keep it in docs first and leave the machine-readable manifest
  unchanged until reviewed.
- Treat mappings as reviewer navigation, not as proof of security.
