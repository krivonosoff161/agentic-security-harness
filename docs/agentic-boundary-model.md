# Agentic Operating-Environment Boundary Model

This is the canonical protection / boundary model catalog for Agentic Security Harness.
The harness does not ask whether a model is generally "safe." It asks whether a declared
boundary invariant survives a concrete agentic workflow and whether the evidence is visible
in a trace.

```text
source content -> parser/perception -> model context -> agent planner ->
permission layer -> tool/action -> memory/audit -> next cycle
```

Every link is a boundary where trust, authority, provenance, and policy labels can be lost.
A **boundary model** names the invariant under test. A **protection model** names the
control that should preserve that invariant. The harness measures observed boundary
preservation; it does not certify complete protection.

For system shapes, see [evaluation-topologies.md](evaluation-topologies.md). For future
pattern selection, see [corpus-expansion-plan.md](corpus-expansion-plan.md).

## Boundary layers

| Boundary / protection model | What it protects | Current patterns | Missing situation families |
|---|---|---|---|
| Data envelope boundary | Sensitivity labels, recipient restrictions, forwarding/storage rules, TTL, and classification immutability. | `data_boundary_recipient_confusion`, `data_boundary_classification_mutation`, `data_boundary_handoff_label_stripping`, `provider_boundary_leakage_sanitized` | multi-hop recipient laundering, summary-based boundary loss, cross-provider label loss |
| Provenance / source trust | Whether content remains tagged as user input, tool output, retrieved data, memory, perception transcript, or model output. | `indirect_prompt_injection_via_tool_output`, `sleeping_prompt.delayed_activation`, `memory_governance.environment_injected_poisoning`, `indirect_instruction.multi_turn_escalation` | weak-model provenance, source-label loss across ecosystems, provenance-preserving summaries |
| Authority scope boundary | Delegated authority, capability token scope, purpose, TTL, issuer chain, and ambient authority binding. | `capability.delegation_chain_drift`, `ambient_authority.environmental_privilege_escalation` | temporal permission drift, receiver ignores signed/scope-bound handoff |
| Tool/schema honesty boundary | Tool-schema provenance, annotation trust, output validation, tool selection, and schema drift detection. | `tool_permission_abuse_sanitized`, `mcp.tool_schema_deception`, `mcp.tool_selection_manipulation` | tool output treated as trusted instruction by another model, live tool-host metadata changes |
| Memory governance boundary | Provenance, trust-level precedence, TTL enforcement, per-user scope, and deletion governance. | `memory_poisoning_sanitized`, `sleeping_prompt.delayed_activation`, `memory_governance.unscoped_memory_persistence`, `memory_governance.environment_injected_poisoning`, `memory_governance.unintentional_cross_user` | cross-agent memory rehydration, stale memory used as current authority |
| Provider boundary | Whether data may leave the local/runtime boundary for a provider or fallback route. | `provider_boundary_leakage_sanitized` | fallback loses policy envelope, cross-provider source label loss |
| Perception trust boundary | The distinction between observed data and user/system intent. OCR, ASR, HTML parse, and sensor transcripts are data, not commands. | `perception_boundary.sensor_command_confusion` | multi-channel perception disagreement, richer sanitized multimodal fixtures |
| Approval context boundary | Whether a human approval request contains enough context for informed consent. | `approval_laundering.underjustified_confirmation` | approval missing provenance, social-pressure approval framing |
| Audit integrity / completeness boundary | Append-only integrity, tamper evidence, audit presence, and decision context. | `audit.spam_label_abuse`, `audit.hash_chain_tamper` | action-audit divergence, missing policy/envelope context |
| Budget / recursion boundary | Step budgets, recursion depth, and bounded execution. | `budget.loop_abuse`, `budget.recursive_execution_amplification` | budget transfer across agents, fallback loops |
| Model trust asymmetry | Different trust levels for weak/local/cheap/filter/chief models in one workflow. | Not yet a seed pattern. | weak-to-strong escalation, cheap filter suppresses risky context |
| Cross-agent handoff trust | Data, authority, provenance, memory, and scope across Agent A -> Agent B. | Partial: `data_boundary_handoff_label_stripping`, `capability.delegation_chain_drift`, exercised by the local `toy-multi-agent` coordinator/worker adapter | cross-agent memory rehydration, receiver ignores signature/scope |
| Recovery path / escalation | What happens when a trust gate, provider, adapter, or validation step fails. | Partial through explicit errors and external `inconclusive`; no seed pattern yet. | failed trust gate with no recovery path, opaque final denial |

## How to read current coverage

- The current local corpus has 22 deterministic seed patterns; [corpus.md](corpus.md) is
  the canonical implemented pattern matrix.
- Some boundary models are represented by multiple current patterns. For example, memory
  governance includes direct memory poisoning, delayed activation, environment-injected
  poisoning, unscoped persistence, and cross-user leakage.
- Some boundary models are only partial. Cross-agent handoff is currently represented by
  label stripping and capability delegation drift through a local toy coordinator/worker
  adapter, not a live multi-agent runtime.
- `adapter_metadata` exists as a remediation/control-family concept, but it is not yet a
  seed pattern. It should become evidence metadata for future non-synthetic adapters before
  it becomes a finding family.

## Expansion rule

Do not expand by brute-force combinations. A new situation should enter the corpus only if
it adds a new invariant, topology, or evidence requirement.

Use:

```text
boundary invariant -> representative topology -> deterministic trace evidence
```

Avoid:

```text
model x provider x prompt wording x agent role x memory mode x time window
```

The bounded backlog is maintained in [corpus-expansion-plan.md](corpus-expansion-plan.md).

## Not yet covered

- Full cross-app workflow contamination beyond the local label/scope handoff slices.
- Native provider/agent-host adapters that execute tools.
- Cross-provider chain-of-custody across mixed model ecosystems.
- Model trust asymmetry in cheap-to-chief or filter-to-chief routing.
- Recovery-path failures as first-class corpus patterns.
- Semantic policy compliance beyond deterministic envelope/invariant checks.
