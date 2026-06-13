# Agentic Operating-Environment Boundary Model

## The chain

Every agentic system processes information through a chain:

```
source content → parser/perception → model context → agent planner →
permission layer → tool/action → memory/audit → next cycle
```

Each link in this chain is a **boundary** where trust must be evaluated. The harness
tests whether these boundaries hold.

## Boundary layers

### 1. Data envelope boundary

**What it protects:** sensitivity labels, recipient restrictions, forwarding rules,
storage rules, TTL, and classification immutability.

**What the harness tests:** whether data-envelope fields survive agent handoffs, memory
writes, tool calls, and provider routing.

**Patterns:** `data_boundary_recipient_confusion`, `data_boundary_classification_mutation`,
`data_boundary_handoff_label_stripping`, `provider_boundary_leakage_sanitized`,
`memory_poisoning_sanitized`.

### 2. Authority scope boundary

**What it protects:** delegated authority, capability tokens, scope, purpose, TTL,
delegation depth, and issuer chain provenance.

**What the harness tests:** whether a delegated capability can expand beyond the original
grant, and whether ambient host authority is used without explicit envelope binding.

**Patterns:** `capability.delegation_chain_drift`,
`ambient_authority.environmental_privilege_escalation`.

### 3. Perception trust boundary

**What it protects:** the distinction between observed data and user intent or system
authority. Content from OCR, ASR, HTML parse, or other perception channels is data, not
commands.

**What the harness tests:** whether the agent acts on perception-channel content as if it
were a user instruction.

**Patterns:** `perception_boundary.sensor_command_confusion`.

### 4. Tool/schema honesty boundary

**What it protects:** tool-schema provenance, annotation trust, output shape validation,
and schema drift detection.

**What the harness tests:** whether the agent detects when a tool's schema, description,
or annotations change between inspection and use.

**Patterns:** `mcp.tool_schema_deception`, `tool_permission_abuse_sanitized`.

### 5. Memory governance boundary

**What it protects:** provenance tracking, trust-level precedence, TTL enforcement at
read, and deletion governance.

**What the harness tests:** whether untrusted memory entries can overwrite trusted ones,
whether TTL is enforced, and whether deletion accepts untrusted commands.

**Patterns:** `memory_governance.unscoped_memory_persistence`,
`sleeping_prompt.delayed_activation`.

### 6. Approval context boundary

**What it protects:** the informativeness of human-in-the-loop approval requests. A human
can only give informed consent if the approval request includes the data class, recipient,
purpose, and risk level.

**What the harness tests:** whether the agent's approval requests include full envelope
context or omit critical information.

**Patterns:** `approval_laundering.underjustified_confirmation`.

### 7. Audit integrity boundary

**What it protects:** the completeness and tamper-evidence of audit trails. An audit log
that cannot explain why an action happened is not an audit log.

**What the harness tests:** whether audit entries include decision context, whether the
hash chain is intact, and whether untrusted labels can suppress audit entries.

**Patterns:** `audit.hash_chain_tamper`, `audit.spam_label_abuse`.

### 8. Budget boundary

**What it protects:** resource exhaustion and loop abuse. A step budget / loop guard must
stop execution at the configured cap.

**What the harness tests:** whether the agent enforces per-run step budgets.

**Patterns:** `budget.loop_abuse`.

## Not yet covered (roadmap)

- **Cross-app contamination:** data/instructions from one app surface leaking into another.
- **Audit/context split:** decision context, action context, and audit context diverging.
- **Semantic policy compliance:** literal policy satisfaction while violating intent.
