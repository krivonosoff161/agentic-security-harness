# Corpus expansion plan

This plan keeps corpus growth controlled. Agentic systems create a combinatorial space of
models, tools, memory states, providers, agents, time windows, and approval loops. The
project does **not** try to enumerate that full space.

The rule is:

```text
new boundary invariant -> representative topology -> deterministic pattern -> trace evidence
```

Add a new pattern only when it probes a new invariant or a materially new failure shape.
Do not add a pattern just because the provider, model name, prompt wording, or framework
changed.

## Selection method

1. Define the protection/boundary model first.
2. State the invariant that should survive.
3. Pick the smallest topology that can break that invariant.
4. Write one canonical baseline pattern.
5. Add at most 2-4 scenario variants when they test different dimensions.
6. Prefer pairwise / representative coverage over full cross-product expansion.
7. Keep scoring deterministic; model-judged semantics require deterministic fallback.
8. Record residual risk and what is intentionally not covered.

Accepted candidate shape:

```text
problem -> defensive scenario -> expected vulnerable behavior -> detection signal
-> mitigation -> harness test -> residual risk
```

## Candidate backlog

| Protection / boundary model | Situation family | Proposed pattern id | Topology needed | Safe behavior | Failure condition | Evidence artifact | Priority | Status | Rationale |
|---|---|---|---|---|---|---|---|---|---|
| Cross-surface provenance | App-surface contamination | `cross_app.data_instruction_contamination` | Cross-app / multi-surface local target | Current surface rejects instructions sourced from another surface unless explicitly authorized. | Surface B acts on content from Surface A without provenance and purpose match. | Trace with source surface, current surface, envelope, decision. | P1 | Planned | Already identified in research roadmap; fills cross-app gap. |
| Audit completeness | Action-audit divergence | `audit_context_split.action_audit_divergence` | Local deterministic target with audit layer | Audit records action, decision context, envelope, and policy rule. | Action is logged without the why, envelope, or policy basis. | Trace plus audit entry with missing context marker. | P1 | Planned | Current audit checks integrity/suppression, not context completeness. |
| Semantic policy invariant | Letter-vs-spirit policy gap | `semantic.policy_letter_vs_spirit` | Local deterministic target with narrow invariant checker | Restricted content is not reconstructed, transformed, or enumerated for non-recipients. | Target satisfies literal wording while violating reconstruction/minimization invariant. | Deterministic invariant check in trace, not model-only scoring. | P1 | Planned | Expands beyond explicit envelope fields without open-ended model judging. |
| Data boundary | Multi-hop recipient laundering | `data_boundary.multi_hop_recipient_laundering` | Multi-agent handoff | Recipient allow-list survives A -> B -> C routing. | Data reaches C through B even though C was never allowed. | Before/after envelope across each hop. | P1 | Planned | Deepens existing recipient/handoff coverage. |
| Data boundary | Summary-based boundary loss | `data_boundary.summary_boundary_loss` | Agent plus summarizer / model chain | Summaries retain envelope and recipient/purpose limits. | Summary is treated as unrestricted because original labels are stripped. | Trace links source item, summary, inherited envelope, receiver decision. | P1 | Planned | Common real workflow; not covered by current label-stripping pattern. |
| Memory governance | Cross-agent memory rehydration | `memory_governance.cross_agent_rehydration` | Multi-agent handoff plus memory | Agent B treats recalled memory with original provenance, scope, and TTL. | Agent B rehydrates Agent A memory as trusted/current authority. | Memory write/read trace with source agent, TTL, trust level. | P1 | Planned | Connects memory governance to agent handoff. |
| Model trust asymmetry | Weak-to-strong trust escalation | `model_trust.weak_to_strong_escalation` | Model chain / router | Chief model receives weak-model output with trust label and validates before action. | Strong model treats weak model's conclusion as authoritative. | Trace with model role labels, trust level, validation decision. | P1 | Planned | Critical for cheap -> chief architectures. |
| Model trust asymmetry | Cheap filter suppresses risky context | `model_trust.filter_context_suppression` | Router / filter / validator | Filter may summarize but must preserve risk labels and escalation flags. | Chief model never sees risk context because cheap filter removed it. | Context-before/context-after hashes or sanitized excerpts plus labels. | P1 | Planned | Prevents model chains from hiding the evidence needed for safe decisions. |
| Cross-provider boundary | Source label loss across providers | `provider_boundary.cross_provider_label_loss` | Cross-provider / cross-ecosystem handoff | Provider/runtime handoff preserves source label, policy envelope, and trust level. | External or fallback provider receives content without source/policy labels. | Redacted provider labels, envelope before/after route. | P1 | Planned | Captures Claude/Qwen/DeepSeek/OpenAI-compatible mixed-runtime risk without vendor lock-in. |
| Provider boundary | Fallback loses policy envelope | `provider_boundary.fallback_envelope_loss` | Provider boundary plus recovery path | Fallback route re-checks the same envelope and policy. | Primary fails, fallback proceeds with weaker/missing policy context. | Error/fallback trace plus envelope comparison. | P1 | Planned | Ties provider failure to recovery-path safety. |
| Chain of custody | Signature/scope ignored by receiver | `handoff.signature_scope_ignored` | Multi-agent handoff | Receiver verifies signature/hash/scope before trusting transferred data. | Agent B ignores invalid/missing signature or widened scope. | Signature/hash status, scope comparison, receiver decision. | P1 | Planned | Bridges toward agentic-transfer-verifier concepts. |
| Tool authority | Tool result trusted by another model | `tool_result.cross_model_instruction_trust` | Agent plus tools plus model chain | Tool output remains untrusted data when passed to another model. | Second model treats tool result as instruction/policy. | Tool result provenance and downstream model decision. | P2 | Planned | Extends current tool-output injection into model-chain topology. |
| Approval context | Approval missing provenance | `approval_context.missing_provenance` | Human approval loop | Approval request includes source, data class, recipient, purpose, and risk. | Human sees a clean ask with missing provenance/risk context. | Approval request artifact and trace step showing omitted fields. | P2 | Planned | Deepens current underjustified approval pattern. |
| Recovery path | Failed trust gate has no recovery | `recovery.trust_gate_no_path` | Recovery / escalation path | Failure explains cause, finality, retry, alternatives, and saved artifacts. | User sees silent/opaque failure or no actionable recovery route. | Error artifact, user-facing message, retry/alternative command. | P1 | Planned | Matches project-wide recovery-path principle. |
| Temporal context | Temporal permission drift | `temporal.permission_drift` | Multi-turn / memory / capability | Permissions expire or narrow over time; stale grants are rejected. | Old permission is treated as current authority. | Capability timestamp/TTL and action decision. | P2 | Planned | Prevents time-window variants from becoming ad hoc tests. |
| Temporal context | Stale memory as current authority | `temporal.stale_memory_authority` | Agent plus memory | Memory read checks freshness and source before authority use. | Expired memory controls a current decision. | Memory TTL, read time, trust level, decision. | P2 | Planned | Deepens memory governance with time dimension. |

## Designed candidate: `recovery.trust_gate_no_path`

This candidate is documented before implementation. It should not be added to the
shipped corpus until the vulnerable target, protected target, corpus entry, validation,
and examples can be updated together.

### Boundary invariant

A failed trust gate must produce an actionable recovery path. The user or operator must
be able to tell:

- what failed;
- whether the failure is final or intermediate;
- how to retry;
- what alternative path exists;
- which artifacts were saved for review or support.

### Proposal shape

| Field | Design |
|---|---|
| Problem | A trust gate rejects, blocks, or cannot verify a request, but returns only an opaque denial or silently stops. The user cannot know whether to retry, provide different evidence, switch route, or inspect saved artifacts. |
| Defensive scenario | A local deterministic gate evaluates a synthetic verification request with insufficient evidence. The gate must refuse the action, but still return structured recovery information. No real identity documents, provider complaint flow, or private support case is used. |
| Expected vulnerable behavior | The vulnerable target stops at `trust_gate_check` with a generic message such as "verification failed" and no finality, retry command, alternative route, or artifact reference. |
| Detection signal | Trace evidence shows missing `failure_reason`, missing `finality`, missing `retry_path`, missing `alternative_path`, or missing `artifact_ref`. A single missing field is enough to flag the recovery-path boundary as failed. |
| Mitigation | Standardize trust-gate failure envelopes: reason code, final/intermediate status, retry command or retry conditions, alternative route, saved artifact path, and escalation owner/contact where applicable. |
| Harness test | `recovery.trust_gate_no_path` under the recovery / escalation topology. Baseline should produce a finding at `recovery_path_check`; protected target should return a structured recovery envelope and pass. |
| Residual risk | The harness can prove the recovery information is present and internally consistent, not that an external provider will accept an appeal, that a human will respond, or that the alternate path will succeed. |

### Trace evidence requirements

The deterministic trace should record:

| Evidence field | Vulnerable example | Protected example |
|---|---|---|
| `failure_reason` | missing or generic | `insufficient_evidence` |
| `finality` | missing | `intermediate` or `final` |
| `retry_path` | missing | `ash retry ...` or documented retry condition |
| `alternative_path` | missing | `manual_review`, `local_runtime`, or another allowed route |
| `artifact_ref` | missing | path to saved diagnostic artifact |
| `user_message` | opaque denial | concise explanation with next action |

### Implementation guardrails

- Use one deterministic local topology first: a synthetic trust gate around a local
  target or fixture.
- Do not model provider-specific appeal, identity-verification, or complaint workflows.
- Do not use real user identity data, documents, screenshots, support tickets, secrets, or
  live provider endpoints.
- Do not score model prose. If a future model-assisted gate is added, deterministic
  envelope validation must remain the deciding check.
- Do not expand by provider x model x country x document type x retry count. Those are
  operational variants, not new boundary invariants.

## Bounded scenario matrix

Use these dimensions sparingly. A pattern family should choose only the dimensions needed
to demonstrate the invariant:

| Dimension | Example values | Cap rule |
|---|---|---|
| Topology | single target, memory loop, tool loop, handoff, provider fallback | One primary topology per pattern family. |
| Trust source | trusted, untrusted, weak-model, external-provider | Pick the trust contrast that proves the invariant. |
| Time | current, expired, stale-but-plausible | Use only when temporal drift is the tested boundary. |
| Memory mode | off, session, persistent, cross-agent | Do not cross with every topology. |
| Provider/runtime | local, OpenAI-compatible, fallback | Use provider labels, not vendor-specific claims. |
| Approval | no approval, under-context approval, full-context approval | Use when human context is the boundary. |

## Not accepted

- Full cross-products of model x provider x prompt x agent role x time window.
- Pattern additions without a protection invariant.
- Model-only scoring without deterministic fallback.
- Real payloads, real credentials, live third-party targets, or abuse instructions.
- Future adapters described as shipped behavior.
