# Data Boundary / Envelope Preservation

> Status: active theory module.
>
> Claim type: deterministic synthetic invariant coverage, not production security proof.

## 1. Claim

Agentic Security Harness models a data envelope as a policy label that travels with a data item. In the shipped synthetic corpus, five primary data-boundary patterns show that a vulnerable demo target loses, ignores, or fails to require envelope constraints, while the protected demo target enforces or fails closed on those constraints.

This module claims a narrower result:

> Data-envelope fields can be checked deterministically at defined synthetic boundaries, and the committed demo comparison contains public evidence for five primary data-boundary patterns.

This does not claim that a deployed agent framework preserves labels, that semantic truthfulness is solved, or that every possible boundary type is covered.

## 2. Formal Object

`DataEnvelope` is defined in `src/agentic_security_harness/models.py` as a policy label, not encryption:

```python
class DataEnvelope(BaseModel):
    data_class: str = "public"
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_purpose: list[str] = Field(default_factory=list)
    can_store: bool = True
    can_forward: bool = True
    ttl_seconds: int | None = None
    requires_confirmation: bool = False
    classification_source: str = "unknown"
    classification_mutable: bool = False
```

The fields support deterministic comparison, but several checks require explicit policy context:

| Field | Deterministic part | Required policy or trace context |
|---|---|---|
| `data_class` | Compare before/after value. | Classification ordering table for downgrade checks. |
| `allowed_recipients` | Check that recipients do not expand. | Stable recipient identity across hops. |
| `allowed_purpose` | Check that purposes do not expand. | Purpose taxonomy for near-synonyms. |
| `can_store` | Check before memory write. | Definition of persistent vs transient storage. |
| `can_forward` | Check before provider/runtime route. | Boundary definition for local vs external transfer. |
| `ttl_seconds` | Compare created/use timestamps. | Reliable clock and timestamp evidence. |
| `requires_confirmation` | Check confirmation event exists. | Confirmation event schema and scope. |
| `classification_source` | Compare source label and authority. | Trusted-source policy table. |
| `classification_mutable` | Check relabel attempt against flag. | Relabel authority rule. |

## 3. Boundary Invariants

These invariants are intentionally field-level and synthetic. They are useful because they can be turned into trace checks without relying on open-ended model judgment.

### 3.1 Restriction model

Let `E_in` be the envelope before a boundary and `E_out` the envelope after that boundary. For deterministic checks, the verifier should treat an output envelope as acceptable only when it is equal to or more restrictive than the input envelope:

```text
E_out <= E_in
```

The relation is field-specific:

| Field | Non-expansion / non-weakening rule |
|---|---|
| `allowed_recipients` | `set(E_out.allowed_recipients) subseteq set(E_in.allowed_recipients)` unless an explicit policy grants a new recipient. |
| `allowed_purpose` | `set(E_out.allowed_purpose) subseteq set(E_in.allowed_purpose)` unless an explicit policy grants a new purpose. |
| `data_class` | `rank(E_out.data_class) >= rank(E_in.data_class)` under a declared classification ordering, for example `public < internal < confidential < restricted`. |
| `can_store` | `False <= True`; a boundary may change `True -> False`, but not `False -> True` without explicit policy evidence. |
| `can_forward` | `False <= True`; a boundary may change `True -> False`, but not `False -> True` without explicit policy evidence. |
| `ttl_seconds` | If both TTL values exist, `E_out.ttl_seconds <= E_in.ttl_seconds`; use must also satisfy `t_use <= t_created + ttl_seconds`. |
| `requires_confirmation` | `True` is more restrictive than `False`; a boundary may require confirmation, but not remove it without trace evidence. |
| `classification_source` | Source may stay the same or move to a more trusted source under a trusted-source policy; it must not silently become unknown/untrusted. |
| `classification_mutable` | `False` is more restrictive than `True`; a boundary may freeze classification, but not make an immutable label mutable without policy evidence. |

This is a partial order, not a universal security proof. The ordering for `data_class`, trusted source rank, and recipient identity must be supplied by policy. Without that policy context, the verifier can compare fields but must not claim semantic completeness.

| # | Invariant | Check |
|---|---|---|
| 1 | Recipient allow-list preservation | Receiver recipients may narrow but not widen the sender envelope. |
| 2 | Classification non-downgrade | If classification is immutable, untrusted relabeling cannot lower `data_class`. |
| 3 | Purpose non-expansion | Receiver purpose set may narrow but not widen the sender envelope. |
| 4 | Forwarding gate | `can_forward=false` blocks provider/runtime forwarding. |
| 5 | Storage gate | `can_store=false` blocks persistent memory writes. |
| 6 | TTL / freshness | Read/use time must not exceed creation time plus TTL. |
| 7 | Source-label preservation | Source/classification labels must not be silently stripped. |
| 8 | Provider/runtime label preservation | Provider boundary calls must carry the required envelope metadata. |
| 9 | Memory write/read envelope preservation | A stored item must read back with the same or more restrictive envelope. |
| 10 | Fail-closed missing envelope | If a required envelope is absent, the boundary action must block or downgrade. |
| 11 | Confirmation gate | `requires_confirmation=true` requires a recorded confirmation event before action. |

## 4. Current Coverage

### Primary Data-Boundary Patterns

These four patterns are category `data_boundary` in the current corpus. They are the primary public evidence for this theory module.

| Pattern | Fields | Boundary | Evidence status |
|---|---|---|---|
| `data_boundary_recipient_confusion` | `data_class`, `allowed_recipients`, `can_forward` | Agent handoff routing | `public_example` |
| `data_boundary_classification_mutation` | `data_class`, `classification_mutable`, `classification_source` | Relabel attempt | `public_example` |
| `data_boundary_handoff_label_stripping` | `data_class`, `allowed_recipients`, `classification_source` | Agent-to-agent handoff | `public_example` |
| `provider_boundary_leakage_sanitized` | `can_forward`, `data_class` | Provider routing | `public_example` |
| `data_boundary_missing_envelope_recovery` | Missing required envelope | Fail-closed recovery path | `public_example` |

The public evidence is corpus-level: `examples/comparison-report/` shows the full 23-pattern corpus reduced from 23 modeled findings on the vulnerable demo target to 0 modeled findings on the protected demo target. The five primary data-boundary patterns are part of that corpus; individual patterns do not themselves prove the whole 23 -> 0 result.

### Adjacent Envelope-Field Patterns

These patterns use `DataEnvelope` fields but belong to other control families. They should be referenced as adjacent coverage, not as primary data-boundary proof.

| Pattern | Control family | Envelope fields | Primary focus |
|---|---|---|---|
| `tool_permission_abuse_sanitized` | `tool_permission` | `allowed_purpose` | Tool purpose enforcement. |
| `memory_poisoning_sanitized` | `memory_poisoning` | `can_store`, `ttl_seconds` | Memory no-store and TTL gate. |
| `sleeping_prompt.delayed_activation` | `sleeping_prompt` | `can_store`, `ttl_seconds`, `classification_source` | Stored-content provenance and activation. |
| `approval_laundering.underjustified_confirmation` | `approval_laundering` | `data_class`, `allowed_recipients`, `requires_confirmation` | Approval context completeness. |
| `perception_boundary.sensor_command_confusion` | `perception_boundary` | `allowed_purpose`, `allowed_recipients` | Perception data vs instruction boundary. |
| `ambient_authority.environmental_privilege_escalation` | `ambient_authority` | `allowed_purpose` | Ambient capability binding. |

## 5. Code Mapping

| Component | Path |
|---|---|
| Envelope model | `src/agentic_security_harness/models.py` |
| Pattern definitions | `src/agentic_security_harness/patterns.py` |
| Corpus metadata and fields-used mapping | `src/agentic_security_harness/corpus.py` |
| Vulnerable synthetic target behavior | `src/agentic_security_harness/demo_agent.py` |
| Protected synthetic target behavior | `src/agentic_security_harness/protected_demo_agent.py` |
| Adapter wiring | `src/agentic_security_harness/demo_adapter.py` |

## 6. Tests

| Test | What it checks |
|---|---|
| `tests/test_demo_agent.py::test_envelope_recipient_control_survives_or_fails` | Recipient allow-list behavior on the demo target. |
| `tests/test_demo_agent.py::test_envelope_no_store_survives_or_fails` | `can_store` behavior on the demo target. |
| `tests/test_runner.py::test_data_boundary_trace_has_immutable_envelope` | Trace carries immutable envelope metadata. |
| `tests/test_demo_agent.py::test_demo_agent_handles_all_seed_patterns` | Every seed pattern maps to the expected failure point. |
| `tests/test_demo_agent.py::test_committed_example_matches_code` | Committed example traces match deterministic local replay. |
| `tests/test_protected.py` | Protected target passes the same deterministic corpus. |

## 7. Coverage Gaps

These are not shipped claims yet. They should remain planned until code, tests, regenerated examples, and validation are committed.

| Gap | Priority | Reason |
|---|---|---|
| Memory write/read envelope drift | P1 | Current memory patterns cover gates, not full write-envelope to read-envelope preservation. |
| Multi-hop recipient laundering | P1 | Current recipient coverage is single-hop. |
| Cross-provider label loss | P1 | Current provider pattern checks forwarding gate, not label survival across provider interfaces. |
| Summary-based boundary loss | P1 | Summaries can strip or weaken labels unless inheritance is explicit. |
| Policy version drift | P2 | Requires explicit policy-version metadata and interpretation rules. |
| Semantic reconstruction | P2 | Mixed deterministic/semantic problem; must not be scored as pure envelope preservation. |

Recommended implementation order:

1. Memory write/read envelope drift.
2. Multi-hop recipient laundering.
3. Cross-provider label loss.
4. Summary-based boundary loss.
5. Policy version drift.
6. Semantic reconstruction.

## 8. Claim Table

| Claim | Status | What this proves | What this does not prove |
|---|---|---|---|
| Single-hop recipient allow-list preservation | `public_example` | The protected demo target blocks a disallowed recipient in the committed comparison corpus. | Multi-hop laundering or stable recipient identity across real systems. |
| Classification non-downgrade at one boundary | `public_example` | The protected demo target rejects untrusted relabeling in the committed comparison corpus. | Complete classification semantics across organizations or providers. |
| Handoff label preservation at one boundary | `public_example` | The protected demo target preserves required labels during the synthetic handoff pattern. | Summary inheritance, multi-hop label survival, or live framework behavior. |
| Provider forwarding gate | `public_example` | The protected demo target blocks forwarding when `can_forward=false`. | Cross-provider label preservation or fallback-route correctness. |
| Missing envelope recovery | `public_example` | The protected demo target fails closed when a boundary action lacks a required envelope. | Complete recovery behavior for every boundary type or live framework behavior. |
| Tool purpose gate | `synthetic_validation` | Adjacent envelope-field coverage for `allowed_purpose`. | Primary data-boundary coverage or cross-model tool-result trust. |
| Memory storage/TTL gate | `synthetic_validation` | Adjacent envelope-field coverage for `can_store` and TTL gates. | Full memory write/read envelope preservation. |
| Full memory envelope drift | `planned` | No implementation claim yet. | Any claim that read-time envelopes preserve all fields. |

## 9. Evidence

| Artifact | Status |
|---|---|
| `examples/comparison-report/` | Public curated comparison evidence for the 23-pattern corpus, including the five primary data-boundary patterns. |
| `examples/demo-agent-report/` | Public vulnerable-target evidence for the 23-pattern corpus, including data-boundary findings. |
| `docs/research-claims.md` | Registry row for the broader data-boundary / envelope-preservation claim. |

## 10. Limits / Non-Claims

This module does not claim:

- a real deployed agent preserves envelope labels;
- envelope labels are encryption;
- envelope preservation proves semantic truthfulness;
- the five primary patterns cover every boundary type;
- adjacent tool, memory, approval, perception, or ambient-authority patterns are primary data-boundary proof;
- complete recovery behavior for every boundary type;
- full memory write/read envelope preservation;
- the project has implemented full memory write/read envelope drift checks;
- the system has complete formal security proof.

This module does claim:

- `DataEnvelope` is a concrete nine-field model in the public codebase;
- five primary data-boundary patterns are present in the committed synthetic corpus;
- deterministic field-level checks can model the current primary invariants;
- the public comparison example includes the five primary data-boundary patterns as part of the broader 23-pattern corpus.
