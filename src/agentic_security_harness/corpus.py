"""Machine-readable manifest for the implemented local defensive corpus.

Curated metadata for the 22 deterministic seed patterns (see ``patterns.py``). Simple Python
data structures only - no database, no YAML. Tests keep it in sync with the actual patterns
and scorecards. OWASP Agentic mapping is intentionally coarse and defensive; OWASP LLM and
MITRE ATLAS mappings remain empty until each ID is verified against primary sources.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.models import Severity

Outcome = Literal["FAIL", "PASS"]

_SAFE_NOTE = "Sanitized synthetic scenario; mock-only; no real data, network, or payloads."


class CorpusEntry(BaseModel):
    """Curated metadata for one implemented defensive test pattern."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    name: str
    category: str
    severity: Severity
    implemented: bool = True
    baseline_expected: Outcome = "FAIL"
    protected_expected: Outcome = "PASS"
    broke_at: str
    data_boundary_fields_used: list[str] = Field(default_factory=list)
    mitigation: str
    docs_reference: str = "docs/corpus.md"
    safe_research_note: str = _SAFE_NOTE
    owasp_agentic: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)  # TBD - not verified per pattern.
    mitre_atlas: list[str] = Field(default_factory=list)  # TBD - not verified per pattern.


_CORPUS: list[CorpusEntry] = [
    CorpusEntry(
        pattern_id="indirect_prompt_injection_via_tool_output",
        name="Indirect prompt injection via tool output",
        category="indirect_prompt_injection",
        severity="high",
        broke_at="agent_decision",
        data_boundary_fields_used=[],
        mitigation="treat tool/retrieved output as untrusted; gate tool calls by policy",
        owasp_agentic=["ASI01", "ASI02"],
    ),
    CorpusEntry(
        pattern_id="data_boundary_recipient_confusion",
        name="Data boundary recipient confusion",
        category="data_boundary",
        severity="high",
        broke_at="recipient_check",
        data_boundary_fields_used=["data_class", "allowed_recipients", "can_forward"],
        mitigation="enforce recipient allow-list and forward gate on the data envelope",
        owasp_agentic=["ASI03", "ASI07"],
    ),
    CorpusEntry(
        pattern_id="memory_poisoning_sanitized",
        name="Memory poisoning (sanitized)",
        category="memory_poisoning",
        severity="medium",
        broke_at="memory_write",
        data_boundary_fields_used=["can_store", "ttl_seconds"],
        mitigation="treat memory as untrusted; enforce can_store and TTL; re-check at read",
        owasp_agentic=["ASI06"],
    ),
    CorpusEntry(
        pattern_id="data_boundary_classification_mutation",
        name="Data boundary classification mutation",
        category="data_boundary",
        severity="high",
        broke_at="classification_check",
        data_boundary_fields_used=["data_class", "classification_mutable", "classification_source"],
        mitigation="reject relabels from untrusted sources; classification is immutable",
        owasp_agentic=["ASI03", "ASI06"],
    ),
    CorpusEntry(
        pattern_id="data_boundary_handoff_label_stripping",
        name="Data boundary handoff label stripping",
        category="data_boundary",
        severity="high",
        broke_at="label_check",
        data_boundary_fields_used=["data_class", "allowed_recipients", "classification_source"],
        mitigation="propagate the envelope across handoffs; block handoff if labels missing",
        owasp_agentic=["ASI03", "ASI07"],
    ),
    CorpusEntry(
        pattern_id="tool_permission_abuse_sanitized",
        name="Tool permission abuse (sanitized)",
        category="tool_permission",
        severity="high",
        broke_at="tool_permission_check",
        data_boundary_fields_used=["allowed_purpose"],
        mitigation="enforce allowed_purpose before any tool call; least-privilege tools",
        owasp_agentic=["ASI02", "ASI03"],
    ),
    CorpusEntry(
        pattern_id="provider_boundary_leakage_sanitized",
        name="Provider boundary leakage (sanitized)",
        category="data_boundary",
        severity="high",
        broke_at="forward_check",
        data_boundary_fields_used=["can_forward", "data_class"],
        mitigation="enforce can_forward before provider routing; redact restricted data",
        owasp_agentic=["ASI03", "ASI04"],
    ),
    CorpusEntry(
        pattern_id="sleeping_prompt.delayed_activation",
        name="Sleeping prompt delayed activation (sanitized)",
        category="sleeping_prompt",
        severity="high",
        broke_at="provenance_check",
        data_boundary_fields_used=["can_store", "ttl_seconds", "classification_source"],
        mitigation=(
            "preserve provenance and TTL on stored content; treat retrieved memory "
            "as untrusted; re-check at read time"
        ),
        owasp_agentic=["ASI01", "ASI06"],
    ),
    CorpusEntry(
        pattern_id="audit.spam_label_abuse",
        name="Audit bypass via spam-label abuse (sanitized)",
        category="audit_bypass",
        severity="high",
        broke_at="audit_check",
        data_boundary_fields_used=["data_class", "classification_source"],
        mitigation=(
            "labels never suppress audit; log every sensitive event regardless of "
            "label or label source"
        ),
        owasp_agentic=["ASI03"],
    ),
    CorpusEntry(
        pattern_id="budget.loop_abuse",
        name="Budget exhaustion via loop abuse (sanitized)",
        category="budget_exhaustion",
        severity="medium",
        broke_at="budget_check",
        data_boundary_fields_used=[],
        mitigation=(
            "enforce per-run step budgets and loop guards; stop at the cap and "
            "surface the overrun"
        ),
        owasp_agentic=["ASI02"],
    ),
    CorpusEntry(
        pattern_id="capability.delegation_chain_drift",
        name="Capability delegation-chain drift (sanitized)",
        category="capability_delegation",
        severity="high",
        broke_at="capability_check",
        data_boundary_fields_used=[],
        mitigation=(
            "enforce most-restrictive-scope-wins, bounded delegation depth, "
            "non-expanding TTL, and delegation-chain provenance"
        ),
        owasp_agentic=["ASI02", "ASI07"],
    ),
    CorpusEntry(
        pattern_id="mcp.tool_schema_deception",
        name="MCP tool-schema deception (mock)",
        category="mcp_tool_schema",
        severity="high",
        broke_at="schema_provenance_check",
        data_boundary_fields_used=[],
        mitigation=(
            "pin tool-schema provenance and hash; treat annotations as untrusted "
            "until approved; validate output shape"
        ),
        owasp_agentic=["ASI02", "ASI06"],
    ),
    CorpusEntry(
        pattern_id="audit.hash_chain_tamper",
        name="Audit hash-chain tamper detection",
        category="audit_integrity",
        severity="high",
        broke_at="audit_integrity_check",
        data_boundary_fields_used=[],
        mitigation=(
            "validate contiguous indexes, previous_hash links, entry hashes, and "
            "required audit events"
        ),
        owasp_agentic=["ASI03"],
    ),
    CorpusEntry(
        pattern_id="perception_boundary.sensor_command_confusion",
        name="Perception-boundary sensor-command confusion (sanitized)",
        category="perception_boundary",
        severity="high",
        broke_at="perception_trust_check",
        data_boundary_fields_used=["allowed_purpose", "allowed_recipients"],
        mitigation=(
            "treat all perception-channel content as untrusted data; "
            "check provenance before acting; never execute actions from perception transcripts"
        ),
        owasp_agentic=["ASI01"],
    ),
    CorpusEntry(
        pattern_id="ambient_authority.environmental_privilege_escalation",
        name="Ambient authority escalation (sanitized)",
        category="ambient_authority",
        severity="high",
        broke_at="authority_binding_check",
        data_boundary_fields_used=["allowed_purpose"],
        mitigation=(
            "deny-by-default for ambient capabilities; require explicit envelope "
            "binding for any ambient privilege use; least-privilege at host boundary"
        ),
        owasp_agentic=["ASI02", "ASI03"],
    ),
    CorpusEntry(
        pattern_id="approval_laundering.underjustified_confirmation",
        name="Approval laundering via underjustified confirmation (sanitized)",
        category="approval_laundering",
        severity="high",
        broke_at="approval_context_check",
        data_boundary_fields_used=["data_class", "allowed_recipients", "requires_confirmation"],
        mitigation=(
            "include data_class, recipient, purpose, and risk in every approval request; "
            "one action per confirmation; reject on ambiguity"
        ),
        owasp_agentic=["ASI05"],
    ),
    CorpusEntry(
        pattern_id="memory_governance.unscoped_memory_persistence",
        name="Memory governance: unscoped persistence (sanitized)",
        category="memory_governance",
        severity="high",
        broke_at="memory_governance_check",
        data_boundary_fields_used=["can_store", "ttl_seconds", "classification_source"],
        mitigation=(
            "track provenance and trust level per memory entry; enforce TTL at read; "
            "trust-level precedence on conflict; deletion requires trusted authorization"
        ),
        owasp_agentic=["ASI01", "ASI03", "ASI06"],
    ),
    # -- v0.9 deeper variants ------------------------------------------------
    CorpusEntry(
        pattern_id="memory_governance.environment_injected_poisoning",
        name="Memory governance: environment-injected poisoning (sanitized)",
        category="memory_governance",
        severity="high",
        broke_at="provenance_check",
        data_boundary_fields_used=["can_store", "ttl_seconds", "classification_source"],
        mitigation=(
            "preserve source provenance and trust level on memory writes; "
            "treat retrieved content as untrusted at read time; enforce TTL"
        ),
        owasp_agentic=["ASI01", "ASI06"],
    ),
    CorpusEntry(
        pattern_id="memory_governance.unintentional_cross_user",
        name="Memory governance: unintentional cross-user contamination (sanitized)",
        category="memory_governance",
        severity="high",
        broke_at="cross_user_boundary_check",
        data_boundary_fields_used=["classification_source"],
        mitigation=(
            "enforce per-user memory isolation; scope-based access control; "
            "provenance tracking per user/session"
        ),
        owasp_agentic=["ASI03", "ASI06"],
    ),
    CorpusEntry(
        pattern_id="budget.recursive_execution_amplification",
        name="Budget: recursive execution amplification (sanitized)",
        category="budget_exhaustion",
        severity="high",
        broke_at="recursion_depth_check",
        data_boundary_fields_used=[],
        mitigation=(
            "enforce recursion depth limits and cycle checks; detect recursive "
            "call patterns; apply call-graph energy budget"
        ),
        owasp_agentic=["ASI02"],
    ),
    CorpusEntry(
        pattern_id="mcp.tool_selection_manipulation",
        name="MCP: tool-selection manipulation (sanitized)",
        category="mcp_tool_schema",
        severity="high",
        broke_at="selection_integrity_check",
        data_boundary_fields_used=["allowed_purpose"],
        mitigation=(
            "validate selected tool against task intent and least privilege; "
            "pin tool selection provenance; reject selection influenced by "
            "untrusted content"
        ),
        owasp_agentic=["ASI02"],
    ),
    CorpusEntry(
        pattern_id="indirect_instruction.multi_turn_escalation",
        name="Indirect instruction: multi-turn escalation (sanitized)",
        category="indirect_prompt_injection",
        severity="high",
        broke_at="per_turn_check",
        data_boundary_fields_used=[],
        mitigation=(
            "validate each turn independently; detect escalation patterns "
            "across turns; isolate context between turns; no defense "
            "relaxation after prior turns"
        ),
        owasp_agentic=["ASI01"],
    ),
]


def corpus_manifest() -> list[CorpusEntry]:
    """Return the curated corpus manifest (22 implemented patterns, stable order)."""
    return list(_CORPUS)
