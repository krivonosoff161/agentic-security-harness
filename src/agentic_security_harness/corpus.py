"""Machine-readable manifest for the implemented local defensive corpus.

Curated metadata for the 7 deterministic seed patterns (see ``patterns.py``). Simple Python
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
]


def corpus_manifest() -> list[CorpusEntry]:
    """Return the curated corpus manifest (7 implemented patterns, stable order)."""
    return list(_CORPUS)
