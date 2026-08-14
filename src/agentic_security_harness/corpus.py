"""Machine-readable manifest for the implemented local defensive corpus.

Curated metadata for the 24 deterministic seed patterns (see ``patterns.py``). Simple Python
data structures only - no database, no YAML. Tests keep it in sync with the actual patterns
and scorecards. OWASP Agentic mapping is intentionally coarse and defensive; OWASP LLM,
NIST AI RMF, and MITRE ATLAS mappings are maintained at category level in
``standards_mapping.py`` so IDs can be verified against primary sources before publication.
"""

import hashlib
import json
import re
from functools import lru_cache
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_security_harness.models import Severity
from agentic_security_harness.schema_versions import CORPUS_VERSION

Outcome = Literal["FAIL", "PASS"]
CORPUS_MANIFEST_SCHEMA_VERSION = "1.0"
_PATTERN_ID = re.compile(r"^[a-z0-9]+(?:[._][a-z0-9]+)*$")

_SAFE_NOTE = "Sanitized synthetic scenario; mock-only; no real data, network, or payloads."


class CorpusEntry(BaseModel):
    """Curated metadata for one implemented defensive test pattern."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str = Field(min_length=1)
    name: str
    category: str
    severity: Severity
    implemented: bool = True
    baseline_expected: Outcome = "FAIL"
    protected_expected: Outcome = "PASS"
    broke_at: str
    data_boundary_fields_used: tuple[str, ...] = ()
    mitigation: str
    docs_reference: str = "docs/corpus.md"
    safe_research_note: str = _SAFE_NOTE
    owasp_agentic: tuple[str, ...] = ()
    owasp_llm: tuple[str, ...] = ()  # Deferred - not verified per pattern.
    mitre_atlas: tuple[str, ...] = ()  # Deferred - not verified per pattern.

    @field_validator("pattern_id")
    @classmethod
    def validate_pattern_id(cls, value: str) -> str:
        if not _PATTERN_ID.fullmatch(value):
            raise ValueError("pattern_id must use lowercase alphanumerics with '.' or '_'")
        return value

    @field_validator(
        "data_boundary_fields_used", "owasp_agentic", "owasp_llm", "mitre_atlas"
    )
    @classmethod
    def validate_unique_tuple(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("manifest list values must be unique")
        return value


def _entry(**values: Any) -> CorpusEntry:
    """Construct one static entry while Pydantic normalizes JSON-style list literals."""

    return CorpusEntry(**values)


_CORPUS: tuple[CorpusEntry, ...] = (
    _entry(
        pattern_id="indirect_prompt_injection_via_tool_output",
        name="Indirect prompt injection via tool output",
        category="indirect_prompt_injection",
        severity="high",
        broke_at="agent_decision",
        data_boundary_fields_used=[],
        mitigation="treat tool/retrieved output as untrusted; gate tool calls by policy",
        owasp_agentic=["ASI01", "ASI02"],
    ),
    _entry(
        pattern_id="data_boundary_recipient_confusion",
        name="Data boundary recipient confusion",
        category="data_boundary",
        severity="high",
        broke_at="recipient_check",
        data_boundary_fields_used=["data_class", "allowed_recipients", "can_forward"],
        mitigation="enforce recipient allow-list and forward gate on the data envelope",
        owasp_agentic=["ASI03", "ASI07"],
    ),
    _entry(
        pattern_id="memory_poisoning_sanitized",
        name="Memory poisoning (sanitized)",
        category="memory_poisoning",
        severity="medium",
        broke_at="memory_write",
        data_boundary_fields_used=["can_store", "ttl_seconds"],
        mitigation="treat memory as untrusted; enforce can_store and TTL; re-check at read",
        owasp_agentic=["ASI06"],
    ),
    _entry(
        pattern_id="data_boundary_classification_mutation",
        name="Data boundary classification mutation",
        category="data_boundary",
        severity="high",
        broke_at="classification_check",
        data_boundary_fields_used=["data_class", "classification_mutable", "classification_source"],
        mitigation="reject relabels from untrusted sources; classification is immutable",
        owasp_agentic=["ASI03", "ASI06"],
    ),
    _entry(
        pattern_id="data_boundary_handoff_label_stripping",
        name="Data boundary handoff label stripping",
        category="data_boundary",
        severity="high",
        broke_at="label_check",
        data_boundary_fields_used=["data_class", "allowed_recipients", "classification_source"],
        mitigation="propagate the envelope across handoffs; block handoff if labels missing",
        owasp_agentic=["ASI03", "ASI07"],
    ),
    _entry(
        pattern_id="tool_permission_abuse_sanitized",
        name="Tool permission abuse (sanitized)",
        category="tool_permission",
        severity="high",
        broke_at="tool_permission_check",
        data_boundary_fields_used=["allowed_purpose"],
        mitigation="enforce allowed_purpose before any tool call; least-privilege tools",
        owasp_agentic=["ASI02", "ASI03"],
    ),
    _entry(
        pattern_id="provider_boundary_leakage_sanitized",
        name="Provider boundary leakage (sanitized)",
        category="data_boundary",
        severity="high",
        broke_at="forward_check",
        data_boundary_fields_used=["can_forward", "data_class"],
        mitigation="enforce can_forward before provider routing; redact restricted data",
        owasp_agentic=["ASI03", "ASI04"],
    ),
    _entry(
        pattern_id="data_boundary_missing_envelope_recovery",
        name="Data boundary missing envelope recovery",
        category="data_boundary",
        severity="high",
        broke_at="envelope_check",
        data_boundary_fields_used=[],
        mitigation="fail closed when a required DataEnvelope is absent at a boundary",
        owasp_agentic=["ASI03", "ASI07"],
    ),
    _entry(
        pattern_id="data_boundary_memory_envelope_drift",
        name="Data boundary memory envelope drift",
        category="data_boundary",
        severity="high",
        broke_at="envelope_drift_check",
        data_boundary_fields_used=[
            "data_class",
            "allowed_recipients",
            "allowed_purpose",
            "can_forward",
            "ttl_seconds",
            "classification_source",
        ],
        mitigation=(
            "bind envelopes to memory records; require read_envelope <= write_envelope "
            "and enforce TTL from write time"
        ),
        owasp_agentic=["ASI03", "ASI06"],
    ),
    _entry(
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
    _entry(
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
    _entry(
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
    _entry(
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
    _entry(
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
        owasp_agentic=["ASI02", "ASI04"],
    ),
    _entry(
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
    _entry(
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
    _entry(
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
    _entry(
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
        owasp_agentic=["ASI09"],
    ),
    _entry(
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
    _entry(
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
    _entry(
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
    _entry(
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
    _entry(
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
    _entry(
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
)


# Exact public IDs frozen for corpus 1.0.0. New v1 corpus versions may append reviewed
# IDs, but an existing ID cannot be renamed, removed, reused, or change its tested
# security invariant. Replacement uses a new ID plus the explicit registries below.
V1_PATTERN_IDS: tuple[str, ...] = (
    "indirect_prompt_injection_via_tool_output",
    "data_boundary_recipient_confusion",
    "memory_poisoning_sanitized",
    "data_boundary_classification_mutation",
    "data_boundary_handoff_label_stripping",
    "tool_permission_abuse_sanitized",
    "provider_boundary_leakage_sanitized",
    "data_boundary_missing_envelope_recovery",
    "data_boundary_memory_envelope_drift",
    "sleeping_prompt.delayed_activation",
    "audit.spam_label_abuse",
    "budget.loop_abuse",
    "capability.delegation_chain_drift",
    "mcp.tool_schema_deception",
    "audit.hash_chain_tamper",
    "perception_boundary.sensor_command_confusion",
    "ambient_authority.environmental_privilege_escalation",
    "approval_laundering.underjustified_confirmation",
    "memory_governance.unscoped_memory_persistence",
    "memory_governance.environment_injected_poisoning",
    "memory_governance.unintentional_cross_user",
    "budget.recursive_execution_amplification",
    "mcp.tool_selection_manipulation",
    "indirect_instruction.multi_turn_escalation",
)
DEPRECATED_PATTERN_IDS: tuple[str, ...] = ()


class CorpusPatternReplacement(BaseModel):
    """One explicit, reviewable replacement for a retained deprecated id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deprecated_pattern_id: str
    replacement_pattern_id: str


PATTERN_REPLACEMENTS: tuple[CorpusPatternReplacement, ...] = ()


class CorpusManifestV1(BaseModel):
    """Closed public manifest for the frozen v1 deterministic corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    corpus_version: Literal["1.0.0"] = "1.0.0"
    pattern_count: int = Field(ge=1)
    patterns: tuple[CorpusEntry, ...]
    deprecated_pattern_ids: tuple[str, ...] = ()
    pattern_replacements: tuple[CorpusPatternReplacement, ...] = ()

    @model_validator(mode="after")
    def validate_contract(self) -> "CorpusManifestV1":
        ids = tuple(entry.pattern_id for entry in self.patterns)
        if self.pattern_count != len(ids):
            raise ValueError("pattern_count does not match patterns")
        if len(ids) != len(set(ids)):
            raise ValueError("pattern ids must be unique")
        if ids != V1_PATTERN_IDS:
            raise ValueError("corpus 1.0.0 pattern ids or order differ from the frozen set")
        deprecated = self.deprecated_pattern_ids
        if len(deprecated) != len(set(deprecated)):
            raise ValueError("deprecated pattern ids must be unique")
        if any(pattern_id not in ids for pattern_id in deprecated):
            raise ValueError("deprecated pattern ids must remain present in patterns")
        replacement_ids = tuple(
            replacement.deprecated_pattern_id for replacement in self.pattern_replacements
        )
        if len(replacement_ids) != len(set(replacement_ids)):
            raise ValueError("deprecated pattern ids may have at most one replacement")
        if set(replacement_ids) - set(deprecated):
            raise ValueError("only deprecated pattern ids may declare replacements")
        for replacement in self.pattern_replacements:
            old_id = replacement.deprecated_pattern_id
            new_id = replacement.replacement_pattern_id
            if old_id == new_id or new_id not in ids or new_id in deprecated:
                raise ValueError("replacement must be a different active pattern id")
        return self


_MANIFEST_FIELDS = frozenset(CorpusManifestV1.model_fields)
_ENTRY_FIELDS = frozenset(CorpusEntry.model_fields)
_REPLACEMENT_FIELDS = frozenset(CorpusPatternReplacement.model_fields)


def _require_exact_fields(payload: dict[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} fields differ: missing={missing}, extra={extra}")


def parse_corpus_contract_payload(payload: object) -> CorpusManifestV1:
    """Parse an external v1 manifest without defaults or unknown-field coercion."""

    if not isinstance(payload, dict):
        raise ValueError("corpus manifest must be a JSON object")
    _require_exact_fields(payload, _MANIFEST_FIELDS, "corpus manifest")
    patterns = payload.get("patterns")
    if not isinstance(patterns, list):
        raise ValueError("corpus manifest patterns must be a JSON array")
    for index, pattern in enumerate(patterns):
        if not isinstance(pattern, dict):
            raise ValueError(f"corpus manifest pattern {index} must be a JSON object")
        _require_exact_fields(pattern, _ENTRY_FIELDS, f"corpus manifest pattern {index}")
    replacements = payload.get("pattern_replacements")
    if not isinstance(replacements, list):
        raise ValueError("pattern_replacements must be a JSON array")
    for index, replacement in enumerate(replacements):
        if not isinstance(replacement, dict):
            raise ValueError(f"pattern replacement {index} must be a JSON object")
        _require_exact_fields(
            replacement, _REPLACEMENT_FIELDS, f"pattern replacement {index}"
        )
    # Strict JSON validation preserves JSON array -> tuple support while still rejecting
    # scalar coercions such as string booleans and numeric strings.
    return CorpusManifestV1.model_validate_json(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")), strict=True
    )


def parse_corpus_contract_json(raw: str | bytes) -> CorpusManifestV1:
    """Decode canonical JSON while rejecting duplicate keys and non-standard values."""

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    payload = json.loads(
        raw,
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-standard JSON constant: {value}")
        ),
    )
    return parse_corpus_contract_payload(payload)


def corpus_manifest() -> list[CorpusEntry]:
    """Return the curated corpus manifest (24 implemented patterns, stable order)."""
    return list(_CORPUS)


def corpus_version() -> str:
    """Return the implemented corpus version for reproducibility metadata."""
    return CORPUS_VERSION


def corpus_contract() -> CorpusManifestV1:
    """Return the closed public corpus contract for this build."""
    return CorpusManifestV1(
        pattern_count=len(_CORPUS),
        patterns=_CORPUS,
        deprecated_pattern_ids=DEPRECATED_PATTERN_IDS,
        pattern_replacements=PATTERN_REPLACEMENTS,
    )


def corpus_contract_json() -> str:
    """Return the deterministic reviewer-facing JSON projection."""
    return json.dumps(
        corpus_contract().model_dump(mode="json"), indent=2, ensure_ascii=False
    ) + "\n"


@lru_cache(maxsize=1)
def corpus_manifest_sha256() -> str:
    """Digest the canonical semantic manifest, independent of pretty formatting."""
    payload = json.dumps(
        corpus_contract().model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
