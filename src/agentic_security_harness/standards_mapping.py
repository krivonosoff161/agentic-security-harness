"""Category-level mapping from the corpus to external security frameworks.

This is a **coarse, defensive, category-level** mapping - not a per-pattern certification.
It maps each implemented pattern category to:

- OWASP Top 10 for Agentic Applications 2026 (``owasp_agentic``, single-sourced from
  ``corpus.py``),
- OWASP Top 10 for LLM Applications 2025 (``owasp_llm``),
- NIST AI RMF core functions (``nist_ai_rmf``: GOVERN / MAP / MEASURE / MANAGE),
- MITRE ATLAS (``mitre_atlas``) - intentionally **deferred**: per-category ATLAS technique
  IDs are not asserted until verified against the ATLAS matrix.

``status`` is honest about completeness: ``mapped`` (owasp_agentic + owasp_llm + nist all
present), ``partial`` (some present, some deferred), ``deferred`` (mostly unmapped).
A clean mapping does not imply real-world coverage or certification.
"""

from __future__ import annotations

import re
from typing import Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.corpus import corpus_manifest


class _Spec(TypedDict):
    owasp_llm: list[str]
    nist_ai_rmf: list[str]
    rationale: str

NIST_FUNCTIONS = ("GOVERN", "MAP", "MEASURE", "MANAGE")

# ID format guards (verified at validation time).
_ASI_RE = re.compile(r"^ASI\d{2}$")
_LLM_RE = re.compile(r"^LLM\d{2}$")
_ATLAS_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


class CategoryStandards(BaseModel):
    """Category-level standards mapping with rationale and honest status."""

    model_config = ConfigDict(extra="forbid")

    category: str
    owasp_agentic: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    status: Literal["mapped", "partial", "deferred"]
    rationale: str


# Per-category mapping (owasp_agentic is filled from the corpus, not duplicated here).
# MITRE ATLAS is deferred everywhere on purpose - see module docstring.
_CATEGORY: dict[str, _Spec] = {
    "indirect_prompt_injection": {
        "owasp_llm": ["LLM01"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Untrusted tool/retrieved content steers the agent - prompt "
        "injection (LLM01). ATLAS technique id deferred.",
    },
    "data_boundary": {
        "owasp_llm": ["LLM02"],
        "nist_ai_rmf": ["MAP", "MEASURE", "MANAGE"],
        "rationale": "Recipient / classification / forwarding labels fail, risking "
        "sensitive information disclosure (LLM02).",
    },
    "memory_poisoning": {
        "owasp_llm": ["LLM04"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Untrusted content is persisted into memory - data poisoning (LLM04).",
    },
    "memory_governance": {
        "owasp_llm": ["LLM04", "LLM02"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Unscoped / cross-user / expired memory is trusted at read - "
        "poisoning (LLM04) and cross-user disclosure (LLM02).",
    },
    "tool_permission": {
        "owasp_llm": ["LLM06"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Tool used outside its allowed purpose - excessive agency (LLM06).",
    },
    "mcp_tool_schema": {
        "owasp_llm": ["LLM06"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Unverified tool schema/annotations are trusted - excessive agency "
        "(LLM06).",
    },
    "capability_delegation": {
        "owasp_llm": ["LLM06"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Delegated authority expands across hops - excessive agency (LLM06).",
    },
    "ambient_authority": {
        "owasp_llm": ["LLM06"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Ambient host capability used without explicit binding - excessive "
        "agency (LLM06).",
    },
    "approval_laundering": {
        "owasp_llm": ["LLM06"],
        "nist_ai_rmf": ["GOVERN", "MANAGE"],
        "rationale": "Under-justified confirmation launders a risky action past the human "
        "- excessive agency (LLM06).",
    },
    "budget_exhaustion": {
        "owasp_llm": ["LLM10"],
        "nist_ai_rmf": ["MEASURE", "MANAGE"],
        "rationale": "Unbounded loops / recursion - unbounded consumption (LLM10).",
    },
    "perception_boundary": {
        "owasp_llm": ["LLM01"],
        "nist_ai_rmf": ["MEASURE"],
        "rationale": "Perceived content treated as instruction - injection via a "
        "perception channel (LLM01).",
    },
    "sleeping_prompt": {
        "owasp_llm": ["LLM01"],
        "nist_ai_rmf": ["MEASURE"],
        "rationale": "Dormant stored instruction activates later - delayed injection "
        "(LLM01).",
    },
    "audit_bypass": {
        "owasp_llm": [],  # deferred: no clean LLM Top 10 fit
        "nist_ai_rmf": ["GOVERN", "MANAGE"],
        "rationale": "Oversight/audit control bypassed. No clean OWASP LLM Top 10 fit; "
        "OWASP LLM mapping deferred. NIST GOVERN/MANAGE apply.",
    },
    "audit_integrity": {
        "owasp_llm": [],  # deferred: no clean LLM Top 10 fit
        "nist_ai_rmf": ["GOVERN", "MANAGE"],
        "rationale": "Tampered audit trail accepted. No clean OWASP LLM Top 10 fit; "
        "OWASP LLM mapping deferred. NIST GOVERN/MANAGE apply.",
    },
}


def _status(owasp_llm: list[str], nist: list[str]) -> Literal["mapped", "partial", "deferred"]:
    if owasp_llm and nist:
        # mitre_atlas is deferred everywhere, so the strongest honest status is "partial".
        return "partial"
    if nist or owasp_llm:
        return "partial"
    return "deferred"


def standards_mapping() -> list[CategoryStandards]:
    """Build the category-level standards mapping, sorted by category."""
    by_category_agentic: dict[str, set[str]] = {}
    for entry in corpus_manifest():
        by_category_agentic.setdefault(entry.category, set()).update(entry.owasp_agentic)

    out: list[CategoryStandards] = []
    for category in sorted(by_category_agentic):
        spec = _CATEGORY.get(category)
        agentic = sorted(by_category_agentic[category])
        if spec is None:
            out.append(CategoryStandards(
                category=category,
                owasp_agentic=agentic,
                status="deferred",
                rationale="Standards mapping not yet authored for this category.",
            ))
            continue
        owasp_llm = list(spec["owasp_llm"])
        nist = list(spec["nist_ai_rmf"])
        out.append(CategoryStandards(
            category=category,
            owasp_agentic=agentic,
            owasp_llm=owasp_llm,
            mitre_atlas=[],
            nist_ai_rmf=nist,
            status=_status(owasp_llm, nist),
            rationale=spec["rationale"],
        ))
    return out


def validate_standards_mapping() -> list[str]:
    """Return a list of error strings (empty if the mapping is internally consistent)."""
    errors: list[str] = []
    corpus_categories = {e.category for e in corpus_manifest()}
    mapped = {m.category for m in standards_mapping()}
    missing = sorted(corpus_categories - mapped)
    if missing:
        errors.append(f"categories missing from standards mapping: {missing}")

    for m in standards_mapping():
        for code in m.owasp_agentic:
            if not _ASI_RE.match(code):
                errors.append(f"{m.category}: bad OWASP Agentic id '{code}'")
        for code in m.owasp_llm:
            if not _LLM_RE.match(code):
                errors.append(f"{m.category}: bad OWASP LLM id '{code}'")
        for code in m.mitre_atlas:
            if not _ATLAS_RE.match(code):
                errors.append(f"{m.category}: bad MITRE ATLAS id '{code}'")
        for fn in m.nist_ai_rmf:
            if fn not in NIST_FUNCTIONS:
                errors.append(f"{m.category}: bad NIST function '{fn}'")
        if not m.rationale.strip():
            errors.append(f"{m.category}: empty rationale")
        # Emptiness must be explicit via status, never an accidental omission.
        if not m.owasp_llm and m.status == "mapped":
            errors.append(f"{m.category}: status 'mapped' but owasp_llm is empty")
    return errors
