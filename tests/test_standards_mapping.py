"""Tests for the category-level standards mapping (Phase 7)."""

from pathlib import Path

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.standards_mapping import (
    MITRE_ATLAS_VERIFIED_TECHNIQUES,
    NIST_FUNCTIONS,
    standards_mapping,
    validate_standards_mapping,
)


def test_mapping_self_consistent() -> None:
    assert validate_standards_mapping() == []


def test_every_corpus_category_is_mapped() -> None:
    corpus_categories = {e.category for e in corpus_manifest()}
    mapped = {m.category for m in standards_mapping()}
    assert corpus_categories == mapped


def test_pattern_ids_are_unique_and_stable() -> None:
    ids = [p.pattern_id for p in seed_patterns()]
    assert len(ids) == 23
    assert len(set(ids)) == 23


def test_owasp_agentic_single_sourced_from_corpus() -> None:
    # The mapping must aggregate exactly the ASI codes the corpus declares.
    by_cat: dict[str, set[str]] = {}
    for e in corpus_manifest():
        by_cat.setdefault(e.category, set()).update(e.owasp_agentic)
    for m in standards_mapping():
        assert set(m.owasp_agentic) == by_cat[m.category]


def test_nist_functions_are_valid() -> None:
    for m in standards_mapping():
        for fn in m.nist_ai_rmf:
            assert fn in NIST_FUNCTIONS


def test_mitre_atlas_verified_subset_is_asserted() -> None:
    by_category = {m.category: m for m in standards_mapping()}

    assert by_category["indirect_prompt_injection"].mitre_atlas == ["AML.T0051.001"]
    assert by_category["memory_poisoning"].mitre_atlas == ["AML.T0080.000"]
    assert by_category["sleeping_prompt"].mitre_atlas == ["AML.T0094"]
    assert by_category["budget_exhaustion"].mitre_atlas == ["AML.T0034.002"]

    still_deferred = {
        "approval_laundering",
        "audit_bypass",
        "audit_integrity",
        "capability_delegation",
    }
    assert {c for c, m in by_category.items() if not m.mitre_atlas} == still_deferred


def test_mitre_atlas_ids_are_allow_listed() -> None:
    asserted = {code for m in standards_mapping() for code in m.mitre_atlas}
    assert asserted
    assert asserted <= set(MITRE_ATLAS_VERIFIED_TECHNIQUES)


def test_empty_owasp_llm_is_explicit_not_mapped() -> None:
    for m in standards_mapping():
        if not m.owasp_llm:
            assert m.status in ("partial", "deferred")


def test_validate_path_runs_standards_selfcheck(tmp_path: Path) -> None:
    from agentic_security_harness.validation import validate_path

    # An empty dir still triggers the corpus-level self-check (which must pass).
    (tmp_path / "empty").mkdir()
    result = validate_path(tmp_path / "empty")
    assert not any("standards-mapping" in e for e in result.errors)
