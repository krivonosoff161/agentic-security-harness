"""Tests for the category-level standards mapping (Phase 7)."""

from pathlib import Path

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.standards_mapping import (
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
    assert len(ids) == 22
    assert len(set(ids)) == 22


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


def test_mitre_atlas_is_deferred_everywhere() -> None:
    # Honest default: ATLAS technique ids are not asserted yet.
    assert all(m.mitre_atlas == [] for m in standards_mapping())


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
