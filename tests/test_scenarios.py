"""Tests for scenario templates and variants."""

import pytest

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.scenarios import (
    get_scenario,
    get_variants,
    list_scenarios,
    scenario_ids,
)


def test_list_scenarios_returns_expected_families() -> None:
    scenarios = list_scenarios()
    ids = [s.scenario_id for s in scenarios]
    for expected in (
        "data-boundary",
        "memory-governance",
        "tool-selection",
        "authority-control",
        "approval-audit",
        "budget-control",
        "perception-boundary",
        "all",
    ):
        assert expected in ids


def test_scenario_ids_matches_list() -> None:
    assert scenario_ids() == [s.scenario_id for s in list_scenarios()]


def test_all_scenario_pattern_ids_exist_in_corpus() -> None:
    corpus = {entry.pattern_id for entry in corpus_manifest()}
    for scenario in list_scenarios():
        for pid in scenario.pattern_ids:
            msg = (
                f"scenario '{scenario.scenario_id}' references "
                f"unknown pattern '{pid}'"
            )
            assert pid in corpus, msg


def test_all_scenario_has_all_22_patterns() -> None:
    all_scenario = get_scenario("all")
    assert len(all_scenario.pattern_ids) == 22


def test_get_scenario_unknown_raises_key_error() -> None:
    with pytest.raises(KeyError, match="unknown scenario id"):
        get_scenario("nonexistent-scenario")


def test_each_scenario_has_title_and_description() -> None:
    for scenario in list_scenarios():
        assert scenario.title
        assert scenario.description
        assert len(scenario.title) > 3
        assert len(scenario.description) > 10


def test_each_scenario_has_safety_note() -> None:
    for scenario in list_scenarios():
        note = scenario.safety_note.lower()
        assert "mock-only" in note or "synthetic" in note


def test_non_all_scenarios_are_proper_subsets() -> None:
    all_patterns = set(get_scenario("all").pattern_ids)
    for scenario in list_scenarios():
        if scenario.scenario_id == "all":
            continue
        assert len(scenario.pattern_ids) > 0
        assert set(scenario.pattern_ids).issubset(all_patterns)


def test_no_duplicate_pattern_ids_within_scenario() -> None:
    for scenario in list_scenarios():
        assert len(scenario.pattern_ids) == len(set(scenario.pattern_ids))


def test_every_scenario_has_variants() -> None:
    for scenario in list_scenarios():
        assert len(scenario.variants) > 0, (
            f"scenario '{scenario.scenario_id}' has no variants"
        )


def test_variant_ids_unique_within_scenario() -> None:
    for scenario in list_scenarios():
        ids = [v.variant_id for v in scenario.variants]
        assert len(ids) == len(set(ids)), (
            f"scenario '{scenario.scenario_id}' has duplicate variant ids"
        )


def test_variant_has_required_fields() -> None:
    for scenario in list_scenarios():
        for v in scenario.variants:
            assert v.variant_id
            assert v.title
            assert isinstance(v.knobs, dict)


def test_get_variants_respects_max() -> None:
    all_scenario = get_scenario("all")
    total = len(all_scenario.variants)
    variants = get_variants("all", max_variants=2)
    assert len(variants) == 2
    assert len(variants) <= total


def test_get_variants_single_filter() -> None:
    variants = get_variants("all", only_variant_id="baseline-all")
    assert len(variants) == 1
    assert variants[0].variant_id == "baseline-all"


def test_get_variants_unknown_filter_raises() -> None:
    with pytest.raises(KeyError, match="unknown variant"):
        get_variants("all", only_variant_id="bogus-variant")


def test_scenario_variant_counts() -> None:
    expected = {
        "data-boundary": 3,
        "memory-governance": 3,
        "tool-selection": 3,
        "authority-control": 2,
        "approval-audit": 3,
        "budget-control": 2,
        "perception-boundary": 2,
        "all": 4,
    }
    for scenario in list_scenarios():
        assert len(scenario.variants) == expected[scenario.scenario_id]
