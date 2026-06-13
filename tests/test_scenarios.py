"""Tests for scenario templates."""

import pytest

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.scenarios import get_scenario, list_scenarios, scenario_ids


def test_list_scenarios_returns_expected_families() -> None:
    scenarios = list_scenarios()
    ids = [s.scenario_id for s in scenarios]
    assert "data-boundary" in ids
    assert "memory-governance" in ids
    assert "tool-selection" in ids
    assert "authority-control" in ids
    assert "approval-audit" in ids
    assert "budget-control" in ids
    assert "perception-boundary" in ids
    assert "all" in ids


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
