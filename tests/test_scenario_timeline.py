"""Deterministic tests for the scenario timeline contract and fixtures."""

import json
from pathlib import Path

import pytest

from agentic_security_harness.scenario_timeline import (
    ScenarioTimeline,
    validate_timeline,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "timelines"
TIMELINE_DOC = ROOT / "docs" / "scenario-timeline.md"

# The three failure classes the contract must actually represent (issue #20).
_EXPECTED_CLASSES = {
    "multi_turn_delayed_activation",
    "context_overload_priority_drift",
    "handoff_provenance",
}


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_three_timeline_classes_are_present() -> None:
    classes = {_load(p)["failure_class"] for p in _fixture_files()}
    assert classes == _EXPECTED_CLASSES


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
def test_committed_timeline_fixture_is_valid(path: Path) -> None:
    assert validate_timeline(_load(path)) == []


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
def test_fixture_has_required_contract_fields(path: Path) -> None:
    tl = ScenarioTimeline.model_validate(_load(path))
    assert tl.actors  # actors derived from steps
    assert len(tl.steps) >= 2
    assert tl.invariant
    assert tl.expected_vulnerable_behavior and tl.expected_protected_behavior
    assert tl.expected_vulnerable_behavior != tl.expected_protected_behavior
    assert tl.validator_expectations
    assert "trace" in tl.trace_evidence


def test_missing_invariant_fails_closed() -> None:
    raw = _load(_fixture_files()[0])
    del raw["invariant"]
    errors = validate_timeline(raw)
    assert errors and any("invariant" in e for e in errors)


def test_missing_trace_evidence_fails_closed() -> None:
    raw = _load(_fixture_files()[0])
    del raw["trace_evidence"]
    assert validate_timeline(raw)  # schema rejects the missing required field

    raw2 = _load(_fixture_files()[0])
    raw2["trace_evidence"] = ["scorecard"]  # present but no trace
    errors = validate_timeline(raw2)
    assert any("trace" in e for e in errors)


def test_swapped_protected_vulnerable_expectation_fails_closed() -> None:
    raw = _load(_fixture_files()[0])
    ve = raw["validator_expectations"][0]
    ve["on_vulnerable"], ve["on_protected"] = ve["on_protected"], ve["on_vulnerable"]
    errors = validate_timeline(raw)
    assert any("expectations must be" in e for e in errors)


def test_identical_expected_behaviors_fail_closed() -> None:
    raw = _load(_fixture_files()[0])
    raw["expected_protected_behavior"] = raw["expected_vulnerable_behavior"]
    errors = validate_timeline(raw)
    assert any("identical" in e for e in errors)


def test_unknown_actor_fails_closed() -> None:
    raw = _load(_fixture_files()[0])
    raw["steps"][1]["actor"] = "attacker"  # not in the allowed actor set
    errors = validate_timeline(raw)
    assert any("unknown actor" in e for e in errors)


def test_no_pressure_step_fails_closed() -> None:
    raw = _load(_fixture_files()[0])
    for step in raw["steps"]:
        step["trust_zone"] = "trusted"  # remove all non-trusted pressure
    errors = validate_timeline(raw)
    assert any("pressure step" in e for e in errors)


def test_extra_field_is_rejected() -> None:
    raw = _load(_fixture_files()[0])
    raw["marketing_blurb"] = "best ever"
    assert validate_timeline(raw)  # extra="forbid"


def test_non_object_input_is_rejected() -> None:
    assert validate_timeline(["not", "a", "timeline"])


def test_doc_matches_committed_fixtures() -> None:
    # The timeline doc must list the committed timeline ids so docs and fixtures stay in sync.
    doc = TIMELINE_DOC.read_text(encoding="utf-8")
    for path in _fixture_files():
        assert _load(path)["timeline_id"] in doc
    # And it must not claim real multi-turn agents are fully covered.
    lowered = doc.lower()
    assert "not a live multi-agent runtime" in lowered or "not a claim" in lowered
