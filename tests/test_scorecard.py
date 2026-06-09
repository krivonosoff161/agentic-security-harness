from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard

SEED_IDS = {
    "indirect_prompt_injection_via_tool_output",
    "data_boundary_recipient_confusion",
    "memory_poisoning_sanitized",
    "data_boundary_classification_mutation",
    "data_boundary_handoff_label_stripping",
    "tool_permission_abuse_sanitized",
    "provider_boundary_leakage_sanitized",
}


def _traces() -> list:
    return HarnessRunner(MockTarget()).run_many(seed_patterns())


def test_total_traces_matches() -> None:
    traces = _traces()
    card = build_scorecard(traces)
    assert card.total_traces == len(traces) == 7
    assert card.target_name == "demo-mock-agent"


def test_severity_counts() -> None:
    card = build_scorecard(_traces())
    assert card.findings_by_severity.get("high") == 6
    assert card.findings_by_severity.get("medium") == 1


def test_failed_patterns_include_seeds() -> None:
    card = build_scorecard(_traces())
    assert set(card.failed_patterns) == SEED_IDS
    assert card.passed_patterns == []


def test_scorecard_deterministic() -> None:
    first = build_scorecard(_traces())
    second = build_scorecard(_traces())
    assert first.model_dump() == second.model_dump()
