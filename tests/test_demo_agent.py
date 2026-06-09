from pathlib import Path

import pytest

from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.demo_agent import DemoAgent
from agentic_security_harness.models import DataEnvelope, ExploitTrace
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import (
    build_summary_md,
    scorecard_to_json,
    traces_to_json,
)
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "demo-agent-report"

SEED_IDS = {
    "indirect_prompt_injection_via_tool_output",
    "data_boundary_recipient_confusion",
    "memory_poisoning_sanitized",
}


def _traces() -> list[ExploitTrace]:
    return HarnessRunner(DemoAgentTarget()).run_many(seed_patterns())


def _norm(text: str) -> str:
    return text.replace("\r\n", "\n")


def test_demo_agent_handles_all_seed_patterns() -> None:
    by_id = {t.pattern_id: t for t in _traces()}
    assert set(by_id) == SEED_IDS
    broke_at = {pid: trace.findings[0].broke_at for pid, trace in by_id.items()}
    assert broke_at == {
        "indirect_prompt_injection_via_tool_output": "agent_decision",
        "data_boundary_recipient_confusion": "recipient_check",
        "memory_poisoning_sanitized": "memory_write",
    }
    target = by_id["memory_poisoning_sanitized"].target
    assert target.adapter == "local"
    assert target.name == "demo-local-agent"


def test_trace_steps_follow_graph_path() -> None:
    for trace in _traces():
        assert [step.action for step in trace.steps] == trace.graph_path


def test_envelope_recipient_control_survives_or_fails() -> None:
    agent = DemoAgent()
    env = DataEnvelope(data_class="confidential", allowed_recipients=["agent_a"])
    assert agent.route("agent_a", env) is False  # allowed recipient -> survives
    assert agent.route("agent_b", env) is True  # disallowed recipient -> fails


def test_envelope_no_store_survives_or_fails() -> None:
    agent = DemoAgent()
    assert agent.write_memory("k", "v", DataEnvelope(can_store=False)) is True  # violation
    assert agent.write_memory("k2", "v", DataEnvelope(can_store=True)) is False  # allowed


def test_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def _boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("network call attempted")

    monkeypatch.setattr(socket, "socket", _boom)
    assert len(_traces()) == 3


def test_demo_traces_deterministic() -> None:
    assert traces_to_json(_traces()) == traces_to_json(_traces())


def test_scorecard_matches_expected() -> None:
    card = build_scorecard(_traces())
    assert card.target_name == "demo-local-agent"
    assert card.findings_by_severity == {"high": 2, "medium": 1}
    assert set(card.failed_patterns) == SEED_IDS
    assert card.passed_patterns == []


def test_committed_example_matches_code() -> None:
    traces = _traces()
    scorecard = build_scorecard(traces)
    assert _norm((EXAMPLE_DIR / "traces.json").read_text(encoding="utf-8")) == _norm(
        traces_to_json(traces)
    )
    assert _norm((EXAMPLE_DIR / "scorecard.json").read_text(encoding="utf-8")) == _norm(
        scorecard_to_json(scorecard)
    )
    assert _norm((EXAMPLE_DIR / "summary.md").read_text(encoding="utf-8")) == _norm(
        build_summary_md(scorecard, traces)
    )
