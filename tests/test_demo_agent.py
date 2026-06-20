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
        "data_boundary_classification_mutation": "classification_check",
        "data_boundary_handoff_label_stripping": "label_check",
        "tool_permission_abuse_sanitized": "tool_permission_check",
        "provider_boundary_leakage_sanitized": "forward_check",
        "data_boundary_missing_envelope_recovery": "envelope_check",
        "data_boundary_memory_envelope_drift": "envelope_drift_check",
        "sleeping_prompt.delayed_activation": "provenance_check",
        "audit.spam_label_abuse": "audit_check",
        "budget.loop_abuse": "budget_check",
        "capability.delegation_chain_drift": "capability_check",
        "mcp.tool_schema_deception": "schema_provenance_check",
        "audit.hash_chain_tamper": "audit_integrity_check",
        "perception_boundary.sensor_command_confusion": "perception_trust_check",
        "ambient_authority.environmental_privilege_escalation": "authority_binding_check",
        "approval_laundering.underjustified_confirmation": "approval_context_check",
        "memory_governance.unscoped_memory_persistence": "memory_governance_check",
        "memory_governance.environment_injected_poisoning": "provenance_check",
        "memory_governance.unintentional_cross_user": "cross_user_boundary_check",
        "budget.recursive_execution_amplification": "recursion_depth_check",
        "mcp.tool_selection_manipulation": "selection_integrity_check",
        "indirect_instruction.multi_turn_escalation": "per_turn_check",
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
    assert len(_traces()) == 24


def test_demo_traces_deterministic() -> None:
    assert traces_to_json(_traces()) == traces_to_json(_traces())


def test_scorecard_matches_expected() -> None:
    card = build_scorecard(_traces())
    assert card.target_name == "demo-local-agent"
    assert card.findings_by_severity == {"high": 22, "medium": 2}
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
