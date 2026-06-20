"""Tests for the local toy multi-agent handoff adapter."""

from agentic_security_harness.adapters import make_target
from agentic_security_harness.models import DefensivePattern, ExploitTrace
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.runner import HarnessRunner


def _pattern(pattern_id: str) -> DefensivePattern:
    return {pattern.pattern_id: pattern for pattern in seed_patterns()}[pattern_id]


def _observed_blob(trace: ExploitTrace) -> str:
    return "\n".join(
        [trace.observed_behavior, *(step.observed or "" for step in trace.steps)]
    )


def test_toy_multi_agent_partial_coverage() -> None:
    traces = HarnessRunner(make_target("toy-multi-agent")).run_many(seed_patterns())
    failed = [trace.pattern_id for trace in traces if trace.findings]

    assert failed == [
        "data_boundary_handoff_label_stripping",
        "capability.delegation_chain_drift",
    ]
    assert len([trace for trace in traces if not trace.findings]) == 21


def test_protected_toy_multi_agent_blocks_handoff_failures() -> None:
    traces = HarnessRunner(make_target("protected-toy-multi-agent")).run_many(seed_patterns())
    failed = [trace.pattern_id for trace in traces if trace.findings]

    assert failed == []
    assert len([trace for trace in traces if not trace.findings]) == 23


def test_toy_multi_agent_handoff_trace_has_before_after_envelope() -> None:
    target = make_target("toy-multi-agent")
    trace = HarnessRunner(target).run(_pattern("data_boundary_handoff_label_stripping"))

    assert trace.target.type == "toy_multi_agent"
    assert trace.findings
    assert trace.findings[0].broke_at == "label_check"
    assert {step.actor for step in trace.steps} == {"coordinator", "worker"}

    blob = _observed_blob(trace)
    assert "before_handoff envelope=" in blob
    assert "after_handoff envelope=missing" in blob
    assert "chain_of_custody=coordinator->worker" in blob
    assert "provenance_decision=missing_source_labels" in blob
    assert "verdict=blocked" in blob
    assert "failure_reasons=missing_provenance,label_loss" in blob
    assert "S_combined=1.00" in blob
    assert "authority_decision=overtrusted_unrestricted" in blob
    assert "consumed malformed summary as trusted fact" in blob
    assert "labels/provenance" in blob


def test_protected_toy_multi_agent_handoff_trace_blocks_consumption() -> None:
    target = make_target("protected-toy-multi-agent")
    trace = HarnessRunner(target).run(_pattern("data_boundary_handoff_label_stripping"))

    assert trace.target.type == "protected_toy_multi_agent"
    assert not trace.findings
    blob = _observed_blob(trace)
    assert "verdict=blocked" in blob
    assert "trusted_fact_consumed=false" in blob
    assert "S_structural=1.00" in blob
    assert "S_semantic=0.00" in blob


def test_toy_multi_agent_capability_trace_has_authority_drift() -> None:
    target = make_target("toy-multi-agent")
    trace = HarnessRunner(target).run(_pattern("capability.delegation_chain_drift"))

    assert trace.findings
    assert trace.findings[0].broke_at == "capability_check"
    assert {step.actor for step in trace.steps} == {"coordinator", "worker"}

    blob = _observed_blob(trace)
    assert "before_handoff capability=issuer:agent_a" in blob
    assert "after_handoff capability=issuer_chain:missing" in blob
    assert "authority_decision=expanded_scope" in blob
    assert "failure_reasons=authority_expansion" in blob
    assert "verdict=blocked" in blob
    assert "broader capability" in blob


def test_protected_toy_multi_agent_capability_trace_blocks_authority() -> None:
    target = make_target("protected-toy-multi-agent")
    trace = HarnessRunner(target).run(_pattern("capability.delegation_chain_drift"))

    assert not trace.findings
    blob = _observed_blob(trace)
    assert "verdict=blocked" in blob
    assert "failure_reasons=authority_expansion" in blob
    assert "trusted_authority_consumed=false" in blob


def test_toy_multi_agent_neutral_pass_for_unrelated_pattern() -> None:
    target = make_target("toy-multi-agent")
    trace = HarnessRunner(target).run(_pattern("budget.loop_abuse"))

    assert not trace.findings
    blob = _observed_blob(trace)
    assert "no multi-agent handoff surface" in blob
    assert "neutral pass" in blob


def test_toy_multi_agent_metadata_is_local_and_reproducible() -> None:
    target = make_target("toy-multi-agent")
    trace = HarnessRunner(target).run(_pattern("data_boundary_handoff_label_stripping"))

    assert trace.reproducibility["adapter_name"] == "toy-multi-agent"
    assert trace.reproducibility["adapter_version"] == "0.2"
    assert trace.reproducibility["runtime_name"] == "toy-coordinator-worker"
    assert trace.reproducibility["memory_mode"] == "session"
    assert trace.reproducibility["permission_model"] == "capability-token"
    assert trace.reproducibility["network_mode"] == "off"
    assert trace.reproducibility["provider_calls"] is False
    assert trace.reproducibility["capability_supported"] is True
    assert trace.reproducibility["safety_gates_passed"] is True
