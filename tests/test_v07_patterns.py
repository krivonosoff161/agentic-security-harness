"""Focused tests for the v0.7 authority / integrity corpus slice."""

from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.demo_agent import DemoAgent
from agentic_security_harness.models import CapabilityToken, ExploitTrace
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.protected_demo_agent import ProtectedDemoAgent
from agentic_security_harness.runner import HarnessRunner

V07_IDS = {
    "capability.delegation_chain_drift",
    "mcp.tool_schema_deception",
    "audit.hash_chain_tamper",
}


def _baseline_by_id() -> dict[str, ExploitTrace]:
    traces = HarnessRunner(DemoAgentTarget()).run_many(seed_patterns())
    return {trace.pattern_id: trace for trace in traces}


def test_v07_patterns_are_present_in_stable_order() -> None:
    ids = [pattern.pattern_id for pattern in seed_patterns()]
    assert ids[-4:] == [
        "perception_boundary.sensor_command_confusion",
        "ambient_authority.environmental_privilege_escalation",
        "approval_laundering.underjustified_confirmation",
        "memory_governance.unscoped_memory_persistence",
    ]


def test_v07_baseline_findings_have_expected_breakpoints() -> None:
    traces = _baseline_by_id()
    assert set(traces).issuperset(V07_IDS)
    assert traces["capability.delegation_chain_drift"].findings[0].broke_at == (
        "capability_check"
    )
    assert traces["mcp.tool_schema_deception"].findings[0].broke_at == (
        "schema_provenance_check"
    )
    assert traces["audit.hash_chain_tamper"].findings[0].broke_at == "audit_integrity_check"


def test_capability_delegation_baseline_expands_parent_grant() -> None:
    agent = DemoAgent()
    grant = CapabilityToken(
        issuer="agent_a",
        subject="agent_b",
        scope=["read"],
        purpose="summarize",
        ttl_steps=2,
        can_delegate=True,
    )
    assert agent.delegate_capability(grant) is True


def test_protected_audit_chain_rejects_tamper() -> None:
    agent = ProtectedDemoAgent()
    chain = agent.build_audit_chain(["input_received", "tool_call_blocked"])
    tampered = list(chain)
    tampered[1] = tampered[1].model_copy(update={"event": "tool_call_allowed"})
    assert agent.validate_audit_chain(tampered) is False
    assert agent.events[-1].node == "audit_integrity_check"
    assert "tamper detected" in agent.events[-1].detail
