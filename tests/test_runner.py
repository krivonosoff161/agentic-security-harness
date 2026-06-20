from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.models import (
    CapabilityCheckResult,
    DefensivePattern,
    HealthStatus,
    Observation,
    TargetMetadata,
    TraceStep,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.runner import HarnessRunner

SEED_ORDER = [
    "indirect_prompt_injection_via_tool_output",
    "data_boundary_recipient_confusion",
    "memory_poisoning_sanitized",
    "data_boundary_classification_mutation",
    "data_boundary_handoff_label_stripping",
    "tool_permission_abuse_sanitized",
    "provider_boundary_leakage_sanitized",
    "data_boundary_missing_envelope_recovery",
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
]


def test_load_seed_patterns_in_stable_order() -> None:
    assert [p.pattern_id for p in seed_patterns()] == SEED_ORDER


def test_runner_one_trace_per_pattern() -> None:
    patterns = seed_patterns()
    traces = HarnessRunner(MockTarget()).run_many(patterns)
    assert len(traces) == len(patterns)
    assert [t.pattern_id for t in traces] == [p.pattern_id for p in patterns]


def test_trace_ids_deterministic_and_unique() -> None:
    patterns = seed_patterns()
    runner = HarnessRunner(MockTarget())
    first = [t.trace_id for t in runner.run_many(patterns)]
    second = [t.trace_id for t in runner.run_many(patterns)]
    assert first == second
    assert all(tid.startswith("trc_") for tid in first)
    assert len(set(first)) == len(first)


def test_data_boundary_trace_has_immutable_envelope() -> None:
    traces = {t.pattern_id: t for t in HarnessRunner(MockTarget()).run_many(seed_patterns())}
    trace = traces["data_boundary_recipient_confusion"]
    assert trace.data_envelope is not None
    assert trace.data_envelope.classification_mutable is False
    assert trace.data_envelope.data_class == "confidential"


def test_no_real_secrets_in_traces() -> None:
    traces = HarnessRunner(MockTarget()).run_many(seed_patterns())
    blob = " ".join(t.model_dump_json() for t in traces)
    for marker in ("sk-", "AKIA", "BEGIN PRIVATE KEY"):
        assert marker not in blob


class LifecycleTarget:
    name = "lifecycle-target"

    def descriptor_fields(self) -> tuple[str, str, str]:
        return ("custom_target", self.name, "custom-adapter")

    def health(self) -> HealthStatus:
        return HealthStatus(
            ok=True,
            status="ready",
            message="ready",
            checks={"fixture": True},
        )

    def metadata(self, run_id: str) -> TargetMetadata:
        return TargetMetadata(
            adapter_name="custom-adapter",
            adapter_version="1.2.3",
            runtime_name="local-fixture",
            memory_mode="session",
            permission_model="capability-token",
            network_mode="local-only",
            provider_calls=False,
            run_id=run_id,
        )

    def capability_check(self, pattern: DefensivePattern) -> CapabilityCheckResult:
        return CapabilityCheckResult(
            pattern_id=pattern.pattern_id,
            supported=True,
            safety_gates_passed=True,
            reasons=[],
        )

    def observe(self, pattern: DefensivePattern) -> Observation:
        return Observation(
            steps=[TraceStep(index=0, actor="target", action=pattern.graph_path[0])],
            observed_behavior="ok",
            findings=[],
        )


def test_runner_calls_adapter_lifecycle_hooks() -> None:
    trace = HarnessRunner(LifecycleTarget()).run(seed_patterns()[0])

    assert trace.reproducibility["adapter_name"] == "custom-adapter"
    assert trace.reproducibility["adapter_version"] == "1.2.3"
    assert trace.reproducibility["runtime_name"] == "local-fixture"
    assert trace.reproducibility["memory_mode"] == "session"
    assert trace.reproducibility["network_mode"] == "local-only"
    assert trace.reproducibility["capability_supported"] is True
    assert trace.reproducibility["safety_gates_passed"] is True


class UnreadyTarget(LifecycleTarget):
    def health(self) -> HealthStatus:
        return HealthStatus(
            ok=False,
            status="misconfigured",
            message="missing fixture",
        )


def test_runner_refuses_unready_adapter() -> None:
    try:
        HarnessRunner(UnreadyTarget()).run(seed_patterns()[0])
    except RuntimeError as exc:
        assert "not ready" in str(exc)
    else:
        raise AssertionError("expected unready adapter to fail before observe")


class UnsupportedPatternTarget(LifecycleTarget):
    def capability_check(self, pattern: DefensivePattern) -> CapabilityCheckResult:
        return CapabilityCheckResult(
            pattern_id=pattern.pattern_id,
            supported=False,
            safety_gates_passed=False,
            reasons=["pattern requires unavailable fixture"],
        )


def test_runner_refuses_unsupported_pattern() -> None:
    try:
        HarnessRunner(UnsupportedPatternTarget()).run(seed_patterns()[0])
    except RuntimeError as exc:
        assert "unavailable fixture" in str(exc)
    else:
        raise AssertionError("expected unsupported pattern to fail before observe")
