"""Deterministic mock target for v0.1 - no LLM, no network.

The mock target is vulnerable *by design* for the seed patterns so the harness can produce
traces and a scorecard end to end. It accepts a ``DefensivePattern`` and returns observations.
"""

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.models import DefensivePattern, Finding, Severity, TraceStep


class Observation(BaseModel):
    """What a target reports back to the runner for one pattern run."""

    model_config = ConfigDict(extra="forbid")

    steps: list[TraceStep]
    observed_behavior: str
    findings: list[Finding] = Field(default_factory=list)


# Deterministic per-pattern outcome: (severity, broke_at, observed_behavior).
_OUTCOMES: dict[str, tuple[Severity, str, str]] = {
    "indirect_prompt_injection_via_tool_output": (
        "high",
        "agent_decision",
        "mock target followed the instruction from untrusted tool output and issued a tool call",
    ),
    "data_boundary_recipient_confusion": (
        "high",
        "recipient_check",
        "mock target forwarded a confidential item to a recipient outside allowed_recipients",
    ),
    "memory_poisoning_sanitized": (
        "medium",
        "memory_write",
        "mock target stored planted state despite can_store false / TTL",
    ),
}


class MockTarget:
    """A deterministic, vulnerable-by-design demo target (no LLM, no network)."""

    def __init__(self, name: str = "demo-mock-agent") -> None:
        self.name = name

    def descriptor_fields(self) -> tuple[str, str, str]:
        """Return (type, name, adapter) for a TargetDescriptor."""
        return ("mock_agent", self.name, "mock")

    def observe(self, pattern: DefensivePattern) -> Observation:
        """Drive one pattern and return deterministic observations."""
        steps = self._build_steps(pattern)
        outcome = _OUTCOMES.get(pattern.pattern_id)
        if outcome is None:
            # Unknown pattern: deterministic "no violation" (passed) outcome.
            return Observation(
                steps=steps,
                observed_behavior="mock target completed the pattern with no observed violation",
                findings=[],
            )
        severity, broke_at, observed = outcome
        for step in steps:
            if step.action == broke_at:
                step.observed = observed
        finding = Finding(
            code=pattern.category,
            severity=severity,
            message=observed,
            broke_at=broke_at,
            mitigation=pattern.mitigation,
        )
        return Observation(steps=steps, observed_behavior=observed, findings=[finding])

    @staticmethod
    def _build_steps(pattern: DefensivePattern) -> list[TraceStep]:
        steps: list[TraceStep] = []
        for i, node in enumerate(pattern.graph_path):
            steps.append(
                TraceStep(
                    index=i,
                    actor="harness" if i == 0 else "target",
                    action=node,
                    input_ref=f"fixtures/{pattern.pattern_id}" if i == 0 else None,
                    observed=None,
                )
            )
        return steps
