"""A protected variant of the local demo agent: a small deterministic defense layer.

It enforces the controls the vulnerable ``DemoAgent`` lacks - untrusted tool output is not
acted on, recipients outside the envelope are blocked, and can_store / no-store is honored -
so the seed patterns produce PASS traces with no findings. Local, synthetic, no network.
"""

from agentic_security_harness.demo_adapter import run_scenarios
from agentic_security_harness.demo_agent import DemoAgent, MemoryRecord
from agentic_security_harness.models import DataEnvelope, DefensivePattern, Observation


class ProtectedDemoAgent(DemoAgent):
    """DemoAgent with deterministic controls that mitigate the seed patterns."""

    def __init__(self, name: str = "protected-demo-agent") -> None:
        super().__init__(name)

    def act_on_tool_output(self) -> bool:
        # Control: tool output is untrusted; do not act on embedded instructions.
        self.log(
            "agent_decision",
            "agent",
            "control: tool output treated as untrusted; instruction ignored",
        )
        self.log("tool_call", "agent", "control: no tool call issued from untrusted content")
        return False

    def write_memory(self, key: str, value: str, envelope: DataEnvelope) -> bool:
        if not envelope.can_store:
            self.log("memory_write", "agent", "control: refused to store (can_store=false)")
            return False
        self.memory[key] = MemoryRecord(value=value, envelope=envelope)
        self.log("memory_write", "agent", "stored item (allowed by envelope)")
        return False

    def route(self, recipient: str, envelope: DataEnvelope) -> bool:
        if recipient not in envelope.allowed_recipients:
            self.log(
                "recipient_check",
                "agent",
                f"control: blocked routing to '{recipient}' (not in allowed_recipients)",
            )
            return False
        self.log("recipient_check", "agent", f"routed to allowed recipient '{recipient}'")
        return False


class ProtectedDemoAgentTarget:
    """Target adapter that runs defensive patterns against the ProtectedDemoAgent."""

    def __init__(self, name: str = "protected-demo-agent") -> None:
        self.name = name

    def descriptor_fields(self) -> tuple[str, str, str]:
        return ("protected_demo_agent", self.name, "local")

    def observe(self, pattern: DefensivePattern) -> Observation:
        return run_scenarios(ProtectedDemoAgent(self.name), pattern)
