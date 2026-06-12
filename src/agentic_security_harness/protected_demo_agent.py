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

    def attempt_relabel(self, envelope: DataEnvelope, new_class: str, source: str) -> bool:
        if not envelope.classification_mutable and source != envelope.classification_source:
            self.log(
                "classification_check", "agent", "control: refused relabel from untrusted source"
            )
            return False
        self.log(
            "classification_check", "agent", f"classification changed to '{new_class}' (authorized)"
        )
        return False

    def handoff_to_peer(self, envelope: DataEnvelope) -> bool:
        self.log("handoff", "agent", "handed off the item to a peer agent")
        self.log("label_check", "agent", "control: envelope propagated to peer (labels preserved)")
        return False

    def call_tool_for_purpose(self, tool: str, purpose: str, envelope: DataEnvelope) -> bool:
        if purpose not in envelope.allowed_purpose:
            self.log(
                "tool_permission_check", "agent", f"control: '{purpose}' not in allowed_purpose"
            )
            self.log("tool_call", "agent", "control: tool call blocked (out of purpose)")
            return False
        self.tool_calls.append((tool, purpose))
        self.log("tool_permission_check", "agent", f"purpose '{purpose}' allowed")
        self.log("tool_call", "agent", f"called '{tool}' for '{purpose}'")
        return False

    def route_to_provider(self, envelope: DataEnvelope) -> bool:
        self.log("provider_routing", "agent", "routing the item to a mock external provider")
        if not envelope.can_forward:
            self.log("forward_check", "agent", "control: can_forward=false; forwarding blocked")
            return False
        self.log("forward_check", "agent", "can_forward=true; item forwarded")
        return False

    def store_retrieved_content(self, key: str, value: str, envelope: DataEnvelope) -> None:
        # Control: keep the envelope (provenance + TTL) attached to the stored record.
        self.memory[key] = MemoryRecord(value=value, envelope=envelope)
        self.log(
            "memory_write", "agent", "stored retrieved content with provenance and TTL preserved"
        )

    def activate_dormant_content(self, key: str) -> bool:
        # Control: retrieved memory stays untrusted; a dormant instruction never activates.
        self.log("later_turn", "agent", "later turn: stored content retrieved into context")
        self.log(
            "provenance_check",
            "agent",
            "control: provenance preserved; retrieved content treated as untrusted; "
            "activation blocked",
        )
        return False

    def record_audit_event(
        self, event: str, label: str, label_source: str, envelope: DataEnvelope
    ) -> bool:
        # Control: labels never suppress audit; the event is logged regardless of source.
        self.audit_log.append(event)
        self.log(
            "audit_check",
            "agent",
            f"control: label '{label}' ignored for audit; event logged regardless of source",
        )
        return False

    def run_loop(self, iterations: int, max_steps: int) -> bool:
        # Control: a loop guard stops the run at the step budget.
        executed = 0
        for _ in range(iterations):
            if executed >= max_steps:
                break
            executed += 1
        self.log(
            "loop_iteration",
            "agent",
            f"executed {executed} synthetic loop iterations (budget {max_steps})",
        )
        self.log("budget_check", "agent", "control: loop guard stopped the run at the budget")
        return False


class ProtectedDemoAgentTarget:
    """Target adapter that runs defensive patterns against the ProtectedDemoAgent."""

    def __init__(self, name: str = "protected-demo-agent") -> None:
        self.name = name

    def descriptor_fields(self) -> tuple[str, str, str]:
        return ("protected_demo_agent", self.name, "local")

    def observe(self, pattern: DefensivePattern) -> Observation:
        return run_scenarios(ProtectedDemoAgent(self.name), pattern)
