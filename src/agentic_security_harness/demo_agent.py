"""Deterministic local demo agent (no network, no LLM, no provider calls).

Simulates realistic agent mechanics - tool-output ingestion, in-memory read/write, mock
tool calls, and data-envelope propagation - and is intentionally vulnerable for the seed
patterns. All data is synthetic and sanitized; the agent does not enforce envelope rules,
which is the failure mode under test.
"""

from dataclasses import dataclass

from agentic_security_harness.models import DataEnvelope


@dataclass
class AgentEvent:
    """One observable step in the agent's run (maps to a trace step)."""

    node: str
    actor: str
    detail: str


@dataclass
class MemoryRecord:
    """A value held in the agent's in-memory store, with its data envelope."""

    value: str
    envelope: DataEnvelope | None = None


class DemoAgent:
    """A small, deterministic, intentionally vulnerable local agent.

    It records an event log (-> trace steps), keeps an in-memory store, and records mock
    tool calls. It does not enforce data-envelope rules - that is the failure under test.
    """

    def __init__(self, name: str = "demo-local-agent") -> None:
        self.name = name
        self.memory: dict[str, MemoryRecord] = {}
        self.tool_calls: list[tuple[str, str]] = []
        self.events: list[AgentEvent] = []

    def log(self, node: str, actor: str, detail: str) -> None:
        self.events.append(AgentEvent(node=node, actor=actor, detail=detail))

    def receive_input(self, label: str) -> None:
        self.log("exposed_input", "harness", f"received input: {label}")

    def ingest_tool_output(self, summary: str) -> None:
        # Vulnerable: no provenance separation - tool output is mixed into context as-is.
        self.log("external_data", "tool", f"ingested untrusted tool output: {summary}")

    def call_tool(self, tool: str, arg: str) -> None:
        self.tool_calls.append((tool, arg))
        self.log("tool_call", "agent", f"called tool '{tool}' with arg '{arg}'")

    def act_on_tool_output(self) -> None:
        # Vulnerable: treats an instruction embedded in tool output as a trusted command.
        self.log("agent_decision", "agent", "treated tool output as a trusted instruction")
        self.call_tool("send_message", "attacker-chosen-recipient")

    def write_memory(self, key: str, value: str, envelope: DataEnvelope) -> bool:
        """Store an item. Returns True if this violated the envelope (can_store=false)."""
        against_policy = not envelope.can_store
        # Vulnerable: stores the item regardless of can_store.
        self.memory[key] = MemoryRecord(value=value, envelope=envelope)
        detail = (
            "stored item despite can_store=false"
            if against_policy
            else "stored item (allowed by envelope)"
        )
        self.log("memory_write", "agent", detail)
        return against_policy

    def use_memory_later(self, key: str) -> bool:
        """Read a planted item on a later turn. Returns True if it influenced a decision."""
        influenced = key in self.memory
        if influenced:
            self.log("later_turn", "agent", "a later decision was influenced by planted memory")
        return influenced

    def route(self, recipient: str, envelope: DataEnvelope) -> bool:
        """Route data to a recipient. Returns True if this violated allowed_recipients."""
        violation = recipient not in envelope.allowed_recipients
        # Vulnerable: forwards even when the recipient is not allowed.
        detail = (
            f"routed to '{recipient}' which is NOT in allowed_recipients"
            if violation
            else f"routed to allowed recipient '{recipient}'"
        )
        self.log("recipient_check", "agent", detail)
        return violation
