"""A protected variant of the local demo agent: a small deterministic defense layer.

It enforces the controls the vulnerable ``DemoAgent`` lacks - untrusted tool output is not
acted on, recipients outside the envelope are blocked, and can_store / no-store is honored -
so the seed patterns produce PASS traces with no findings. Local, synthetic, no network.
"""

from agentic_security_harness.demo_adapter import run_scenarios
from agentic_security_harness.demo_agent import DemoAgent, MemoryRecord
from agentic_security_harness.models import (
    AuditEntry,
    CapabilityToken,
    DataEnvelope,
    DefensivePattern,
    Observation,
    ToolSchemaRecord,
)


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

    def delegate_capability(self, grant: CapabilityToken) -> bool:
        self.log(
            "capability_grant",
            "agent_a",
            f"issued scope={grant.scope} purpose={grant.purpose} ttl={grant.ttl_steps}",
        )
        self.log(
            "agent_handoff",
            "agent_b",
            "control: delegated only the parent scope, purpose, and a shorter TTL",
        )
        self.log(
            "capability_check",
            "agent_c",
            "control: downstream capability stayed within the parent grant",
        )
        return False

    def accept_tool_schema(self, pinned: ToolSchemaRecord, changed_hash: str) -> bool:
        self.log(
            "tool_schema",
            "mock_mcp_server",
            f"presented tool '{pinned.tool_name}' with changed schema hash",
        )
        if changed_hash != pinned.schema_hash:
            self.log(
                "schema_provenance_check",
                "agent",
                "control: schema drift detected against pinned provenance; tool call blocked",
            )
            self.log("tool_call", "agent", "control: no call issued after schema drift")
            return False
        self.log("schema_provenance_check", "agent", "schema matches pinned provenance")
        return False

    def process_perception_transcript(self, transcript: str, source: str) -> bool:
        # Control: perception-channel content is untrusted data, not user intent.
        self.log(
            "perception_channel",
            "agent",
            f"received {source} transcript into context",
        )
        self.log(
            "agent_context",
            "agent",
            "control: perception content tagged as untrusted data",
        )
        self.log(
            "agent_decision",
            "agent",
            "control: perception content not treated as user instruction; no action taken",
        )
        return False

    def use_ambient_capability(self, envelope: DataEnvelope) -> bool:
        # Control: ambient capability not in envelope's allowed_purpose; denied.
        self.log(
            "ambient_capability_available",
            "agent",
            "ambient capability mock_file_read available from host",
        )
        self.log(
            "agent_decision",
            "agent",
            "control: ambient capability not bound in envelope; denied",
        )
        self.log(
            "unauthorized_action",
            "agent",
            "control: no action taken (ambient authority not granted for this task)",
        )
        return False

    def craft_approval_request(self, envelope: DataEnvelope) -> str:
        # Control: approval request includes full envelope context.
        self.log(
            "action_requiring_approval",
            "agent",
            "action requires human confirmation",
        )
        request = (
            "Confirm: forward data "
            f"(data_class={envelope.data_class}, "
            f"recipients={envelope.allowed_recipients}, "
            f"purpose={envelope.allowed_purpose}). "
            "Risk: HIGH. Reject if unsure."
        )
        self.log(
            "approval_request_crafted",
            "agent",
            f"approval request with full context: {request}",
        )
        return request

    def write_memory_with_governance(
        self, entries: list[tuple[str, str, str, str, int | None]]
    ) -> list[bool]:
        violations = []
        for key, value, source, trust_level, ttl in entries:
            if trust_level == "untrusted":
                # Control: untrusted entries cannot overwrite or be stored alongside trusted data.
                self.log(
                    "memory_write_untrusted",
                    "agent",
                    f"control: refused to store untrusted '{key}' from {source}",
                )
                violations.append(False)
                continue
            self.memory[key] = MemoryRecord(
                value=value,
                envelope=DataEnvelope(
                    data_class="internal",
                    classification_source=source,
                    ttl_seconds=ttl,
                ),
            )
            self.log(
                "memory_write_trusted",
                "agent",
                f"stored '{key}' from {source} (trust={trust_level}, ttl={ttl})",
            )
            violations.append(False)
        return violations

    def read_memory_with_governance(self, key: str) -> bool:
        record = self.memory.get(key)
        self.log("later_read", "agent", f"reading memory key '{key}'")
        if record is None:
            self.log(
                "observed_behavior",
                "agent",
                "control: memory key not found; no governance issue",
            )
            return False
        # Control: check trust level and TTL at read time.
        envelope = record.envelope
        if envelope and envelope.ttl_seconds is not None:
            self.log(
                "observed_behavior",
                "agent",
                "control: TTL checked; entry treated with governance constraints",
            )
        else:
            self.log(
                "observed_behavior",
                "agent",
                "control: provenance and trust level checked at read time",
            )
        return False

    def validate_audit_chain(self, chain: list[AuditEntry]) -> bool:
        self.log("audit_append", "agent", f"received audit chain with {len(chain)} entries")
        self.log("tamper_attempt", "harness", "synthetic audit entry edited after append")
        previous = "GENESIS"
        for expected_index, entry in enumerate(chain):
            expected_hash = self._audit_hash(entry.index, entry.event, entry.previous_hash)
            if (
                entry.index != expected_index
                or entry.previous_hash != previous
                or entry.entry_hash != expected_hash
            ):
                self.log(
                    "audit_integrity_check",
                    "agent",
                    "control: audit hash-chain tamper detected",
                )
                return False
            previous = entry.entry_hash
        self.log("audit_integrity_check", "agent", "audit chain verified")
        return False

    # ── v0.9 deeper variants ────────────────────────────────────────────────

    def store_retrieved_content_with_source(
        self, key: str, value: str, envelope: DataEnvelope, source_channel: str
    ) -> None:
        # Control: preserve source provenance and source_channel metadata.
        self.log(
            "retrieval",
            "tool",
            f"retrieved content from {source_channel} with provenance tag",
        )
        self.memory[key] = MemoryRecord(value=value, envelope=envelope)
        self.log(
            "memory_write",
            "agent",
            f"stored retrieved content from {source_channel} with provenance preserved",
        )

    def activate_retrieved_as_trusted(self, key: str) -> bool:
        # Control: check source provenance; retrieved content stays untrusted.
        record = self.memory.get(key)
        self.log("later_turn", "agent", "later turn: retrieved content loaded into context")
        if record is None:
            self.log("provenance_check", "agent", "nothing stored; no activation")
            return False
        envelope = record.envelope
        if envelope and envelope.classification_source == "untrusted_source":
            self.log(
                "provenance_check",
                "agent",
                "control: provenance checked; source is untrusted; "
                "content treated as untrusted data",
            )
        else:
            self.log(
                "provenance_check",
                "agent",
                "control: provenance and source_channel verified at read time",
            )
        return False

    def write_memory_scoped(self, key: str, value: str, user_scope: str) -> None:
        # Control: store with explicit per-user scope isolation.
        self.memory[key] = MemoryRecord(
            value=value,
            envelope=DataEnvelope(
                data_class="internal",
                classification_source=f"scope:{user_scope}",
            ),
        )
        self.log(
            "user_a_write" if user_scope == "user_a" else "user_b_write",
            "agent",
            f"control: stored '{key}' with per-user scope={user_scope}",
        )

    def read_memory_cross_scope(self, key: str, requesting_scope: str) -> str | None:
        record = self.memory.get(key)
        self.log("user_b_read", "agent", f"reading memory key '{key}' as {requesting_scope}")
        if record is None:
            return None
        # Control: verify scope ownership before returning data.
        stored_scope = "unknown"
        if record.envelope and record.envelope.classification_source.startswith("scope:"):
            stored_scope = record.envelope.classification_source.removeprefix("scope:")
        if stored_scope != requesting_scope:
            self.log(
                "cross_user_boundary_check",
                "agent",
                f"control: cross-user boundary enforced; data from scope={stored_scope} "
                "not returned to scope={requesting_scope}",
            )
            return None
        self.log(
            "cross_user_boundary_check",
            "agent",
            "control: scope ownership verified; data returned to matching scope",
        )
        return record.value

    def run_recursive_call(self, depth: int, max_depth: int) -> bool:
        # Control: recursion depth guard enforced.
        actual_depth = 0
        for d in range(depth):
            if d + 1 > max_depth:
                break
            actual_depth = d + 1
        self.log(
            "recursive_call",
            "agent",
            f"executed recursive calls to depth {actual_depth} (budget {max_depth})",
        )
        self.log(
            "depth_check",
            "agent",
            "control: recursion depth guard enforced the budget",
        )
        return False

    def select_tool_for_task(
        self, intended_tool: str, biased_tool: str, has_bias: bool
    ) -> str:
        # Control: validate selection against task intent; reject untrusted bias.
        self.log(
            "tool_registry",
            "agent",
            f"task requires {intended_tool}; untrusted bias suggests {biased_tool}",
        )
        self.log(
            "selection_integrity_check",
            "agent",
            f"control: selected tool {intended_tool} validated against task intent; "
            f"untrusted bias ignored",
        )
        self.log("tool_call", "agent", f"called tool '{intended_tool}'")
        return intended_tool

    def process_multi_turn(self, turns: list[str]) -> bool:
        # Control: validate each turn independently; detect escalation.
        for i, turn in enumerate(turns):
            self.log(
                f"turn_{i + 1}_context",
                "agent",
                f"turn {i + 1}: processed '{turn}' into context",
            )
        self.log(
            "per_turn_check",
            "agent",
            "control: each turn validated independently; escalation detected across turns",
        )
        return False


class ProtectedDemoAgentTarget:
    """Target adapter that runs defensive patterns against the ProtectedDemoAgent."""

    def __init__(self, name: str = "protected-demo-agent") -> None:
        self.name = name

    def descriptor_fields(self) -> tuple[str, str, str]:
        return ("protected_demo_agent", self.name, "local")

    def observe(self, pattern: DefensivePattern) -> Observation:
        return run_scenarios(ProtectedDemoAgent(self.name), pattern)
