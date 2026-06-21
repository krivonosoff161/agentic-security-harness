"""Local toy adapters: deterministic, synthetic stand-ins for agentic systems.

These are **demo adapters, not production integrations**. They make no network or
provider calls. Each toy adapter exercises a *subset* of agentic surfaces and emits
corpus-consistent findings for the pattern categories it handles, and a clean PASS for
categories it has no surface for. That partial coverage is the point: the coverage
heatmap shows where an adapter is and is not exercised.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agentic_security_harness.adapter_base import TargetAdapterBase
from agentic_security_harness.corpus import CorpusEntry, corpus_manifest
from agentic_security_harness.handoff_integrity import (
    HandoffEnvelope,
    HandoffVerification,
    format_verification_summary,
    payload_sha256,
    verify_handoff,
)
from agentic_security_harness.models import (
    CapabilityCheckResult,
    DefensivePattern,
    Finding,
    HealthStatus,
    Observation,
    TargetMetadata,
    TraceStep,
)

# A single benign, clearly-synthetic untrusted document the toy RAG "retrieves". It
# carries a marker, never a real payload, so the demo is concrete but safe.
_UNTRUSTED_FIXTURE = (
    "knowledge_base/quarterly_notes.txt :: [SYNTHETIC-UNTRUSTED-MARKER] "
    "benchmark probe content (no real instructions, no real data)"
)
_HANDOFF_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_HANDOFF_EXPIRES = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)

_corpus_index: dict[str, CorpusEntry] | None = None


def _corpus_by_id() -> dict[str, CorpusEntry]:
    global _corpus_index
    if _corpus_index is None:
        _corpus_index = {e.pattern_id: e for e in corpus_manifest()}
    return _corpus_index


class _ToyCategoryTarget:
    """Toy adapter base: FINDING for handled categories, PASS otherwise.

    Subclasses set ``type``, ``handled_categories``, and ``surface_note``.
    """

    type: str = "toy"
    handled_categories: frozenset[str] = frozenset()
    surface_note: str = "toy adapter"

    def __init__(self, name: str) -> None:
        self.name = name

    def descriptor_fields(self) -> tuple[str, str, str]:
        return (self.type, self.name, "toy")

    def observe(self, pattern: DefensivePattern) -> Observation:
        steps = [
            TraceStep(index=i, actor=self.name, action=node)
            for i, node in enumerate(pattern.graph_path)
        ]
        entry = _corpus_by_id().get(pattern.pattern_id)
        handled = pattern.category in self.handled_categories and entry is not None
        if handled and entry is not None:
            finding = Finding(
                code=pattern.category,
                severity=entry.severity,
                message=(
                    f"toy {self.name} did not enforce the {pattern.category} boundary "
                    f"(synthetic; ingested {_UNTRUSTED_FIXTURE})"
                ),
                broke_at=entry.broke_at,
                mitigation=pattern.mitigation,
            )
            return Observation(
                steps=steps,
                observed_behavior=(
                    f"toy {self.name}: {self.surface_note}; "
                    f"{pattern.category} boundary not enforced"
                ),
                findings=[finding],
            )
        return Observation(
            steps=steps,
            observed_behavior=(
                f"toy {self.name}: no {pattern.category} surface exercised; "
                "boundary preserved by construction"
            ),
            findings=[],
        )


class ToyRagTarget(_ToyCategoryTarget):
    """Toy retrieval-augmented agent: ingests an untrusted local document.

    Exercises the data / memory / injection surfaces; has no tool, budget, audit, or
    perception surface, so it PASSes those categories.
    """

    type = "toy_rag"
    handled_categories = frozenset(
        {
            "indirect_prompt_injection",
            "data_boundary",
            "memory_governance",
            "memory_poisoning",
        }
    )
    surface_note = "retrieved untrusted document into context/memory"

    def __init__(self, name: str = "toy-rag") -> None:
        super().__init__(name)


class ToyToolsTarget(_ToyCategoryTarget):
    """Toy tool-using agent with a mock tool registry.

    Exercises the tool-selection / schema / capability / ambient-authority surfaces; has
    no data-boundary or memory surface, so it PASSes those categories.
    """

    type = "toy_tools"
    handled_categories = frozenset(
        {
            "mcp_tool_schema",
            "tool_permission",
            "capability_delegation",
            "ambient_authority",
        }
    )
    surface_note = "selected a tool from a mock registry without provenance checks"

    def __init__(self, name: str = "toy-tools") -> None:
        super().__init__(name)


class ToyMultiAgentHandoffTarget(TargetAdapterBase):
    """Toy coordinator -> worker handoff target.

    This target is intentionally local and synthetic. It models only the handoff surface:
    data-envelope propagation and scoped capability delegation across coordinator/worker
    boundaries. It emits findings for the handoff/delegation patterns it exercises and
    PASSes unrelated categories by construction.
    """

    target_type = "toy_multi_agent"
    adapter_name = "toy-multi-agent"
    adapter_version = "0.2"
    memory_mode = "session"
    permission_model = "capability-token"
    network_mode = "off"
    provider_calls = False
    protected = False

    handled_pattern_ids = frozenset({
        "data_boundary_handoff_label_stripping",
        "capability.delegation_chain_drift",
    })

    def __init__(self, name: str = "toy-multi-agent") -> None:
        super().__init__(name)

    def health(self) -> HealthStatus:
        return HealthStatus(
            ok=True,
            status="ready",
            message="toy multi-agent handoff adapter ready",
            checks={
                "local_only": True,
                "coordinator": True,
                "worker": True,
                "no_provider_calls": True,
            },
        )

    def metadata(self, run_id: str) -> TargetMetadata:
        return TargetMetadata(
            adapter_name=self.adapter_name,
            adapter_version=self.adapter_version,
            runtime_name="toy-coordinator-worker",
            memory_mode="session",
            permission_model="capability-token",
            network_mode="off",
            deterministic=True,
            provider_calls=False,
            run_id=run_id,
        )

    def capability_check(self, pattern: DefensivePattern) -> CapabilityCheckResult:
        if pattern.pattern_id in self.handled_pattern_ids:
            return CapabilityCheckResult(
                pattern_id=pattern.pattern_id,
                supported=True,
                safety_gates_passed=True,
                reasons=["synthetic local coordinator/worker handoff surface"],
            )
        return CapabilityCheckResult(
            pattern_id=pattern.pattern_id,
            supported=True,
            safety_gates_passed=True,
            reasons=["pattern outside toy multi-agent handoff surface; neutral pass"],
        )

    def observe(self, pattern: DefensivePattern) -> Observation:
        if pattern.pattern_id == "data_boundary_handoff_label_stripping":
            return self._observe_label_stripping(pattern)
        if pattern.pattern_id == "capability.delegation_chain_drift":
            return self._observe_capability_drift(pattern)
        return Observation(
            steps=[
                TraceStep(
                    index=0,
                    actor="coordinator",
                    action="surface_check",
                    observed=(
                        f"no multi-agent handoff surface for category={pattern.category}; "
                        "boundary preserved by construction"
                    ),
                )
            ],
            observed_behavior=(
                f"toy {self.name}: no {pattern.category} handoff/delegation surface "
                "exercised; neutral pass"
            ),
            findings=[],
        )

    def _finding(
        self, pattern: DefensivePattern, entry: CorpusEntry, result: HandoffVerification
    ) -> Finding:
        return Finding(
            code=pattern.category,
            severity=entry.severity,
            message=(
                f"toy {self.name} exposed coordinator/worker handoff failure for "
                f"{pattern.pattern_id}: verifier verdict={result.verdict}, "
                f"S_combined={result.combined_score:.2f}"
            ),
            broke_at=entry.broke_at,
            mitigation=pattern.mitigation,
        )

    def _observe_label_stripping(self, pattern: DefensivePattern) -> Observation:
        entry = _corpus_by_id()[pattern.pattern_id]
        envelope = pattern.data_envelope
        payload = {
            "claim": "synthetic briefing item",
            "task": "conference_briefing",
            "source": "trusted_policy_fixture",
        }
        sender = HandoffEnvelope(
            envelope_id="env-summary-before",
            created_at=_HANDOFF_NOW,
            sender_id="coordinator",
            receiver_id="worker",
            task_id="task-briefing",
            session_id="session-toy-handoff",
            payload_type="summary",
            payload_hash=payload_sha256(payload),
            source_labels=["trusted_policy", "synthetic_user_input"],
            transformation_chain=[
                {
                    "agent_id": "coordinator",
                    "action": "summarize",
                    "input_hash": payload_sha256(payload),
                }
            ],
            authority_scope=["read", "summarize"],
            purpose="summarize",
            allowed_recipients=["worker"],
            ttl_seconds=300,
            expires_at=_HANDOFF_EXPIRES,
            policy_version="handoff-policy-v1",
            receiver_supported_policy_versions=["handoff-policy-v1"],
            audit_entry_hash="audit-summary-before",
        )
        receiver = sender.model_copy(
            update={
                "envelope_id": "env-summary-after",
                "source_labels": [],
                "transformation_chain": [],
                "audit_entry_hash": None,
            }
        )
        result = verify_handoff(
            receiver,
            payload,
            current_time=_HANDOFF_NOW,
            parent_source_labels=sender.source_labels,
            unsafe_consumptions=0 if self.protected else 1,
            total_consumptions=1,
        )
        before = (
            "before_handoff envelope="
            f"data_class={getattr(envelope, 'data_class', None)}; "
            f"allowed_recipients={getattr(envelope, 'allowed_recipients', [])}; "
            f"classification_source={getattr(envelope, 'classification_source', None)}; "
            f"classification_mutable={getattr(envelope, 'classification_mutable', None)}; "
            f"payload_hash={sender.payload_hash[:12]}; source_labels={sender.source_labels}"
        )
        after = (
            "after_handoff envelope=missing; receiver=worker; "
            "provenance_decision=missing_source_labels; "
            "authority_decision=overtrusted_unrestricted; "
            f"{format_verification_summary(result)}"
        )
        final = (
            "control: verifier blocked the malformed handoff; "
            "trusted_fact_consumed=false"
            if self.protected
            else "receiver ignored verifier result and consumed malformed summary as trusted fact"
        )
        steps = [
            TraceStep(
                index=0,
                actor="coordinator",
                action="receive_enveloped_item",
                input_ref="synthetic-envelope:source",
                observed=before,
            ),
            TraceStep(
                index=1,
                actor="coordinator",
                action="prepare_handoff",
                input_ref="synthetic-envelope:before",
                observed="handoff_intent=agent_b; chain_of_custody=coordinator->worker",
            ),
            TraceStep(
                index=2,
                actor="worker",
                action="receive_handoff",
                input_ref="synthetic-envelope:after",
                observed=after,
            ),
            TraceStep(
                index=3,
                actor="worker",
                action=entry.broke_at,
                observed=final,
            ),
        ]
        findings = [] if self.protected else [self._finding(pattern, entry, result)]
        return Observation(
            steps=steps,
            observed_behavior=(
                "coordinator sent an enveloped item; receiver-side verification produced "
                f"{result.verdict} for missing labels/provenance"
            ),
            findings=findings,
        )

    def _observe_capability_drift(self, pattern: DefensivePattern) -> Observation:
        entry = _corpus_by_id()[pattern.pattern_id]
        parent_scope = ["read"]
        parent_payload = {
            "capability_id": "cap-parent",
            "subject": "agent_b",
            "scope": parent_scope,
            "purpose": "summarize",
            "ttl_seconds": 60,
        }
        delegated_payload = {
            "capability_id": "cap-delegated",
            "subject": "agent_c",
            "scope": ["read", "write"],
            "purpose": "any",
            "ttl_seconds": 3600,
        }
        delegated = HandoffEnvelope(
            envelope_id="env-capability-after",
            created_at=_HANDOFF_NOW,
            sender_id="agent_b",
            receiver_id="agent_c",
            task_id="task-briefing",
            session_id="session-toy-handoff",
            payload_type="capability",
            payload_hash=payload_sha256(delegated_payload),
            authority_issuer=None,
            authority_scope=["read", "write"],
            purpose="any",
            delegation_depth=2,
            max_delegation_depth=1,
            can_delegate=True,
            allowed_recipients=["agent_c"],
            ttl_seconds=3600,
            expires_at=_HANDOFF_EXPIRES,
            policy_version="handoff-policy-v1",
            receiver_supported_policy_versions=["handoff-policy-v1"],
        )
        result = verify_handoff(
            delegated,
            delegated_payload,
            current_time=_HANDOFF_NOW,
            parent_authority_scope=parent_scope,
            parent_authority_issuer="senior",
            parent_purpose="summarize",
            parent_ttl_seconds=60,
            unsafe_consumptions=0 if self.protected else 1,
            total_consumptions=1,
        )
        final = (
            "control: verifier blocked expanded delegated capability; "
            "trusted_authority_consumed=false"
            if self.protected
            else "receiver ignored verifier result and accepted broader capability"
        )
        steps = [
            TraceStep(
                index=0,
                actor="coordinator",
                action="capability_grant",
                input_ref="synthetic-capability:parent",
                observed=(
                    "before_handoff capability=issuer:agent_a subject:agent_b "
                    "scope:read purpose:summarize ttl_seconds:60 "
                    f"payload_hash={payload_sha256(parent_payload)[:12]}"
                ),
            ),
            TraceStep(
                index=1,
                actor="worker",
                action="agent_handoff",
                input_ref="synthetic-capability:delegated",
                observed=(
                    "after_handoff capability=issuer_chain:missing subject:agent_c "
                    "scope:read,write purpose:any ttl_seconds:3600 "
                    f"{format_verification_summary(result)}"
                ),
            ),
            TraceStep(
                index=2,
                actor="worker",
                action=entry.broke_at,
                observed=f"authority_decision=expanded_scope; {final}",
            ),
        ]
        findings = [] if self.protected else [self._finding(pattern, entry, result)]
        return Observation(
            steps=steps,
            observed_behavior=(
                "worker delegated a broader capability than the coordinator granted; "
                f"receiver-side verification produced {result.verdict}"
            ),
            findings=findings,
        )


class ProtectedToyMultiAgentHandoffTarget(ToyMultiAgentHandoffTarget):
    """Protected toy coordinator -> worker handoff target.

    It runs the same malformed synthetic handoffs as ``ToyMultiAgentHandoffTarget`` but
    enforces the verifier verdict, so malformed payloads are blocked instead of consumed
    as trusted facts or authority.
    """

    target_type = "protected_toy_multi_agent"
    adapter_name = "protected-toy-multi-agent"
    protected = True

    def __init__(self, name: str = "protected-toy-multi-agent") -> None:
        super().__init__(name)
