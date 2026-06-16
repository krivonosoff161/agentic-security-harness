"""Local toy adapters: deterministic, synthetic stand-ins for agentic systems.

These are **demo adapters, not production integrations**. They make no network or
provider calls. Each toy adapter exercises a *subset* of agentic surfaces and emits
corpus-consistent findings for the pattern categories it handles, and a clean PASS for
categories it has no surface for. That partial coverage is the point: the coverage
heatmap shows where an adapter is and is not exercised.
"""

from __future__ import annotations

from agentic_security_harness.adapter_base import TargetAdapterBase
from agentic_security_harness.corpus import CorpusEntry, corpus_manifest
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
    adapter_version = "0.1"
    memory_mode = "session"
    permission_model = "capability-token"
    network_mode = "off"
    provider_calls = False

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

    def _finding(self, pattern: DefensivePattern, entry: CorpusEntry) -> Finding:
        return Finding(
            code=pattern.category,
            severity=entry.severity,
            message=(
                f"toy {self.name} exposed coordinator/worker handoff failure for "
                f"{pattern.pattern_id}"
            ),
            broke_at=entry.broke_at,
            mitigation=pattern.mitigation,
        )

    def _observe_label_stripping(self, pattern: DefensivePattern) -> Observation:
        entry = _corpus_by_id()[pattern.pattern_id]
        envelope = pattern.data_envelope
        before = (
            "before_handoff envelope="
            f"data_class={getattr(envelope, 'data_class', None)}; "
            f"allowed_recipients={getattr(envelope, 'allowed_recipients', [])}; "
            f"classification_source={getattr(envelope, 'classification_source', None)}; "
            f"classification_mutable={getattr(envelope, 'classification_mutable', None)}"
        )
        after = (
            "after_handoff envelope=missing; receiver=worker; "
            "provenance_decision=missing_source_labels; "
            "authority_decision=overtrusted_unrestricted"
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
                observed="receiver treated missing labels as unrestricted data",
            ),
        ]
        return Observation(
            steps=steps,
            observed_behavior=(
                "coordinator sent an enveloped item, but worker received it without "
                "labels/provenance and treated it as unrestricted"
            ),
            findings=[self._finding(pattern, entry)],
        )

    def _observe_capability_drift(self, pattern: DefensivePattern) -> Observation:
        entry = _corpus_by_id()[pattern.pattern_id]
        steps = [
            TraceStep(
                index=0,
                actor="coordinator",
                action="capability_grant",
                input_ref="synthetic-capability:parent",
                observed=(
                    "before_handoff capability=issuer:agent_a subject:agent_b "
                    "scope:read purpose:summarize ttl_seconds:60"
                ),
            ),
            TraceStep(
                index=1,
                actor="worker",
                action="agent_handoff",
                input_ref="synthetic-capability:delegated",
                observed=(
                    "after_handoff capability=issuer_chain:missing subject:agent_c "
                    "scope:read,write purpose:any ttl_seconds:3600"
                ),
            ),
            TraceStep(
                index=2,
                actor="worker",
                action=entry.broke_at,
                observed=(
                    "authority_decision=expanded_scope; provenance_decision="
                    "issuer_chain_missing; receiver accepted broader delegated grant"
                ),
            ),
        ]
        return Observation(
            steps=steps,
            observed_behavior=(
                "worker delegated a broader capability than the coordinator granted "
                "and lost issuer-chain provenance"
            ),
            findings=[self._finding(pattern, entry)],
        )
