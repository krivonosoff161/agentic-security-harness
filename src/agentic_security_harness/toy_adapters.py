"""Local toy adapters: deterministic, synthetic stand-ins for agentic systems.

These are **demo adapters, not production integrations**. They make no network or
provider calls. Each toy adapter exercises a *subset* of agentic surfaces and emits
corpus-consistent findings for the pattern categories it handles, and a clean PASS for
categories it has no surface for. That partial coverage is the point: the coverage
heatmap shows where an adapter is and is not exercised.
"""

from __future__ import annotations

from agentic_security_harness.corpus import CorpusEntry, corpus_manifest
from agentic_security_harness.models import (
    DefensivePattern,
    Finding,
    Observation,
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
