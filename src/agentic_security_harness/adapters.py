"""Adapter registry: maps target ids to constructors and metadata.

Built-in targets are local, deterministic, and make no network or provider calls.
This module provides ``list_targets()`` and ``make_target()`` for CLI discovery.
"""

from __future__ import annotations

from typing import Any

from agentic_security_harness.models import Target


class TargetInfo:
    """Metadata for a registered built-in target."""

    __slots__ = ("target_id", "name", "type", "deterministic", "description", "_factory")

    def __init__(
        self,
        target_id: str,
        name: str,
        type: str,
        deterministic: bool,
        description: str,
        factory: Any,
    ) -> None:
        self.target_id = target_id
        self.name = name
        self.type = type
        self.deterministic = deterministic
        self.description = description
        self._factory = factory

    def make(self) -> Target:
        return self._factory()


_REGISTRY: list[TargetInfo] = []


def _register(info: TargetInfo) -> None:
    _REGISTRY.append(info)


def _init_registry() -> None:
    if _REGISTRY:
        return

    from agentic_security_harness.demo_adapter import DemoAgentTarget
    from agentic_security_harness.mock_target import MockTarget
    from agentic_security_harness.protected_demo_agent import ProtectedDemoAgentTarget

    _register(
        TargetInfo(
            target_id="mock",
            name="demo-mock-agent",
            type="mock_agent",
            deterministic=True,
            description="Deterministic minimal target for fast benchmark checks",
            factory=MockTarget,
        )
    )
    _register(
        TargetInfo(
            target_id="demo-agent",
            name="demo-local-agent",
            type="demo_agent",
            deterministic=True,
            description="Local vulnerable-by-design synthetic agent",
            factory=DemoAgentTarget,
        )
    )
    _register(
        TargetInfo(
            target_id="protected-demo-agent",
            name="protected-demo-agent",
            type="protected_demo_agent",
            deterministic=True,
            description="Local controlled synthetic agent; demonstrates risk reduction",
            factory=ProtectedDemoAgentTarget,
        )
    )
    _register(
        TargetInfo(
            target_id="toy-local-function",
            name="toy-local-function",
            type="toy_local",
            deterministic=True,
            description="Toy adapter wrapping a plain Python function as a target",
            factory=_ToyLocalFunctionTarget,
        )
    )

    from agentic_security_harness.toy_adapters import (
        ProtectedToyMultiAgentHandoffTarget,
        ToyMultiAgentHandoffTarget,
        ToyRagTarget,
        ToyToolsTarget,
    )

    _register(
        TargetInfo(
            target_id="toy-rag",
            name="toy-rag",
            type="toy_rag",
            deterministic=True,
            description="Toy retrieval agent; exercises data/memory/injection surfaces",
            factory=ToyRagTarget,
        )
    )
    _register(
        TargetInfo(
            target_id="toy-tools",
            name="toy-tools",
            type="toy_tools",
            deterministic=True,
            description="Toy tool-using agent; exercises tool/authority surfaces",
            factory=ToyToolsTarget,
        )
    )
    _register(
        TargetInfo(
            target_id="toy-multi-agent",
            name="toy-multi-agent",
            type="toy_multi_agent",
            deterministic=True,
            description=(
                "Toy coordinator/worker handoff adapter; exercises data-label "
                "handoff and capability delegation surfaces"
            ),
            factory=ToyMultiAgentHandoffTarget,
        )
    )
    _register(
        TargetInfo(
            target_id="protected-toy-multi-agent",
            name="protected-toy-multi-agent",
            type="protected_toy_multi_agent",
            deterministic=True,
            description=(
                "Protected toy coordinator/worker handoff adapter; blocks malformed "
                "handoffs through deterministic verifier decisions"
            ),
            factory=ProtectedToyMultiAgentHandoffTarget,
        )
    )


class _ToyLocalFunctionTarget:
    """Toy adapter: wraps a deterministic Python function as a target.

    Returns PASS (no findings) for every pattern, useful for docs and tests.
    """

    def __init__(self, name: str = "toy-local-function") -> None:
        self.name = name

    def descriptor_fields(self) -> tuple[str, str, str]:
        return ("toy_local", self.name, "toy")

    def observe(self, pattern: Any) -> Any:
        from agentic_security_harness.models import Observation, TraceStep

        steps = [
            TraceStep(index=i, actor="toy", action=node)
            for i, node in enumerate(pattern.graph_path)
        ]
        return Observation(
            steps=steps,
            observed_behavior="toy adapter completed with no observed violation",
            findings=[],
        )


def list_targets() -> list[TargetInfo]:
    """Return metadata for all registered built-in targets."""
    _init_registry()
    return list(_REGISTRY)


def make_target(target_id: str) -> Target:
    """Create a target instance by its registered id.

    Raises ``KeyError`` with a helpful message if the id is unknown.
    """
    _init_registry()
    for info in _REGISTRY:
        if info.target_id == target_id:
            return info.make()
    known = ", ".join(info.target_id for info in _REGISTRY)
    raise KeyError(f"unknown target id '{target_id}'. Known targets: {known}")


def target_ids() -> list[str]:
    """Return just the registered target ids."""
    return [info.target_id for info in list_targets()]
