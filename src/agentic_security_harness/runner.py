"""HarnessRunner: pattern -> mock target -> ExploitTrace.

Trace IDs are deterministic (a stable hash of pattern id + target name) so the same run
reproduces the same traces.
"""

import hashlib
from typing import Any

from agentic_security_harness.models import (
    CapabilityCheckResult,
    DefensivePattern,
    ExploitTrace,
    HealthStatus,
    Target,
    TargetDescriptor,
    TargetMetadata,
)


def _trace_id(pattern_id: str, target_name: str) -> str:
    digest = hashlib.sha256(f"{pattern_id}:{target_name}".encode()).hexdigest()
    return f"trc_{digest[:8]}"


class HarnessRunner:
    """Runs defensive patterns against a target and emits one trace per pattern."""

    def __init__(self, target: Target, *, enforce_health: bool = True) -> None:
        self.target = target
        self.enforce_health = enforce_health

    def health(self) -> HealthStatus:
        hook = getattr(self.target, "health", None)
        if callable(hook):
            return HealthStatus.model_validate(hook())
        return HealthStatus(
            ok=True,
            status="ready",
            message="adapter has no explicit health hook; using structural target contract",
            checks={"descriptor": True, "observe": True},
        )

    def capability_check(self, pattern: DefensivePattern) -> CapabilityCheckResult:
        hook = getattr(self.target, "capability_check", None)
        if callable(hook):
            return CapabilityCheckResult.model_validate(hook(pattern))
        return CapabilityCheckResult(
            pattern_id=pattern.pattern_id,
            supported=True,
            safety_gates_passed=True,
        )

    def metadata(self, trace_id: str) -> TargetMetadata:
        type_, name, adapter = self.target.descriptor_fields()
        hook = getattr(self.target, "metadata", None)
        if callable(hook):
            try:
                return TargetMetadata.model_validate(hook(trace_id))
            except TypeError:
                return TargetMetadata.model_validate(hook())
        return TargetMetadata(
            adapter_name=adapter,
            adapter_version="builtin",
            runtime_name=name,
            deterministic=True,
            run_id=trace_id,
        )

    @staticmethod
    def _reproducibility(
        metadata: TargetMetadata, health: HealthStatus, check: CapabilityCheckResult
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "deterministic": metadata.deterministic,
            "seed": metadata.run_seed if metadata.run_seed is not None else 0,
            "adapter_name": metadata.adapter_name,
            "adapter_version": metadata.adapter_version,
            "memory_mode": metadata.memory_mode,
            "permission_model": metadata.permission_model,
            "network_mode": metadata.network_mode,
            "provider_calls": metadata.provider_calls,
            "run_count": metadata.run_count,
            "health_status": health.status,
            "capability_supported": check.supported,
            "safety_gates_passed": check.safety_gates_passed,
        }
        if metadata.runtime_name:
            payload["runtime_name"] = metadata.runtime_name
        if metadata.runtime_version:
            payload["runtime_version"] = metadata.runtime_version
        if metadata.model_family:
            payload["model_family"] = metadata.model_family
        if metadata.model_name:
            payload["model_name"] = metadata.model_name
        if metadata.tool_registry_hash:
            payload["tool_registry_hash"] = metadata.tool_registry_hash
        return payload

    def run(self, pattern: DefensivePattern) -> ExploitTrace:
        health = self.health()
        if self.enforce_health and not health.ok:
            raise RuntimeError(f"target adapter not ready: {health.status}: {health.message}")
        check = self.capability_check(pattern)
        if not check.supported or not check.safety_gates_passed:
            reasons = "; ".join(check.reasons) or "no reason provided"
            raise RuntimeError(
                f"target adapter cannot run pattern '{pattern.pattern_id}': {reasons}"
            )
        obs = self.target.observe(pattern)
        type_, name, adapter = self.target.descriptor_fields()
        trace_id = _trace_id(pattern.pattern_id, name)
        metadata = self.metadata(trace_id)
        return ExploitTrace(
            trace_id=trace_id,
            pattern_id=pattern.pattern_id,
            target=TargetDescriptor(type=type_, name=name, adapter=adapter),
            graph_path=list(pattern.graph_path),
            steps=obs.steps,
            expected_vulnerable_behavior=pattern.expected_vulnerable_behavior,
            observed_behavior=obs.observed_behavior,
            findings=obs.findings,
            data_envelope=pattern.data_envelope,
            reproducibility=self._reproducibility(metadata, health, check)
            | {"inputs_ref": f"fixtures/{pattern.pattern_id}"},
        )

    def run_many(self, patterns: list[DefensivePattern]) -> list[ExploitTrace]:
        return [self.run(pattern) for pattern in patterns]
