"""Base lifecycle hooks for target adapters.

Adapters can still satisfy the small structural ``Target`` protocol directly. This base
class exists for adapters that want explicit readiness, reproducibility metadata, and
per-pattern capability checks without re-implementing boilerplate.
"""

from __future__ import annotations

from agentic_security_harness.models import (
    CapabilityCheckResult,
    DefensivePattern,
    HealthStatus,
    TargetMetadata,
)


class TargetAdapterBase:
    """Convenience base class for target adapters with lifecycle hooks."""

    target_type = "custom"
    adapter_name = "custom"
    adapter_version = "0.1"
    deterministic = True
    network_mode = "off"
    memory_mode = "off"
    permission_model = "none"
    provider_calls = False

    def __init__(self, name: str | None = None) -> None:
        self.name = name or self.adapter_name

    def descriptor_fields(self) -> tuple[str, str, str]:
        return (self.target_type, self.name, self.adapter_name)

    def health(self) -> HealthStatus:
        return HealthStatus(
            ok=True,
            status="ready",
            message=f"{self.adapter_name} adapter ready",
            checks={"descriptor": True, "observe": True},
        )

    def metadata(self, run_id: str) -> TargetMetadata:
        return TargetMetadata(
            adapter_name=self.adapter_name,
            adapter_version=self.adapter_version,
            memory_mode=self.memory_mode,  # type: ignore[arg-type]
            permission_model=self.permission_model,  # type: ignore[arg-type]
            network_mode=self.network_mode,  # type: ignore[arg-type]
            deterministic=self.deterministic,
            provider_calls=self.provider_calls,
            run_id=run_id,
        )

    def capability_check(self, pattern: DefensivePattern) -> CapabilityCheckResult:
        return CapabilityCheckResult(
            pattern_id=pattern.pattern_id,
            supported=True,
            safety_gates_passed=True,
        )
