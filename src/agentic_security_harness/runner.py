"""HarnessRunner: pattern -> mock target -> ExploitTrace.

Trace IDs are deterministic (a stable hash of pattern id + target name) so the same run
reproduces the same traces.
"""

import hashlib

from agentic_security_harness.models import (
    DefensivePattern,
    ExploitTrace,
    Target,
    TargetDescriptor,
)


def _trace_id(pattern_id: str, target_name: str) -> str:
    digest = hashlib.sha256(f"{pattern_id}:{target_name}".encode()).hexdigest()
    return f"trc_{digest[:8]}"


class HarnessRunner:
    """Runs defensive patterns against a target and emits one trace per pattern."""

    def __init__(self, target: Target) -> None:
        self.target = target

    def run(self, pattern: DefensivePattern) -> ExploitTrace:
        obs = self.target.observe(pattern)
        type_, name, adapter = self.target.descriptor_fields()
        return ExploitTrace(
            trace_id=_trace_id(pattern.pattern_id, name),
            schema_version="0.1",
            pattern_id=pattern.pattern_id,
            target=TargetDescriptor(type=type_, name=name, adapter=adapter),
            graph_path=list(pattern.graph_path),
            steps=obs.steps,
            expected_vulnerable_behavior=pattern.expected_vulnerable_behavior,
            observed_behavior=obs.observed_behavior,
            findings=obs.findings,
            data_envelope=pattern.data_envelope,
            reproducibility={
                "deterministic": True,
                "seed": 0,
                "inputs_ref": f"fixtures/{pattern.pattern_id}",
            },
        )

    def run_many(self, patterns: list[DefensivePattern]) -> list[ExploitTrace]:
        return [self.run(pattern) for pattern in patterns]
