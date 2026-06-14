"""Scorecard: a deterministic aggregate derived from a set of traces."""

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS


class ScorecardSummary(BaseModel):
    """Per-target summary derived from traces."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["scorecard"]
    target_name: str
    total_traces: int
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    failed_patterns: list[str] = Field(default_factory=list)
    passed_patterns: list[str] = Field(default_factory=list)


def build_scorecard(traces: list[ExploitTrace]) -> ScorecardSummary:
    """Build a deterministic scorecard from traces.

    A trace with any findings is a *failed* pattern; otherwise it *passed*. Category counts
    use each finding's ``code`` (set to the pattern category by the mock target).
    """
    target_name = traces[0].target.name if traces else ""
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    failed: list[str] = []
    passed: list[str] = []
    for trace in traces:
        (failed if trace.findings else passed).append(trace.pattern_id)
        for finding in trace.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.code] = by_category.get(finding.code, 0) + 1
    return ScorecardSummary(
        target_name=target_name,
        total_traces=len(traces),
        findings_by_severity=by_severity,
        findings_by_category=by_category,
        failed_patterns=failed,
        passed_patterns=passed,
    )
