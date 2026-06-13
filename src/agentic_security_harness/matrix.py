"""Variant matrix foundation: controlled replay layer for scenario x variant runs.

For v0.12 the matrix layer is a controlled replay layer: select scenario, select pattern
ids, attach variant metadata, run target, record variant metadata in a matrix report.
No harmful content is invented. Variants vary safe benchmark dimensions only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.models import Target
from agentic_security_harness.patterns import DefensivePattern, seed_patterns
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scenarios import get_scenario
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard

VariantScope = Literal["single-step", "multi-step"]
MemoryMode = Literal["off", "session", "scoped"]
RecipientCount = Literal["one", "multiple"]
ToolMode = Literal["none", "read-only", "read-write"]
ApprovalMode = Literal["none", "explicit", "incomplete"]
BudgetProfile = Literal["normal", "constrained"]


class VariantKnobs(BaseModel):
    """Deterministic variant dimensions for a matrix run."""

    model_config = ConfigDict(extra="forbid")

    scope: VariantScope = "single-step"
    memory_mode: MemoryMode = "off"
    recipient_count: RecipientCount = "one"
    tool_mode: ToolMode = "none"
    approval_mode: ApprovalMode = "none"
    budget_profile: BudgetProfile = "normal"


class VariantResult(BaseModel):
    """Outcome of one variant run within a matrix."""

    model_config = ConfigDict(extra="forbid")

    variant_id: str
    variant_knobs: dict[str, str] = Field(default_factory=dict)
    trace_ids: list[str] = Field(default_factory=list)
    total_traces: int = 0
    failed_patterns: list[str] = Field(default_factory=list)
    passed_patterns: list[str] = Field(default_factory=list)


class MatrixReport(BaseModel):
    """Metadata for a scenario x target matrix run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.1"
    target_id: str
    target_name: str
    scenario_id: str
    scenario_title: str
    corpus_version: str = "0.12"
    selected_pattern_ids: list[str] = Field(default_factory=list)
    variants: list[VariantResult] = Field(default_factory=list)
    total_traces: int = 0
    total_failed: int = 0
    total_passed: int = 0
    generated_by: str = "agentic-security-harness"


def _variant_id(scenario_id: str, knobs: VariantKnobs) -> str:
    raw = f"{scenario_id}:{json.dumps(knobs.model_dump(), sort_keys=True)}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"var_{digest[:8]}"


def _select_patterns(
    scenario_id: str,
) -> list[DefensivePattern]:
    """Select patterns for a scenario from the full seed corpus."""
    scenario = get_scenario(scenario_id)
    all_patterns = {p.pattern_id: p for p in seed_patterns()}
    selected = []
    for pid in scenario.pattern_ids:
        if pid in all_patterns:
            selected.append(all_patterns[pid])
    return selected


def run_matrix(
    target: Target,
    scenario_id: str,
    out_dir: Path,
    target_id: str = "",
) -> MatrixReport:
    """Run a target against a scenario's patterns with deterministic variant metadata.

    Produces:
      - matrix.json
      - traces.json
      - scorecard.json
      - summary.md
      - executive.md
      - remediation artifacts (when findings exist)
    """
    from agentic_security_harness.reporting import write_reports

    scenario = get_scenario(scenario_id)
    patterns = _select_patterns(scenario_id)
    if not patterns:
        raise ValueError(f"scenario '{scenario_id}' has no matching patterns in the corpus")

    # Single variant for v0.12: deterministic, capped at the scenario defaults
    knobs = VariantKnobs.model_validate(scenario.default_variant_knobs)
    variant_id = _variant_id(scenario_id, knobs)

    runner = HarnessRunner(target)
    traces = runner.run_many(patterns)
    scorecard = build_scorecard(traces)

    variant = VariantResult(
        variant_id=variant_id,
        variant_knobs=knobs.model_dump(),
        trace_ids=[t.trace_id for t in traces],
        total_traces=len(traces),
        failed_patterns=list(scorecard.failed_patterns),
        passed_patterns=list(scorecard.passed_patterns),
    )

    target_type, target_name, _ = target.descriptor_fields()
    report = MatrixReport(
        target_id=target_id or target_name,
        target_name=target_name,
        scenario_id=scenario_id,
        scenario_title=scenario.title,
        selected_pattern_ids=[p.pattern_id for p in patterns],
        variants=[variant],
        total_traces=len(traces),
        total_failed=len(scorecard.failed_patterns),
        total_passed=len(scorecard.passed_patterns),
    )

    out_dir.mkdir(parents=True, exist_ok=True)

    # Write standard report artifacts
    write_reports(traces, scorecard, out_dir)

    # Write matrix.json
    matrix_path = out_dir / "matrix.json"
    matrix_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    # Write matrix summary (extends summary.md)
    summary_path = out_dir / "matrix.md"
    summary_path.write_text(_build_matrix_md(report, scorecard), encoding="utf-8", newline="\n")

    return report


def _build_matrix_md(report: MatrixReport, scorecard: ScorecardSummary) -> str:
    """Build deterministic matrix summary markdown."""
    lines: list[str] = [
        "# Agentic Security Harness - matrix report",
        "",
        f"Target: `{report.target_name}`",
        "",
        f"Scenario: `{report.scenario_id}` - {report.scenario_title}",
        "",
        f"- Selected patterns: {len(report.selected_pattern_ids)}",
        f"- Variants: {len(report.variants)}",
        f"- Total traces: {report.total_traces}",
        f"- Failed: {report.total_failed}",
        f"- Passed: {report.total_passed}",
        "",
    ]

    if report.variants:
        lines += ["## Variants", ""]
        for v in report.variants:
            lines.append(f"### Variant `{v.variant_id}`")
            lines.append("")
            if v.variant_knobs:
                lines.append("Knobs:")
                for key, val in v.variant_knobs.items():
                    lines.append(f"- {key}: `{val}`")
                lines.append("")
            lines.append(f"- Traces: {v.total_traces}")
            lines.append(f"- Failed: {len(v.failed_patterns)}")
            lines.append(f"- Passed: {len(v.passed_patterns)}")
            lines.append("")

    # Pattern table
    lines += [
        "## Patterns",
        "",
        "| Pattern | Result | Severity |",
        "|---|---|---|",
    ]
    failed_set = set(scorecard.failed_patterns)
    for pid in report.selected_pattern_ids:
        result = "FAIL" if pid in failed_set else "PASS"
        lines.append(f"| `{pid}` | {result} | - |")

    lines += [
        "",
        "> Matrix artifacts are deterministic and synthetic. "
        "Risk reduction is measured from deterministic mock traces.",
        "",
    ]
    return "\n".join(lines)


def load_matrix_report(path: Path) -> MatrixReport:
    """Load a matrix.json file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return MatrixReport.model_validate(raw)
