"""Variant matrix: multi-variant replay layer for scenario x variant runs.

Runs multiple safe benchmark variants for a scenario, aggregates results,
and produces stability analysis. No harmful content is invented.
Variants vary safe benchmark dimensions only.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.models import Target
from agentic_security_harness.patterns import DefensivePattern, seed_patterns
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scenarios import (
    _DEFAULT_MAX_VARIANTS,
    ScenarioVariant,
    get_variants,
)
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard


class VariantResult(BaseModel):
    """Outcome of one variant run within a matrix."""

    model_config = ConfigDict(extra="forbid")

    variant_id: str
    title: str = ""
    description: str = ""
    knobs: dict[str, str] = Field(default_factory=dict)
    expected_control_focus: list[str] = Field(default_factory=list)
    trace_ids: list[str] = Field(default_factory=list)
    total_traces: int = 0
    failed_patterns: list[str] = Field(default_factory=list)
    passed_patterns: list[str] = Field(default_factory=list)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)


class PatternStability(BaseModel):
    """Stability classification for a pattern across variants."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    variants_seen: int = 0
    variants_failed: int = 0
    stability: str = "pass"


class MatrixSummary(BaseModel):
    """Aggregated results across all variants in a matrix run."""

    model_config = ConfigDict(extra="forbid")

    total_variants: int = 0
    failed_variants: int = 0
    passed_variants: int = 0
    total_traces: int = 0
    findings_by_variant: dict[str, int] = Field(default_factory=dict)
    findings_by_pattern: dict[str, int] = Field(default_factory=dict)
    findings_by_control_family: dict[str, int] = Field(default_factory=dict)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    stable_failures: list[str] = Field(default_factory=list)
    variant_sensitive_failures: list[str] = Field(default_factory=list)


class MatrixReport(BaseModel):
    """Metadata for a scenario x target multi-variant matrix run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.2"
    target_id: str
    target_name: str
    scenario_id: str
    scenario_title: str
    corpus_version: str = "0.12.1"
    selected_pattern_ids: list[str] = Field(default_factory=list)
    variants: list[VariantResult] = Field(default_factory=list)
    summary: MatrixSummary = Field(default_factory=MatrixSummary)
    total_traces: int = 0
    generated_by: str = "agentic-security-harness"


def _variant_trace_id(pattern_id: str, target_name: str, variant_id: str) -> str:
    """Deterministic trace ID including variant context for uniqueness."""
    raw = f"{pattern_id}:{target_name}:{variant_id}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"trc_{digest[:8]}"


def _select_patterns(scenario_id: str) -> list[DefensivePattern]:
    """Select patterns for a scenario from the full seed corpus."""
    from agentic_security_harness.scenarios import get_scenario

    scenario = get_scenario(scenario_id)
    all_patterns = {p.pattern_id: p for p in seed_patterns()}
    return [all_patterns[pid] for pid in scenario.pattern_ids if pid in all_patterns]


def _run_variant(
    runner: HarnessRunner,
    patterns: list[DefensivePattern],
    variant: ScenarioVariant,
    target_name: str,
) -> tuple[VariantResult, list]:
    """Run one variant and collect results. Returns (result, traces)."""
    traces = runner.run_many(patterns)

    # Rewrite trace IDs to include variant context for uniqueness
    for trace in traces:
        trace.trace_id = _variant_trace_id(
            trace.pattern_id, target_name, variant.variant_id
        )

    scorecard = build_scorecard(traces)
    result = VariantResult(
        variant_id=variant.variant_id,
        title=variant.title,
        description=variant.description,
        knobs=variant.knobs,
        expected_control_focus=list(variant.expected_control_focus),
        trace_ids=[t.trace_id for t in traces],
        total_traces=len(traces),
        failed_patterns=list(scorecard.failed_patterns),
        passed_patterns=list(scorecard.passed_patterns),
        findings_by_severity=dict(scorecard.findings_by_severity),
    )
    return result, traces


def _build_summary(
    variants: list[VariantResult],
    all_traces: list,
    scenario_id: str,
) -> MatrixSummary:
    """Build aggregated matrix summary across all variants."""
    from agentic_security_harness.remediation import _FAMILY_MAP

    total_variants = len(variants)
    failed_variants = [v for v in variants if v.failed_patterns]
    passed_variants = [v for v in variants if not v.failed_patterns]

    findings_by_variant: dict[str, int] = {}
    findings_by_pattern: dict[str, int] = defaultdict(int)
    findings_by_severity: dict[str, int] = defaultdict(int)
    pattern_seen: dict[str, int] = defaultdict(int)
    pattern_failed: dict[str, int] = defaultdict(int)

    for v in variants:
        n = sum(v.findings_by_severity.values())
        findings_by_variant[v.variant_id] = n
        for pid in v.failed_patterns:
            pattern_failed[pid] += 1
        for pid in v.failed_patterns + v.passed_patterns:
            pattern_seen[pid] += 1
        for sev, count in v.findings_by_severity.items():
            findings_by_severity[sev] += count

    # Aggregate findings_by_pattern from actual traces
    for trace in all_traces:
        if trace.findings:
            findings_by_pattern[trace.pattern_id] += len(trace.findings)

    # Aggregate control families
    findings_by_control_family: dict[str, int] = defaultdict(int)
    for trace in all_traces:
        for _finding in trace.findings:
            family: str = _FAMILY_MAP.get(trace.pattern_id, "provenance")
            findings_by_control_family[family] += 1

    # Classify stability
    stable_failures: list[str] = []
    variant_sensitive_failures: list[str] = []
    for pid, seen in pattern_seen.items():
        failed = pattern_failed.get(pid, 0)
        if failed == seen and seen > 0:
            stable_failures.append(pid)
        elif 0 < failed < seen:
            variant_sensitive_failures.append(pid)

    return MatrixSummary(
        total_variants=total_variants,
        failed_variants=len(failed_variants),
        passed_variants=len(passed_variants),
        total_traces=sum(v.total_traces for v in variants),
        findings_by_variant=dict(findings_by_variant),
        findings_by_pattern=dict(findings_by_pattern),
        findings_by_control_family=dict(findings_by_control_family),
        findings_by_severity=dict(findings_by_severity),
        stable_failures=sorted(stable_failures),
        variant_sensitive_failures=sorted(variant_sensitive_failures),
    )


def run_matrix(
    target: Target,
    scenario_id: str,
    out_dir: Path,
    target_id: str = "",
    max_variants: int = _DEFAULT_MAX_VARIANTS,
    only_variant_id: str | None = None,
) -> MatrixReport:
    """Run a target against scenario variants and produce aggregated reports.

    Produces:
      - matrix.json
      - traces.json (all variant traces combined)
      - scorecard.json (aggregated)
      - summary.md
      - executive.md
      - matrix.md (variant-specific summary)
      - remediation artifacts (when findings exist)
    """
    from agentic_security_harness.reporting import write_reports
    from agentic_security_harness.scenarios import get_scenario

    scenario = get_scenario(scenario_id)
    variants_to_run = get_variants(scenario_id, max_variants, only_variant_id)
    patterns = _select_patterns(scenario_id)
    if not patterns:
        raise ValueError(
            f"scenario '{scenario_id}' has no matching patterns in the corpus"
        )

    runner = HarnessRunner(target)
    _, target_name, _ = target.descriptor_fields()

    variant_results: list[VariantResult] = []
    all_traces = []

    for variant in variants_to_run:
        vresult, v_traces = _run_variant(
            runner, patterns, variant, target_name
        )
        variant_results.append(vresult)
        all_traces.extend(v_traces)

    summary = _build_summary(variant_results, all_traces, scenario_id)

    report = MatrixReport(
        target_id=target_id or target_name,
        target_name=target_name,
        scenario_id=scenario_id,
        scenario_title=scenario.title,
        selected_pattern_ids=[p.pattern_id for p in patterns],
        variants=variant_results,
        summary=summary,
        total_traces=summary.total_traces,
    )

    out_dir.mkdir(parents=True, exist_ok=True)

    # Write standard report artifacts using aggregated scorecard
    scorecard = build_scorecard(all_traces)
    write_reports(all_traces, scorecard, out_dir)

    # Write matrix.json
    matrix_path = out_dir / "matrix.json"
    matrix_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    # Write matrix.md
    summary_path = out_dir / "matrix.md"
    summary_path.write_text(
        _build_matrix_md(report, scorecard),
        encoding="utf-8",
        newline="\n",
    )

    return report


def _build_matrix_md(report: MatrixReport, scorecard: ScorecardSummary) -> str:
    """Build deterministic multi-variant matrix markdown."""
    s = report.summary
    lines: list[str] = [
        "# Agentic Security Harness - matrix report",
        "",
        f"Target: `{report.target_name}`",
        "",
        f"Scenario: `{report.scenario_id}` - {report.scenario_title}",
        "",
        "## Overview",
        "",
        f"- Variants tested: {s.total_variants}",
        f"- Total traces: {s.total_traces}",
        f"- Failed variants: {s.failed_variants}",
        f"- Passed variants: {s.passed_variants}",
        "",
    ]

    # Variant table
    lines += [
        "## Variant results",
        "",
        "| Variant | Knobs | Traces | Findings | Top severity |",
        "|---|---|---|---|---|",
    ]
    for v in report.variants:
        n = sum(v.findings_by_severity.values())
        top_sev = "-"
        if v.findings_by_severity:
            rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            top_sev = max(v.findings_by_severity, key=lambda s: rank.get(s, -1))
        knobs_str = ", ".join(f"{k}={val}" for k, val in v.knobs.items())
        if len(knobs_str) > 50:
            knobs_str = knobs_str[:47] + "..."
        lines.append(
            f"| `{v.variant_id}` | {knobs_str} | {v.total_traces} "
            f"| {n} | {top_sev} |"
        )

    # Pattern stability table
    lines += [
        "",
        "## Pattern stability",
        "",
        "| Pattern | Variants seen | Variants failed | Stability |",
        "|---|---|---|---|",
    ]
    pattern_seen: dict[str, int] = defaultdict(int)
    pattern_failed: dict[str, int] = defaultdict(int)
    for v in report.variants:
        for pid in v.failed_patterns + v.passed_patterns:
            pattern_seen[pid] += 1
        for pid in v.failed_patterns:
            pattern_failed[pid] += 1

    for pid in report.selected_pattern_ids:
        seen = pattern_seen.get(pid, 0)
        failed = pattern_failed.get(pid, 0)
        if failed == seen and seen > 0:
            label = "stable_fail"
        elif 0 < failed < seen:
            label = "variant_sensitive"
        else:
            label = "pass"
        lines.append(f"| `{pid}` | {seen} | {failed} | {label} |")

    # Control family table
    if s.findings_by_control_family:
        lines += [
            "",
            "## Control families",
            "",
            "| Family | Findings | Variants affected |",
            "|---|---|---|",
        ]
        # Count variants per family
        family_variants: dict[str, set[str]] = defaultdict(set)
        for v in report.variants:
            for pid in v.failed_patterns:
                from agentic_security_harness.remediation import _FAMILY_MAP

                fam: str = _FAMILY_MAP.get(pid, "provenance")
                family_variants[fam].add(v.variant_id)
        for family, count in sorted(
            s.findings_by_control_family.items(), key=lambda x: -x[1]
        ):
            n_var = len(family_variants.get(family, set()))
            lines.append(f"| {family} | {count} | {n_var} |")

    # Next reading
    lines += [
        "",
        "## Next reading",
        "",
        "- `summary.md` - pattern-level results",
        "- `executive.md` - scope, headline result, top control families",
        "- `remediation.md` - control recommendations per finding",
        "- `traces.json` - portable machine-readable failure traces",
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
