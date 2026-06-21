"""Derived evidence-quality analysis for external/local model artifacts.

This module does not call models. It reads existing ``run-external`` /
``local-suite`` artifacts and summarizes whether the recorded evidence is usable,
weak, flaky, or incomplete. The output is a research aid, not a model leaderboard.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.run_config import (
    ExternalResult,
    ExternalSummary,
    RunConfig,
)
from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS

_DECISIVE_OUTCOMES = frozenset({"pass", "finding"})
_WEAK_OUTCOMES = frozenset({"inconclusive", "adapter_error"})
_STABILITY_WEAK = frozenset({"flaky", "inconclusive", "adapter_error"})


class EvidenceQualityRun(BaseModel):
    """Evidence-quality summary for one external/local run directory."""

    model_config = ConfigDict(extra="forbid")

    run_dir: str
    model: str = ""
    scenario_id: str = ""
    runtime_name: str = ""
    local_only: bool = False
    prompt_only: bool = True
    tool_execution: bool = False
    total_results: int = 0
    pass_count: int = 0
    finding_count: int = 0
    inconclusive_count: int = 0
    adapter_error_count: int = 0
    invalid_outcome_count: int = 0
    parse_error_count: int = 0
    raw_response_count: int = 0
    raw_response_hash_count: int = 0
    assertion_bound_count: int = 0
    assertion_pass_count: int = 0
    assertion_finding_count: int = 0
    repeat_groups: int = 0
    stable_pass_groups: int = 0
    stable_finding_groups: int = 0
    flaky_groups: int = 0
    inconclusive_groups: int = 0
    adapter_error_groups: int = 0
    decisive_rate: float = 0.0
    weak_evidence_rate: float = 0.0
    raw_response_coverage_rate: float = 0.0
    raw_hash_coverage_rate: float = 0.0
    assertion_binding_rate: float = 0.0


class EvidenceQualityReport(BaseModel):
    """Aggregate evidence-quality report across one or more run directories."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["evidence_quality"]
    generated_by: str = "ash evidence-quality"
    total_runs: int = 0
    total_results: int = 0
    decisive_rate: float = 0.0
    weak_evidence_rate: float = 0.0
    raw_response_coverage_rate: float = 0.0
    raw_hash_coverage_rate: float = 0.0
    assertion_binding_rate: float = 0.0
    comparable_groups: int = 0
    disagreement_groups: int = 0
    cross_run_disagreement_rate: float = 0.0
    outcome_counts: dict[str, int] = Field(default_factory=dict)
    stability_counts: dict[str, int] = Field(default_factory=dict)
    runs: list[EvidenceQualityRun] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    safety_note: str = (
        "Derived evidence-quality analysis only. No model calls, no tool execution, "
        "and no model-safety or live multi-agent runtime claim."
    )


def build_evidence_quality_report(root: Path) -> EvidenceQualityReport:
    """Build a derived report for all external/local run artifacts under ``root``."""
    run_dirs = discover_external_run_dirs(root)
    warnings: list[str] = []
    runs: list[EvidenceQualityRun] = []
    summaries: list[tuple[str, ExternalSummary]] = []

    for run_dir in run_dirs:
        try:
            config, results, summary = load_external_artifacts(run_dir)
        except ValueError as exc:
            warnings.append(f"{run_dir.as_posix()}: {exc}")
            continue
        runs.append(summarize_run(run_dir, config, results, summary))
        summaries.append((run_dir.as_posix(), summary))

    total_results = sum(r.total_results for r in runs)
    outcome_counts: Counter[str] = Counter()
    stability_counts: Counter[str] = Counter()
    for run in runs:
        outcome_counts.update({
            "pass": run.pass_count,
            "finding": run.finding_count,
            "inconclusive": run.inconclusive_count,
            "adapter_error": run.adapter_error_count,
            "invalid": run.invalid_outcome_count,
        })
        stability_counts.update({
            "stable_pass": run.stable_pass_groups,
            "stable_finding": run.stable_finding_groups,
            "flaky": run.flaky_groups,
            "inconclusive": run.inconclusive_groups,
            "adapter_error": run.adapter_error_groups,
        })

    comparable, disagreements = _cross_run_disagreement(summaries)

    return EvidenceQualityReport(
        total_runs=len(runs),
        total_results=total_results,
        decisive_rate=_ratio(
            outcome_counts["pass"] + outcome_counts["finding"], total_results
        ),
        weak_evidence_rate=_ratio(
            outcome_counts["inconclusive"] + outcome_counts["adapter_error"],
            total_results,
        ),
        raw_response_coverage_rate=_ratio(
            sum(r.raw_response_count for r in runs), total_results
        ),
        raw_hash_coverage_rate=_ratio(
            sum(r.raw_response_hash_count for r in runs), total_results
        ),
        assertion_binding_rate=_ratio(
            sum(r.assertion_bound_count for r in runs), total_results
        ),
        comparable_groups=comparable,
        disagreement_groups=disagreements,
        cross_run_disagreement_rate=_ratio(disagreements, comparable),
        outcome_counts=dict(sorted(outcome_counts.items())),
        stability_counts=dict(sorted(stability_counts.items())),
        runs=runs,
        warnings=warnings,
    )


def discover_external_run_dirs(root: Path) -> list[Path]:
    """Return directories under ``root`` that contain external run artifacts."""
    if not root.exists():
        return []
    if root.is_file():
        return []
    candidates: set[Path] = set()
    if (root / "external_results.json").is_file():
        candidates.add(root)
    for path in root.rglob("external_results.json"):
        candidates.add(path.parent)
    return sorted(candidates)


def load_external_artifacts(
    run_dir: Path,
) -> tuple[RunConfig, list[ExternalResult], ExternalSummary]:
    """Load one external/local run directory with strict artifact models."""
    config_path = run_dir / "run_config.json"
    results_path = run_dir / "external_results.json"
    summary_path = run_dir / "external_summary.json"
    missing = [
        p.name for p in (config_path, results_path, summary_path) if not p.is_file()
    ]
    if missing:
        raise ValueError(f"missing required artifact(s): {', '.join(missing)}")
    try:
        config = RunConfig.model_validate(_load_json(config_path))
        raw_results = _load_json(results_path)
        if not isinstance(raw_results, list):
            raise ValueError("external_results.json must be a list")
        results = [ExternalResult.model_validate(item) for item in raw_results]
        summary = ExternalSummary.model_validate(_load_json(summary_path))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"invalid external artifact: {exc}") from exc
    return config, results, summary


def summarize_run(
    run_dir: Path,
    config: RunConfig,
    results: list[ExternalResult],
    summary: ExternalSummary,
) -> EvidenceQualityRun:
    """Summarize one run from already-validated external result models."""
    outcomes: Counter[str] = Counter()
    parse_error_count = 0
    raw_response_count = 0
    raw_response_hash_count = 0
    assertion_bound_count = 0
    assertion_pass_count = 0
    assertion_finding_count = 0

    for result in results:
        outcome = result.deterministic_cross_check
        if outcome not in _DECISIVE_OUTCOMES | _WEAK_OUTCOMES:
            outcomes["invalid"] += 1
        else:
            outcomes[outcome] += 1
        if result.parse_error:
            parse_error_count += 1
        if result.raw_response_path:
            raw_response_count += 1
        if result.raw_response_path and result.raw_response_sha256:
            raw_response_hash_count += 1
        if result.assertion_id and result.assertion_result:
            assertion_bound_count += 1
        if result.assertion_result == "pass":
            assertion_pass_count += 1
        elif result.assertion_result == "finding":
            assertion_finding_count += 1

    stability = Counter(rs.stability_status for rs in summary.repeat_summaries)
    total = len(results)
    return EvidenceQualityRun(
        run_dir=run_dir.as_posix(),
        model=config.model,
        scenario_id=config.scenario_id,
        runtime_name=config.runtime.runtime_name,
        local_only=config.runtime.local_only,
        prompt_only=config.runtime.prompt_only,
        tool_execution=config.runtime.tool_execution,
        total_results=total,
        pass_count=outcomes["pass"],
        finding_count=outcomes["finding"],
        inconclusive_count=outcomes["inconclusive"],
        adapter_error_count=outcomes["adapter_error"],
        invalid_outcome_count=outcomes["invalid"],
        parse_error_count=parse_error_count,
        raw_response_count=raw_response_count,
        raw_response_hash_count=raw_response_hash_count,
        assertion_bound_count=assertion_bound_count,
        assertion_pass_count=assertion_pass_count,
        assertion_finding_count=assertion_finding_count,
        repeat_groups=len(summary.repeat_summaries),
        stable_pass_groups=stability["stable_pass"],
        stable_finding_groups=stability["stable_finding"],
        flaky_groups=stability["flaky"],
        inconclusive_groups=stability["inconclusive"],
        adapter_error_groups=stability["adapter_error"],
        decisive_rate=_ratio(outcomes["pass"] + outcomes["finding"], total),
        weak_evidence_rate=_ratio(
            outcomes["inconclusive"] + outcomes["adapter_error"], total
        ),
        raw_response_coverage_rate=_ratio(raw_response_count, total),
        raw_hash_coverage_rate=_ratio(raw_response_hash_count, total),
        assertion_binding_rate=_ratio(assertion_bound_count, total),
    )


def write_evidence_quality(report: EvidenceQualityReport, out_dir: Path) -> dict[str, Path]:
    """Write JSON and Markdown evidence-quality artifacts."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = write_text_artifact(
        out_dir / "evidence_quality.json",
        json.dumps(report.model_dump(mode="json"), indent=2) + "\n",
    )
    md_path = write_text_artifact(
        out_dir / "evidence_quality.md",
        build_evidence_quality_markdown(report),
    )
    return {"json": json_path, "markdown": md_path}


def build_evidence_quality_markdown(report: EvidenceQualityReport) -> str:
    """Render a compact reviewer-facing Markdown report."""
    lines = [
        "# Evidence quality report",
        "",
        "> Derived analysis only. This does not call a model and is not a model "
        "leaderboard or live multi-agent runtime claim.",
        "",
        "## Aggregate",
        "",
        f"- Runs: {report.total_runs}",
        f"- Results: {report.total_results}",
        f"- Decisive rate: {_pct(report.decisive_rate)}",
        f"- Weak evidence rate: {_pct(report.weak_evidence_rate)}",
        f"- Raw response coverage: {_pct(report.raw_response_coverage_rate)}",
        f"- Raw hash coverage: {_pct(report.raw_hash_coverage_rate)}",
        f"- Assertion binding: {_pct(report.assertion_binding_rate)}",
        f"- Cross-run disagreement: {report.disagreement_groups}/"
        f"{report.comparable_groups} ({_pct(report.cross_run_disagreement_rate)})",
        "",
        "## Outcome counts",
        "",
        "| Outcome | Count |",
        "|---|---:|",
    ]
    for outcome, count in sorted(report.outcome_counts.items()):
        lines.append(f"| `{outcome}` | {count} |")

    lines += [
        "",
        "## Runs",
        "",
        "| Run | Model | Scenario | Results | Decisive | Weak | Raw/hash | Stability weak groups |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for run in report.runs:
        weak_groups = run.flaky_groups + run.inconclusive_groups + run.adapter_error_groups
        lines.append(
            f"| `{run.run_dir}` | `{run.model}` | `{run.scenario_id}` | "
            f"{run.total_results} | {_pct(run.decisive_rate)} | "
            f"{_pct(run.weak_evidence_rate)} | {_pct(run.raw_hash_coverage_rate)} | "
            f"{weak_groups} |"
        )

    if report.warnings:
        lines += ["", "## Warnings", ""]
        for warning in report.warnings:
            lines.append(f"- {warning}")

    lines += [
        "",
        "## Claim boundary",
        "",
        "- Decisive model self-reports are still checked by deterministic harness fields.",
        "- Inconclusive, adapter_error, and flaky outcomes are weak evidence, not pass/finding.",
        "- Raw local model responses remain local/private unless curated and promoted.",
        "",
    ]
    return "\n".join(lines)


def _cross_run_disagreement(
    summaries: list[tuple[str, ExternalSummary]],
) -> tuple[int, int]:
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for _run_dir, summary in summaries:
        for repeat in summary.repeat_summaries:
            status = repeat.stability_status
            if status in _STABILITY_WEAK:
                normalized = status
            elif status in {"stable_pass", "stable_finding"}:
                normalized = status
            else:
                normalized = "unknown"
            groups[(repeat.pattern_id, repeat.variant_id)].add(normalized)
    comparable = sum(1 for statuses in groups.values() if len(statuses) >= 1)
    disagreements = sum(1 for statuses in groups.values() if len(statuses) > 1)
    return comparable, disagreements


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"
