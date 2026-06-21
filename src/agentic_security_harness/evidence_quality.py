"""Derived evidence-quality analysis for external/local model artifacts.

This module does not call models. It reads existing ``run-external`` /
``local-suite`` artifacts plus ``local-swarm`` artifacts and summarizes whether
the recorded evidence is usable, weak, flaky, incomplete, or contract-covered.
The output is a research aid, not a model leaderboard.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.local_swarm import LocalSwarmSummary
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


class LocalSwarmEvidenceRun(BaseModel):
    """Evidence-quality summary for one local-swarm artifact directory."""

    model_config = ConfigDict(extra="forbid")

    run_dir: str
    model: str = ""
    executed_model_calls: bool = False
    request_count: int = 0
    max_requests: int = 0
    scenarios: int = 0
    modes: int = 0
    results: int = 0
    monolith_boundary_failures: int = 0
    naive_swarm_boundary_failures: int = 0
    bounded_swarm_boundary_failures: int = 0
    verifier_blocks: int = 0
    invalid_acceptances: int = 0
    unique_blocked_reasons: int = 0
    role_transcripts: int = 0
    role_transcript_hashes: int = 0
    adapter_errors: int = 0
    contract_coverage: float = 0.0
    evidence_completeness: float = 0.0
    role_transcript_hash_coverage: float = 0.0
    adapter_error_rate: float = 0.0
    bounded_failure_reduction_vs_naive: float = 0.0
    evidence_maturity: str = "deterministic_example"
    runtime_mode_coverage_rate: float = 0.0


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
    local_swarm_runs_count: int = 0
    local_swarm_results: int = 0
    local_swarm_executed_runs: int = 0
    local_swarm_contract_coverage_rate: float = 0.0
    local_swarm_evidence_completeness_rate: float = 0.0
    local_swarm_transcript_hash_coverage_rate: float = 0.0
    local_swarm_adapter_error_rate: float = 0.0
    local_swarm_runtime_mode_coverage_rate: float = 0.0
    outcome_counts: dict[str, int] = Field(default_factory=dict)
    stability_counts: dict[str, int] = Field(default_factory=dict)
    runs: list[EvidenceQualityRun] = Field(default_factory=list)
    local_swarm_runs: list[LocalSwarmEvidenceRun] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    safety_note: str = (
        "Derived evidence-quality analysis only. No model calls, no tool execution, "
        "and no model-safety or live multi-agent runtime claim."
    )


def build_evidence_quality_report(root: Path) -> EvidenceQualityReport:
    """Build a derived report for all external/local run artifacts under ``root``."""
    run_dirs = discover_external_run_dirs(root)
    local_swarm_dirs = discover_local_swarm_run_dirs(root)
    warnings: list[str] = []
    runs: list[EvidenceQualityRun] = []
    local_swarm_runs: list[LocalSwarmEvidenceRun] = []
    summaries: list[tuple[str, ExternalSummary]] = []

    for run_dir in run_dirs:
        try:
            config, results, summary = load_external_artifacts(run_dir)
        except ValueError as exc:
            warnings.append(f"{run_dir.as_posix()}: {exc}")
            continue
        runs.append(summarize_run(run_dir, config, results, summary))
        summaries.append((run_dir.as_posix(), summary))

    for run_dir in local_swarm_dirs:
        try:
            local_swarm_summary = load_local_swarm_artifact(run_dir)
        except ValueError as exc:
            warnings.append(f"{run_dir.as_posix()}: {exc}")
            continue
        local_swarm_runs.append(
            summarize_local_swarm_run(run_dir, local_swarm_summary)
        )

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
    local_results = sum(r.results for r in local_swarm_runs)
    local_scenarios = sum(r.scenarios for r in local_swarm_runs)
    local_transcripts = sum(r.role_transcripts for r in local_swarm_runs)
    local_expected_modes = sum(r.modes for r in local_swarm_runs)
    warnings.extend(_local_swarm_warnings(local_swarm_runs))

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
        local_swarm_runs_count=len(local_swarm_runs),
        local_swarm_results=local_results,
        local_swarm_executed_runs=sum(1 for r in local_swarm_runs if r.executed_model_calls),
        local_swarm_contract_coverage_rate=_weighted_rate(
            ((r.contract_coverage, r.scenarios) for r in local_swarm_runs),
            local_scenarios,
        ),
        local_swarm_evidence_completeness_rate=_weighted_rate(
            ((r.evidence_completeness, r.results) for r in local_swarm_runs),
            local_results,
        ),
        local_swarm_transcript_hash_coverage_rate=_ratio(
            sum(r.role_transcript_hashes for r in local_swarm_runs),
            local_transcripts,
        ),
        local_swarm_adapter_error_rate=_ratio(
            sum(r.adapter_errors for r in local_swarm_runs),
            local_transcripts,
        ),
        local_swarm_runtime_mode_coverage_rate=_weighted_rate(
            ((r.runtime_mode_coverage_rate, r.modes) for r in local_swarm_runs),
            local_expected_modes,
        ),
        outcome_counts=dict(sorted(outcome_counts.items())),
        stability_counts=dict(sorted(stability_counts.items())),
        runs=runs,
        local_swarm_runs=local_swarm_runs,
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


def discover_local_swarm_run_dirs(root: Path) -> list[Path]:
    """Return directories under ``root`` that contain local-swarm artifacts."""
    if not root.exists():
        return []
    if root.is_file():
        return []
    candidates: set[Path] = set()
    if (root / "local_swarm_summary.json").is_file():
        candidates.add(root)
    for path in root.rglob("local_swarm_summary.json"):
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


def load_local_swarm_artifact(run_dir: Path) -> LocalSwarmSummary:
    """Load one local-swarm directory with the strict artifact model."""
    summary_path = run_dir / "local_swarm_summary.json"
    if not summary_path.is_file():
        raise ValueError("missing required artifact: local_swarm_summary.json")
    try:
        return LocalSwarmSummary.model_validate(_load_json(summary_path))
    except Exception as exc:
        raise ValueError(f"invalid local-swarm artifact: {exc}") from exc


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


def summarize_local_swarm_run(
    run_dir: Path,
    summary: LocalSwarmSummary,
) -> LocalSwarmEvidenceRun:
    """Summarize deterministic and model-evidence quality for one local-swarm run."""
    transcript_count = 0
    transcript_hash_count = 0
    adapter_error_count = 0
    for result in summary.results:
        for transcript in result.role_transcripts:
            transcript_count += 1
            if transcript.prompt_sha256 and transcript.response_sha256:
                transcript_hash_count += 1
            if transcript.adapter_error:
                adapter_error_count += 1
    metrics = summary.metrics
    runtime_mode_coverage = _local_swarm_runtime_mode_coverage(summary)
    return LocalSwarmEvidenceRun(
        run_dir=run_dir.as_posix(),
        model=summary.model,
        executed_model_calls=summary.executed_model_calls,
        request_count=summary.request_count,
        max_requests=summary.max_requests,
        scenarios=len(summary.scenarios),
        modes=len(summary.modes),
        results=len(summary.results),
        monolith_boundary_failures=metrics.monolith_boundary_failures,
        naive_swarm_boundary_failures=metrics.naive_swarm_boundary_failures,
        bounded_swarm_boundary_failures=metrics.bounded_swarm_boundary_failures,
        verifier_blocks=metrics.verifier_blocks,
        invalid_acceptances=metrics.invalid_acceptances,
        unique_blocked_reasons=metrics.unique_blocked_reasons,
        role_transcripts=transcript_count,
        role_transcript_hashes=transcript_hash_count,
        adapter_errors=adapter_error_count,
        contract_coverage=metrics.contract_coverage,
        evidence_completeness=metrics.evidence_completeness,
        role_transcript_hash_coverage=metrics.role_transcript_hash_coverage,
        adapter_error_rate=metrics.adapter_error_rate,
        bounded_failure_reduction_vs_naive=metrics.bounded_failure_reduction_vs_naive,
        evidence_maturity=_local_swarm_evidence_maturity(summary, runtime_mode_coverage),
        runtime_mode_coverage_rate=runtime_mode_coverage,
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
        f"- Local-swarm runs: {report.local_swarm_runs_count}",
        f"- Local-swarm results: {report.local_swarm_results}",
        f"- Local-swarm contract coverage: "
        f"{_pct(report.local_swarm_contract_coverage_rate)}",
        f"- Local-swarm transcript hash coverage: "
        f"{_pct(report.local_swarm_transcript_hash_coverage_rate)}",
        f"- Local-swarm adapter error rate: "
        f"{_pct(report.local_swarm_adapter_error_rate)}",
        f"- Local-swarm runtime mode coverage: "
        f"{_pct(report.local_swarm_runtime_mode_coverage_rate)}",
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

    if report.local_swarm_runs:
        lines += [
            "",
            "## Local swarm runs",
            "",
            "| Run | Model | Exec | Scenarios | Modes | Results | Blocks | Contract | "
            "Evidence | Transcript hash | Adapter errors | Runtime modes | Maturity |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
        for swarm_run in report.local_swarm_runs:
            lines.append(
                f"| `{swarm_run.run_dir}` | `{swarm_run.model}` | "
                f"{swarm_run.executed_model_calls} | {swarm_run.scenarios} | "
                f"{swarm_run.modes} | {swarm_run.results} | "
                f"{swarm_run.verifier_blocks} | "
                f"{_pct(swarm_run.contract_coverage)} | "
                f"{_pct(swarm_run.evidence_completeness)} | "
                f"{_pct(swarm_run.role_transcript_hash_coverage)} | "
                f"{swarm_run.adapter_errors} | "
                f"{_pct(swarm_run.runtime_mode_coverage_rate)} | "
                f"`{swarm_run.evidence_maturity}` |"
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
        "- Local-swarm role text is evidence context only; deterministic contracts decide "
        "the boundary verdict.",
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


def _local_swarm_runtime_mode_coverage(summary: LocalSwarmSummary) -> float:
    if not summary.executed_model_calls:
        return 0.0
    modes_with_transcripts = {
        result.mode for result in summary.results if result.role_transcripts
    }
    return _ratio(len(modes_with_transcripts), len(summary.modes))


def _local_swarm_evidence_maturity(
    summary: LocalSwarmSummary,
    runtime_mode_coverage: float,
) -> str:
    if not summary.executed_model_calls:
        return "deterministic_example"
    if runtime_mode_coverage >= 1.0 and len(summary.modes) >= 3:
        return "full_runtime_comparison"
    if "bounded_swarm" in summary.modes and runtime_mode_coverage > 0:
        return "bounded_runtime_smoke"
    return "incomplete_runtime_evidence"


def _local_swarm_warnings(runs: list[LocalSwarmEvidenceRun]) -> list[str]:
    warnings: list[str] = []
    for run in runs:
        if run.evidence_maturity == "bounded_runtime_smoke":
            warnings.append(
                f"{run.run_dir}: executed local-swarm evidence covers bounded mode only; "
                "run all modes before comparing model-channel behavior."
            )
        if run.executed_model_calls and run.role_transcript_hash_coverage < 1.0:
            warnings.append(
                f"{run.run_dir}: executed local-swarm evidence has incomplete transcript "
                "hash coverage."
            )
        if run.adapter_error_rate > 0:
            warnings.append(
                f"{run.run_dir}: local-swarm adapter errors are evidence-quality "
                "weak spots, not verifier failures."
            )
    return warnings


def _weighted_rate(items: Iterable[tuple[float, int]], denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    total = 0.0
    for value, weight in items:
        total += float(value) * int(weight)
    return round(total / denominator, 6)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"
