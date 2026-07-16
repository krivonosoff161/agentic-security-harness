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
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.local_swarm import LocalSwarmSummary
from agentic_security_harness.run_config import (
    ExternalResult,
    ExternalSummary,
    RunConfig,
)
from agentic_security_harness.run_manifest import build_manifest, write_run_manifest
from agentic_security_harness.safe_io import (
    atomic_evidence_bundle,
    require_fresh_output_dir,
    write_text_artifact,
)
from agentic_security_harness.safe_markdown import markdown_code_span, markdown_prose
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS, check_schema_version
from agentic_security_harness.validation import validate_artifact_path

_DECISIVE_OUTCOMES = frozenset({"pass", "finding"})
_WEAK_OUTCOMES = frozenset({"inconclusive", "adapter_error"})
_STABILITY_WEAK = frozenset({"flaky", "inconclusive", "adapter_error"})
_SAFETY_NOTE = (
    "Derived evidence-quality analysis only. No model calls, no tool execution, "
    "and no model-safety or live multi-agent runtime claim. Included bundles pass "
    "artifact validation, but their manifests are unsigned."
)


class EvidenceQualityStatus(BaseModel):
    """One external pattern/variant stability status retained for regrouping."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    variant_id: str
    status: str


class EvidenceQualityRun(BaseModel):
    """Evidence-quality summary for one external/local run directory."""

    model_config = ConfigDict(extra="forbid")

    run_dir: str
    manifest_schema_version: str = ""
    artifact_validation: str = ""
    origin_authentication: str = "unsigned"
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
    comparison_statuses: list[EvidenceQualityStatus] = Field(default_factory=list)


class LocalSwarmEvidenceRun(BaseModel):
    """Evidence-quality summary for one local-swarm artifact directory."""

    model_config = ConfigDict(extra="forbid")

    run_dir: str
    manifest_schema_version: str = ""
    artifact_validation: str = ""
    origin_authentication: str = "unsigned"
    model: str = ""
    executed_model_calls: bool = False
    request_count: int = 0
    max_requests: int = 0
    scenarios: int = 0
    modes: int = 0
    scenario_ids: list[str] = Field(default_factory=list)
    mode_ids: list[str] = Field(default_factory=list)
    runtime_mode_ids: list[str] = Field(default_factory=list)
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


class EvidenceQualityComparisonGroup(BaseModel):
    """Statuses retained so cross-run disagreement can be independently rebuilt."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    variant_id: str
    statuses: list[str] = Field(default_factory=list)


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
    comparison_groups: list[EvidenceQualityComparisonGroup] = Field(default_factory=list)
    runs: list[EvidenceQualityRun] = Field(default_factory=list)
    local_swarm_runs: list[LocalSwarmEvidenceRun] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    safety_note: str = _SAFETY_NOTE


class ArtifactValidationContext(BaseModel):
    """Validation strength carried into every derived evidence-quality row."""

    model_config = ConfigDict(extra="forbid")

    manifest_schema_version: str
    artifact_validation: str
    origin_authentication: str = "unsigned"


def build_evidence_quality_report(root: Path) -> EvidenceQualityReport:
    """Build a derived report for all external/local run artifacts under ``root``."""
    run_dirs = discover_external_run_dirs(root)
    local_swarm_dirs = discover_local_swarm_run_dirs(root)
    warnings: list[str] = []
    runs: list[EvidenceQualityRun] = []
    local_swarm_runs: list[LocalSwarmEvidenceRun] = []
    summaries: list[tuple[str, ExternalSummary]] = []

    for run_dir in run_dirs:
        run_label = _portable_run_label(root, run_dir)
        try:
            config, results, summary, context = load_external_artifacts(run_dir)
        except ValueError as exc:
            warnings.append(f"{run_label}: {exc}")
            continue
        runs.append(summarize_run(run_label, config, results, summary, context))
        summaries.append((run_label, summary))
        _append_validation_scope_warning(run_label, context, warnings)

    for run_dir in local_swarm_dirs:
        run_label = _portable_run_label(root, run_dir)
        try:
            local_swarm_summary, context = load_local_swarm_artifact(run_dir)
        except ValueError as exc:
            warnings.append(f"{run_label}: {exc}")
            continue
        local_swarm_runs.append(
            summarize_local_swarm_run(run_label, local_swarm_summary, context)
        )
        _append_validation_scope_warning(run_label, context, warnings)

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

    comparable, disagreements, comparison_groups = _cross_run_disagreement(summaries)
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
        comparison_groups=comparison_groups,
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
) -> tuple[RunConfig, list[ExternalResult], ExternalSummary, ArtifactValidationContext]:
    """Validate and load one external/local run bundle."""

    context = _validated_bundle_context(run_dir)
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
    return config, results, summary, context


def load_local_swarm_artifact(
    run_dir: Path,
) -> tuple[LocalSwarmSummary, ArtifactValidationContext]:
    """Validate and load one local-swarm bundle."""

    context = _validated_bundle_context(run_dir)
    summary_path = run_dir / "local_swarm_summary.json"
    if not summary_path.is_file():
        raise ValueError("missing required artifact: local_swarm_summary.json")
    try:
        return LocalSwarmSummary.model_validate(_load_json(summary_path)), context
    except Exception as exc:
        raise ValueError(f"invalid local-swarm artifact: {exc}") from exc


def summarize_run(
    run_label: str,
    config: RunConfig,
    results: list[ExternalResult],
    summary: ExternalSummary,
    context: ArtifactValidationContext,
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
        run_dir=run_label,
        manifest_schema_version=context.manifest_schema_version,
        artifact_validation=context.artifact_validation,
        origin_authentication=context.origin_authentication,
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
        comparison_statuses=_external_comparison_statuses(summary),
    )


def summarize_local_swarm_run(
    run_label: str,
    summary: LocalSwarmSummary,
    context: ArtifactValidationContext,
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
        run_dir=run_label,
        manifest_schema_version=context.manifest_schema_version,
        artifact_validation=context.artifact_validation,
        origin_authentication=context.origin_authentication,
        model=summary.model,
        executed_model_calls=summary.executed_model_calls,
        request_count=summary.request_count,
        max_requests=summary.max_requests,
        scenarios=len(summary.scenarios),
        modes=len(summary.modes),
        scenario_ids=[str(scenario) for scenario in summary.scenarios],
        mode_ids=[str(mode) for mode in summary.modes],
        runtime_mode_ids=sorted(
            str(mode)
            for mode in {
                result.mode for result in summary.results if result.role_transcripts
            }
        ),
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


@atomic_evidence_bundle("out_dir")
def write_evidence_quality(report: EvidenceQualityReport, out_dir: Path) -> dict[str, Path]:
    """Write a content-bound evidence-quality artifact bundle."""

    projection_errors = validate_evidence_quality_projection(report)
    if projection_errors:
        raise ValueError(
            "refusing to persist invalid evidence-quality projection: "
            + "; ".join(projection_errors)
        )
    require_fresh_output_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = write_text_artifact(
        out_dir / "evidence_quality.json",
        json.dumps(report.model_dump(mode="json"), indent=2) + "\n",
    )
    md_path = write_text_artifact(
        out_dir / "evidence_quality.md",
        build_evidence_quality_markdown(report),
    )
    projection = evidence_quality_manifest_projection(report)
    manifest = build_manifest(
        "evidence_quality",
        out_dir,
        target=str(projection["target"]),
        scenario=str(projection["scenario"]),
        outcomes=projection["outcomes"],  # type: ignore[arg-type]
        metadata=projection["metadata"],  # type: ignore[arg-type]
        artifacts=["evidence_quality.json", "evidence_quality.md"],
        created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    manifest_path = write_run_manifest(out_dir, manifest)
    return {"json": json_path, "markdown": md_path, "run_index": manifest_path}


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
        lines.append(f"| {markdown_code_span(outcome)} | {count} |")

    lines += [
        "",
        "## Runs",
        "",
        "| Run | Validation | Model | Scenario | Results | Decisive | Weak | Raw/hash | "
        "Stability weak groups |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for run in report.runs:
        weak_groups = run.flaky_groups + run.inconclusive_groups + run.adapter_error_groups
        lines.append(
            f"| {markdown_code_span(run.run_dir)} | "
            f"{markdown_code_span(run.artifact_validation)} / "
            f"{markdown_code_span(run.origin_authentication)} | "
            f"{markdown_code_span(run.model)} | {markdown_code_span(run.scenario_id)} | "
            f"{run.total_results} | {_pct(run.decisive_rate)} | "
            f"{_pct(run.weak_evidence_rate)} | {_pct(run.raw_hash_coverage_rate)} | "
            f"{weak_groups} |"
        )

    if report.local_swarm_runs:
        lines += [
            "",
            "## Local swarm runs",
            "",
            "| Run | Validation | Model | Exec | Scenarios | Modes | Results | Blocks | Contract | "
            "Evidence | Transcript hash | Adapter errors | Runtime modes | Maturity |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
        for swarm_run in report.local_swarm_runs:
            lines.append(
                f"| {markdown_code_span(swarm_run.run_dir)} | "
                f"{markdown_code_span(swarm_run.artifact_validation)} / "
                f"{markdown_code_span(swarm_run.origin_authentication)} | "
                f"{markdown_code_span(swarm_run.model)} | "
                f"{swarm_run.executed_model_calls} | {swarm_run.scenarios} | "
                f"{swarm_run.modes} | {swarm_run.results} | "
                f"{swarm_run.verifier_blocks} | "
                f"{_pct(swarm_run.contract_coverage)} | "
                f"{_pct(swarm_run.evidence_completeness)} | "
                f"{_pct(swarm_run.role_transcript_hash_coverage)} | "
                f"{swarm_run.adapter_errors} | "
                f"{_pct(swarm_run.runtime_mode_coverage_rate)} | "
                f"{markdown_code_span(swarm_run.evidence_maturity)} |"
            )

    if report.warnings:
        lines += ["", "## Warnings", ""]
        for warning in report.warnings:
            lines.append(f"- {markdown_prose(warning)}")

    lines += [
        "",
        "## Claim boundary",
        "",
        "- Decisive model self-reports are still checked by deterministic harness fields.",
        "- Inconclusive, adapter_error, and flaky outcomes are weak evidence, not pass/finding.",
        "- Raw local model responses remain local/private unless curated and promoted.",
        "- Local-swarm role text is evidence context only; deterministic contracts decide "
        "the boundary verdict.",
        "- Current manifest hashes bind persisted bytes but remain unsigned; legacy bundles "
        "receive structural validation only.",
        "",
    ]
    return "\n".join(lines)


def _cross_run_disagreement(
    summaries: list[tuple[str, ExternalSummary]],
) -> tuple[int, int, list[EvidenceQualityComparisonGroup]]:
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for _run_dir, summary in summaries:
        for item in _external_comparison_statuses(summary):
            groups[(item.pattern_id, item.variant_id)].add(item.status)
    comparison_groups = [
        EvidenceQualityComparisonGroup(
            pattern_id=pattern_id,
            variant_id=variant_id,
            statuses=sorted(statuses),
        )
        for (pattern_id, variant_id), statuses in sorted(groups.items())
    ]
    comparable = len(comparison_groups)
    disagreements = sum(1 for group in comparison_groups if len(group.statuses) > 1)
    return comparable, disagreements, comparison_groups


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _external_comparison_statuses(
    summary: ExternalSummary,
) -> list[EvidenceQualityStatus]:
    statuses: list[EvidenceQualityStatus] = []
    for repeat in summary.repeat_summaries:
        status = repeat.stability_status
        if status in _STABILITY_WEAK or status in {"stable_pass", "stable_finding"}:
            normalized = status
        else:
            normalized = "unknown"
        statuses.append(EvidenceQualityStatus(
            pattern_id=repeat.pattern_id,
            variant_id=repeat.variant_id,
            status=normalized,
        ))
    return statuses


def _validated_bundle_context(run_dir: Path) -> ArtifactValidationContext:
    manifest_path = run_dir / "run_index.json"
    if not manifest_path.is_file():
        raise ValueError("excluded: missing run_index.json validation boundary")
    validation = validate_artifact_path(run_dir)
    if not validation.integrity_ok:
        details = "; ".join(validation.errors) or "artifact integrity validation failed"
        raise ValueError(f"excluded: artifact integrity validation failed: {details}")
    try:
        manifest_raw = _load_json(manifest_path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"excluded: unreadable run_index.json: {exc}") from exc
    if not isinstance(manifest_raw, dict):
        raise ValueError("excluded: run_index.json must be an object")
    schema_version = str(manifest_raw.get("schema_version") or "")
    scope = (
        "current_content_bound"
        if schema_version == SCHEMA_VERSIONS["run_manifest"]
        else "legacy_structural"
    )
    return ArtifactValidationContext(
        manifest_schema_version=schema_version,
        artifact_validation=scope,
    )


def _append_validation_scope_warning(
    run_label: str,
    context: ArtifactValidationContext,
    warnings: list[str],
) -> None:
    if context.artifact_validation == "legacy_structural":
        warnings.append(
            f"{run_label}: legacy manifest schema "
            f"{context.manifest_schema_version} is structurally validated without "
            "persisted-byte hash binding; origin remains unsigned."
        )


def _portable_run_label(root: Path, run_dir: Path) -> str:
    try:
        relative = run_dir.resolve().relative_to(root.resolve())
    except ValueError:
        return run_dir.name
    label = relative.as_posix()
    return run_dir.name if label in {"", "."} else label


def evidence_quality_manifest_projection(report: EvidenceQualityReport) -> dict[str, object]:
    """Return the semantic manifest fields derived from one quality report."""

    validation_counts: Counter[str] = Counter()
    for external_row in report.runs:
        validation_counts[external_row.artifact_validation] += 1
    for swarm_row in report.local_swarm_runs:
        validation_counts[swarm_row.artifact_validation] += 1
    return {
        "target": "validated-recorded-artifact-quality",
        "scenario": "external-and-local-swarm",
        "outcomes": {
            "external_runs": report.total_runs,
            "external_results": report.total_results,
            "local_swarm_runs": report.local_swarm_runs_count,
            "local_swarm_results": report.local_swarm_results,
            "disagreement_groups": report.disagreement_groups,
        },
        "metadata": {
            "current_content_bound_runs": validation_counts["current_content_bound"],
            "legacy_structural_runs": validation_counts["legacy_structural"],
            "warning_count": len(report.warnings),
            "origin_authentication": "unsigned",
        },
    }


def validate_evidence_quality_projection(report: EvidenceQualityReport) -> list[str]:
    """Independently rebuild every aggregate retained by schema v0.3."""

    errors: list[str] = []
    if report.generated_by != "ash evidence-quality":
        errors.append("generated_by does not match the producer contract")
    if report.safety_note != _SAFETY_NOTE:
        errors.append("safety_note does not match the producer contract")

    labels = [row.run_dir for row in report.runs] + [
        row.run_dir for row in report.local_swarm_runs
    ]
    if len(labels) != len(set(labels)):
        errors.append("run_dir labels must be unique across included runs")
    for label in labels:
        if (
            not label
            or label.startswith("/")
            or "\\" in label
            or (len(label) >= 2 and label[1] == ":")
            or ".." in Path(label).parts
        ):
            errors.append(f"run_dir label is not a portable relative path: {label!r}")

    for warning in report.warnings:
        normalized = warning.replace("\\", "/")
        if (
            normalized.startswith("/")
            or (len(normalized) >= 2 and normalized[1] == ":")
            or "/AppData/" in normalized
            or "/Users/" in normalized
            or "/home/" in normalized
        ):
            errors.append("warning contains an absolute local path")

    outcome_counts: Counter[str] = Counter()
    stability_counts: Counter[str] = Counter()
    comparison_status_groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for external_run in report.runs:
        _validate_quality_row_scope(
            external_run.manifest_schema_version,
            external_run.artifact_validation,
            external_run.origin_authentication,
            external_run.run_dir,
            errors,
        )
        total = external_run.total_results
        outcome_values = (
            external_run.pass_count,
            external_run.finding_count,
            external_run.inconclusive_count,
            external_run.adapter_error_count,
            external_run.invalid_outcome_count,
        )
        if any(value < 0 for value in outcome_values) or sum(outcome_values) != total:
            errors.append(f"{external_run.run_dir}: outcome counts do not match total_results")
        if not (
            0 <= external_run.parse_error_count <= total
            and 0 <= external_run.raw_response_hash_count
            <= external_run.raw_response_count <= total
            and 0 <= external_run.assertion_bound_count <= total
            and 0
            <= external_run.assertion_pass_count + external_run.assertion_finding_count
            <= external_run.assertion_bound_count
        ):
            errors.append(f"{external_run.run_dir}: evidence coverage counts are impossible")
        stability_values = (
            external_run.stable_pass_groups,
            external_run.stable_finding_groups,
            external_run.flaky_groups,
            external_run.inconclusive_groups,
            external_run.adapter_error_groups,
        )
        if any(value < 0 for value in stability_values) or sum(stability_values) != (
            external_run.repeat_groups
        ):
            errors.append(f"{external_run.run_dir}: stability counts do not match groups")
        status_keys: list[tuple[str, str]] = []
        for status in external_run.comparison_statuses:
            key = (status.pattern_id, status.variant_id)
            status_keys.append(key)
            if (
                not status.pattern_id
                or status.status
                not in _STABILITY_WEAK | {"stable_pass", "stable_finding"}
            ):
                errors.append(f"{external_run.run_dir}: invalid comparison status")
            comparison_status_groups[key].add(status.status)
        if len(status_keys) != len(set(status_keys)):
            errors.append(f"{external_run.run_dir}: duplicate comparison status key")
        if len(status_keys) != external_run.repeat_groups:
            errors.append(
                f"{external_run.run_dir}: comparison statuses do not match repeat groups"
            )
        expected_decisive = _ratio(
            external_run.pass_count + external_run.finding_count, total
        )
        expected_weak = _ratio(
            external_run.inconclusive_count + external_run.adapter_error_count, total
        )
        expected_raw = _ratio(external_run.raw_response_count, total)
        expected_hash = _ratio(external_run.raw_response_hash_count, total)
        expected_assertion = _ratio(external_run.assertion_bound_count, total)
        for field, actual, expected in (
            ("decisive_rate", external_run.decisive_rate, expected_decisive),
            ("weak_evidence_rate", external_run.weak_evidence_rate, expected_weak),
            (
                "raw_response_coverage_rate",
                external_run.raw_response_coverage_rate,
                expected_raw,
            ),
            ("raw_hash_coverage_rate", external_run.raw_hash_coverage_rate, expected_hash),
            ("assertion_binding_rate", external_run.assertion_binding_rate, expected_assertion),
        ):
            if actual != expected:
                errors.append(
                    f"{external_run.run_dir}: {field} does not match row counts"
                )
        outcome_counts.update({
            "pass": external_run.pass_count,
            "finding": external_run.finding_count,
            "inconclusive": external_run.inconclusive_count,
            "adapter_error": external_run.adapter_error_count,
            "invalid": external_run.invalid_outcome_count,
        })
        stability_counts.update({
            "stable_pass": external_run.stable_pass_groups,
            "stable_finding": external_run.stable_finding_groups,
            "flaky": external_run.flaky_groups,
            "inconclusive": external_run.inconclusive_groups,
            "adapter_error": external_run.adapter_error_groups,
        })

    if report.total_runs != len(report.runs):
        errors.append("total_runs does not match runs")
    total_results = sum(external_run.total_results for external_run in report.runs)
    if report.total_results != total_results:
        errors.append("total_results does not match runs")
    if report.outcome_counts != dict(sorted(outcome_counts.items())):
        errors.append("outcome_counts does not match runs")
    if report.stability_counts != dict(sorted(stability_counts.items())):
        errors.append("stability_counts does not match runs")
    aggregate_rates = (
        ("decisive_rate", report.decisive_rate, _ratio(
            outcome_counts["pass"] + outcome_counts["finding"], total_results
        )),
        ("weak_evidence_rate", report.weak_evidence_rate, _ratio(
            outcome_counts["inconclusive"] + outcome_counts["adapter_error"], total_results
        )),
        ("raw_response_coverage_rate", report.raw_response_coverage_rate, _ratio(
            sum(external_run.raw_response_count for external_run in report.runs),
            total_results,
        )),
        ("raw_hash_coverage_rate", report.raw_hash_coverage_rate, _ratio(
            sum(external_run.raw_response_hash_count for external_run in report.runs),
            total_results,
        )),
        ("assertion_binding_rate", report.assertion_binding_rate, _ratio(
            sum(external_run.assertion_bound_count for external_run in report.runs),
            total_results,
        )),
    )
    for field, actual, expected in aggregate_rates:
        if actual != expected:
            errors.append(f"{field} does not match included runs")

    group_keys = [(group.pattern_id, group.variant_id) for group in report.comparison_groups]
    if len(group_keys) != len(set(group_keys)):
        errors.append("comparison_groups contain duplicate pattern/variant keys")
    for group in report.comparison_groups:
        if not group.pattern_id or group.statuses != sorted(set(group.statuses)):
            errors.append("comparison_group statuses must be non-empty, sorted, and unique")
    expected_groups = [
        EvidenceQualityComparisonGroup(
            pattern_id=pattern_id,
            variant_id=variant_id,
            statuses=sorted(statuses),
        )
        for (pattern_id, variant_id), statuses in sorted(comparison_status_groups.items())
    ]
    if report.comparison_groups != expected_groups:
        errors.append("comparison_groups do not match per-run comparison statuses")
    comparable = len(report.comparison_groups)
    disagreements = sum(1 for group in report.comparison_groups if len(group.statuses) > 1)
    if report.comparable_groups != comparable:
        errors.append("comparable_groups does not match comparison_groups")
    if report.disagreement_groups != disagreements:
        errors.append("disagreement_groups does not match comparison_groups")
    if report.cross_run_disagreement_rate != _ratio(disagreements, comparable):
        errors.append("cross_run_disagreement_rate does not match comparison_groups")

    for swarm_run in report.local_swarm_runs:
        _validate_quality_row_scope(
            swarm_run.manifest_schema_version,
            swarm_run.artifact_validation,
            swarm_run.origin_authentication,
            swarm_run.run_dir,
            errors,
        )
        if swarm_run.role_transcript_hash_coverage != _ratio(
            swarm_run.role_transcript_hashes, swarm_run.role_transcripts
        ):
            errors.append(
                f"{swarm_run.run_dir}: role transcript hash coverage mismatch"
            )
        if swarm_run.adapter_error_rate != _ratio(
            swarm_run.adapter_errors, swarm_run.role_transcripts
        ):
            errors.append(f"{swarm_run.run_dir}: adapter error rate mismatch")
        if (
            swarm_run.scenarios != len(swarm_run.scenario_ids)
            or swarm_run.modes != len(swarm_run.mode_ids)
            or len(swarm_run.scenario_ids) != len(set(swarm_run.scenario_ids))
            or len(swarm_run.mode_ids) != len(set(swarm_run.mode_ids))
            or swarm_run.runtime_mode_ids
            != sorted(set(swarm_run.runtime_mode_ids))
            or not set(swarm_run.runtime_mode_ids).issubset(swarm_run.mode_ids)
            or swarm_run.results != swarm_run.scenarios * swarm_run.modes
        ):
            errors.append(f"{swarm_run.run_dir}: scenario/mode projection mismatch")
        expected_runtime_coverage = _ratio(
            len(swarm_run.runtime_mode_ids), len(swarm_run.mode_ids)
        )
        if swarm_run.runtime_mode_coverage_rate != expected_runtime_coverage:
            errors.append(f"{swarm_run.run_dir}: runtime mode coverage mismatch")
        if any(
            value < 0
            for value in (
                swarm_run.request_count,
                swarm_run.max_requests,
                swarm_run.results,
                swarm_run.role_transcripts,
                swarm_run.role_transcript_hashes,
                swarm_run.adapter_errors,
            )
        ) or not (
            swarm_run.role_transcript_hashes <= swarm_run.role_transcripts
            and swarm_run.adapter_errors <= swarm_run.role_transcripts
        ):
            errors.append(f"{swarm_run.run_dir}: local-swarm counts are impossible")
        if not swarm_run.executed_model_calls and (
            swarm_run.request_count != 0
            or swarm_run.runtime_mode_coverage_rate != 0.0
            or swarm_run.evidence_maturity != "deterministic_example"
        ):
            errors.append(
                f"{swarm_run.run_dir}: deterministic maturity/runtime fields mismatch"
            )
        if (
            swarm_run.executed_model_calls
            and swarm_run.request_count > swarm_run.max_requests
        ):
            errors.append(f"{swarm_run.run_dir}: request_count exceeds max_requests")
        if swarm_run.executed_model_calls:
            if swarm_run.request_count != swarm_run.role_transcripts:
                errors.append(f"{swarm_run.run_dir}: request/transcript count mismatch")
            if expected_runtime_coverage >= 1.0 and len(swarm_run.mode_ids) >= 3:
                expected_maturity = "full_runtime_comparison"
            elif "bounded_swarm" in swarm_run.mode_ids and expected_runtime_coverage > 0:
                expected_maturity = "bounded_runtime_smoke"
            else:
                expected_maturity = "incomplete_runtime_evidence"
            if swarm_run.evidence_maturity != expected_maturity:
                errors.append(f"{swarm_run.run_dir}: evidence maturity mismatch")

    local_results = sum(run.results for run in report.local_swarm_runs)
    local_scenarios = sum(run.scenarios for run in report.local_swarm_runs)
    local_transcripts = sum(run.role_transcripts for run in report.local_swarm_runs)
    local_modes = sum(run.modes for run in report.local_swarm_runs)
    local_checks = (
        ("local_swarm_runs_count", report.local_swarm_runs_count,
         len(report.local_swarm_runs)),
        ("local_swarm_results", report.local_swarm_results, local_results),
        ("local_swarm_executed_runs", report.local_swarm_executed_runs,
         sum(1 for run in report.local_swarm_runs if run.executed_model_calls)),
        ("local_swarm_contract_coverage_rate", report.local_swarm_contract_coverage_rate,
         _weighted_rate(((run.contract_coverage, run.scenarios)
                         for run in report.local_swarm_runs), local_scenarios)),
        ("local_swarm_evidence_completeness_rate",
         report.local_swarm_evidence_completeness_rate,
         _weighted_rate(((run.evidence_completeness, run.results)
                         for run in report.local_swarm_runs), local_results)),
        ("local_swarm_transcript_hash_coverage_rate",
         report.local_swarm_transcript_hash_coverage_rate,
         _ratio(sum(run.role_transcript_hashes for run in report.local_swarm_runs),
                local_transcripts)),
        ("local_swarm_adapter_error_rate", report.local_swarm_adapter_error_rate,
         _ratio(sum(run.adapter_errors for run in report.local_swarm_runs),
                local_transcripts)),
        ("local_swarm_runtime_mode_coverage_rate",
         report.local_swarm_runtime_mode_coverage_rate,
         _weighted_rate(((run.runtime_mode_coverage_rate, run.modes)
                         for run in report.local_swarm_runs), local_modes)),
    )
    for field, actual, expected in local_checks:
        if actual != expected:
            errors.append(f"{field} does not match local_swarm_runs")
    return errors


def _validate_quality_row_scope(
    manifest_schema_version: str,
    artifact_validation: str,
    origin_authentication: str,
    label: str,
    errors: list[str],
) -> None:
    version_error = check_schema_version("run_manifest", manifest_schema_version)
    if version_error:
        errors.append(f"{label}: {version_error}")
    expected_scope = (
        "current_content_bound"
        if manifest_schema_version == SCHEMA_VERSIONS["run_manifest"]
        else "legacy_structural"
    )
    if artifact_validation != expected_scope:
        errors.append(f"{label}: artifact_validation does not match manifest schema")
    if origin_authentication != "unsigned":
        errors.append(f"{label}: origin_authentication must be unsigned")


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
