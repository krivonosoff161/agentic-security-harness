"""Deterministic example regeneration and comparison helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.adapters import make_target
from agentic_security_harness.local_swarm import (
    run_local_swarm,
    write_local_swarm_artifacts,
)
from agentic_security_harness.local_swarm_ablation import (
    build_local_swarm_ablation_matrix,
    write_local_swarm_ablation_artifacts,
)
from agentic_security_harness.local_swarm_allowed import (
    build_allowed_flow_suite,
    write_allowed_flow_artifacts,
)
from agentic_security_harness.local_swarm_matrix import (
    build_local_swarm_attack_matrix,
    write_local_swarm_matrix_artifacts,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import write_comparison
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS
from agentic_security_harness.scorecard import build_scorecard
from agentic_security_harness.validation import validate_path

ExampleId = Literal[
    "comparison-report",
    "local-swarm-report",
    "local-swarm-attack-matrix",
    "local-swarm-allowed-flows",
    "local-swarm-ablation-matrix",
]

EXAMPLE_IDS: tuple[ExampleId, ...] = (
    "comparison-report",
    "local-swarm-report",
    "local-swarm-attack-matrix",
    "local-swarm-allowed-flows",
    "local-swarm-ablation-matrix",
)


class ExampleReproResult(BaseModel):
    """Stable comparison result for one regenerated example."""

    model_config = ConfigDict(extra="forbid")

    example_id: ExampleId
    generated_path: str
    committed_path: str
    validation_ok: bool
    metrics_match: bool
    committed_metrics: dict[str, int | float | str | bool] = Field(default_factory=dict)
    generated_metrics: dict[str, int | float | str | bool] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class ReproducibilityReport(BaseModel):
    """Machine-readable reproducibility report."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["reproducibility_report"]
    run_kind: Literal["reproducibility_report"] = "reproducibility_report"
    examples: int
    validation_failures: int
    metric_mismatches: int
    ok: bool
    results: list[ExampleReproResult]


def rebuild_and_compare_examples(
    *,
    out_dir: Path,
    examples_root: Path = Path("examples"),
) -> ReproducibilityReport:
    """Regenerate deterministic examples and compare stable metrics to committed ones."""

    generated_root = out_dir / "generated"
    generated_root.mkdir(parents=True, exist_ok=True)

    results: list[ExampleReproResult] = []
    for example_id in EXAMPLE_IDS:
        generated = generated_root / example_id
        committed = examples_root / example_id
        _regenerate(example_id, generated)
        validation = validate_path(generated)
        committed_metrics = _stable_metrics(example_id, committed)
        generated_metrics = _stable_metrics(example_id, generated)
        errors = [*validation.errors]
        if not committed.exists():
            errors.append(f"missing committed example: {committed.as_posix()}")
        results.append(
            ExampleReproResult(
                example_id=example_id,
                generated_path=generated.as_posix(),
                committed_path=committed.as_posix(),
                validation_ok=validation.ok,
                metrics_match=committed_metrics == generated_metrics,
                committed_metrics=committed_metrics,
                generated_metrics=generated_metrics,
                errors=errors,
            )
        )

    report = ReproducibilityReport(
        examples=len(results),
        validation_failures=sum(1 for item in results if not item.validation_ok),
        metric_mismatches=sum(1 for item in results if not item.metrics_match),
        ok=all(item.validation_ok and item.metrics_match for item in results),
        results=results,
    )
    write_text_artifact(
        out_dir / "reproducibility_report.json",
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
    )
    write_text_artifact(out_dir / "reproducibility_report.md", render_report(report))
    return report


def render_report(report: ReproducibilityReport) -> str:
    """Render reproducibility results as Markdown."""

    lines = [
        "# Reproducibility Report",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Examples | {report.examples} |",
        f"| Validation failures | {report.validation_failures} |",
        f"| Metric mismatches | {report.metric_mismatches} |",
        f"| Overall OK | {report.ok} |",
        "",
        "## Examples",
        "",
        "| Example | Validation OK | Metrics match | Generated |",
        "| --- | ---: | ---: | --- |",
    ]
    for item in report.results:
        lines.append(
            f"| `{item.example_id}` | {item.validation_ok} | {item.metrics_match} | "
            f"`{item.generated_path}` |"
        )
    lines.extend(
        [
            "",
            "Stable metrics are compared instead of timestamps, run ids, or formatting-only "
            "fields. JSON artifacts remain the source of truth.",
            "",
        ]
    )
    return "\n".join(lines)


def _regenerate(example_id: ExampleId, out_dir: Path) -> None:
    if example_id == "comparison-report":
        _regenerate_comparison(out_dir)
        return
    if example_id == "local-swarm-report":
        write_local_swarm_artifacts(out_dir, run_local_swarm(created_at=""))
        return
    if example_id == "local-swarm-attack-matrix":
        write_local_swarm_matrix_artifacts(out_dir, build_local_swarm_attack_matrix())
        return
    if example_id == "local-swarm-allowed-flows":
        write_allowed_flow_artifacts(out_dir, build_allowed_flow_suite(created_at=""))
        return
    if example_id == "local-swarm-ablation-matrix":
        write_local_swarm_ablation_artifacts(
            out_dir,
            build_local_swarm_ablation_matrix(created_at=""),
        )
        return
    raise AssertionError(f"unknown example id: {example_id}")


def _regenerate_comparison(out_dir: Path) -> None:
    patterns = seed_patterns()
    baseline_traces = HarnessRunner(make_target("demo-agent")).run_many(patterns)
    baseline_card = build_scorecard(baseline_traces)
    protected_traces = HarnessRunner(make_target("protected-demo-agent")).run_many(patterns)
    protected_card = build_scorecard(protected_traces)
    write_comparison(
        out_dir,
        baseline_traces,
        baseline_card,
        protected_traces,
        protected_card,
    )


def _stable_metrics(
    example_id: ExampleId,
    path: Path,
) -> dict[str, int | float | str | bool]:
    if not path.exists():
        return {}
    if example_id == "comparison-report":
        baseline = _load_json(path / "baseline" / "scorecard.json")
        protected = _load_json(path / "protected" / "scorecard.json")
        return {
            "baseline_failed": int(baseline.get("failed", 0)),
            "baseline_passed": int(baseline.get("passed", 0)),
            "protected_failed": int(protected.get("failed", 0)),
            "protected_passed": int(protected.get("passed", 0)),
        }
    if example_id == "local-swarm-report":
        metrics = _load_json(path / "local_swarm_summary.json").get("metrics", {})
        return {
            "scenarios": int(metrics.get("scenarios", 0)),
            "naive_failures": int(metrics.get("naive_swarm_boundary_failures", 0)),
            "bounded_failures": int(metrics.get("bounded_swarm_boundary_failures", 0)),
            "verifier_blocks": int(metrics.get("verifier_blocks", 0)),
        }
    if example_id == "local-swarm-attack-matrix":
        metrics = _load_json(path / "local_swarm_attack_matrix.json").get("metrics", {})
        return {
            "cases": int(metrics.get("cases", 0)),
            "families": int(metrics.get("variation_families", 0)),
            "bounded_failures": int(metrics.get("bounded_swarm_boundary_failures", 0)),
            "bounded_blocks": int(metrics.get("bounded_blocks", 0)),
        }
    if example_id == "local-swarm-allowed-flows":
        metrics = _load_json(path / "local_swarm_allowed_flows.json").get("metrics", {})
        return {
            "flows": int(metrics.get("flows", 0)),
            "allowed_passes": int(metrics.get("allowed_passes", 0)),
            "unexpected_blocks": int(metrics.get("unexpected_blocks", 0)),
        }
    if example_id == "local-swarm-ablation-matrix":
        metrics = _load_json(path / "local_swarm_ablation_matrix.json").get("metrics", {})
        return {
            "scenarios": int(metrics.get("scenarios", 0)),
            "controls": int(metrics.get("controls", 0)),
            "bounded_blocks": int(metrics.get("bounded_blocks", 0)),
            "vulnerable_when_primary_removed": int(
                metrics.get("vulnerable_when_primary_removed", 0)
            ),
        }
    raise AssertionError(f"unknown example id: {example_id}")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
