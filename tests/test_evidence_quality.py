import json
from pathlib import Path

import pytest

from agentic_security_harness.evidence_quality import (
    build_evidence_quality_report,
    discover_external_run_dirs,
    write_evidence_quality,
)
from agentic_security_harness.run_config import (
    ExternalResult,
    ExternalSummary,
    RepeatSummary,
    RunConfig,
)


def _write_external_run(
    root: Path,
    name: str,
    *,
    model: str,
    outcomes: list[str],
    stability_status: str,
    raw_hash: bool = True,
) -> Path:
    run = root / name
    run.mkdir(parents=True)
    config = RunConfig(
        model=model,
        scenario_id="data-boundary",
        request_count=len(outcomes),
        repeats=len(outcomes),
    )
    results: list[ExternalResult] = []
    for idx, outcome in enumerate(outcomes):
        is_error = outcome == "adapter_error"
        raw_path = f"raw_responses/r{idx}.txt" if not is_error else ""
        result = ExternalResult(
            result_id=f"r{idx}",
            pattern_id="data_boundary_recipient_confusion",
            variant_id="base-envelope",
            repeat_index=idx,
            error="timeout" if is_error else "",
            deterministic_cross_check=outcome,
            assertion_id="data_boundary_recipient_confusion:boundary_preservation",
            assertion_result=outcome if outcome in {"pass", "finding"} else outcome,
            raw_response_path=raw_path,
            raw_response_sha256="abc123" if raw_path and raw_hash else "",
            parse_error="no valid JSON response" if outcome == "inconclusive" else "",
        )
        results.append(result)
    summary = ExternalSummary(
        scenario_id="data-boundary",
        adapter_type="openai-compatible",
        model=model,
        total_checks=1,
        total_repeats=len(outcomes),
        repeat_summaries=[
            RepeatSummary(
                pattern_id="data_boundary_recipient_confusion",
                variant_id="base-envelope",
                total_repeats=len(outcomes),
                pass_count=outcomes.count("pass"),
                finding_count=outcomes.count("finding"),
                inconclusive_count=outcomes.count("inconclusive"),
                error_count=outcomes.count("adapter_error"),
                flaky=stability_status == "flaky",
                dominant_outcome=outcomes[0],
                stability_status=stability_status,
            )
        ],
    )
    (run / "run_config.json").write_text(
        json.dumps(config.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    (run / "external_results.json").write_text(
        json.dumps([r.model_dump(mode="json") for r in results], indent=2) + "\n",
        encoding="utf-8",
    )
    (run / "external_summary.json").write_text(
        json.dumps(summary.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    return run


def test_discover_external_run_dirs_finds_nested_runs(tmp_path: Path) -> None:
    run = _write_external_run(
        tmp_path / "reports",
        "a",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )

    assert discover_external_run_dirs(tmp_path / "reports") == [run]


def test_evidence_quality_report_counts_decisive_weak_and_raw_hash(
    tmp_path: Path,
) -> None:
    _write_external_run(
        tmp_path,
        "mixed",
        model="m1",
        outcomes=["pass", "finding", "inconclusive", "adapter_error"],
        stability_status="flaky",
    )

    report = build_evidence_quality_report(tmp_path)

    assert report.total_runs == 1
    assert report.total_results == 4
    assert report.outcome_counts == {
        "adapter_error": 1,
        "finding": 1,
        "inconclusive": 1,
        "invalid": 0,
        "pass": 1,
    }
    assert report.decisive_rate == 0.5
    assert report.weak_evidence_rate == 0.5
    assert report.raw_response_coverage_rate == 0.75
    assert report.raw_hash_coverage_rate == 0.75
    assert report.assertion_binding_rate == 1.0
    assert report.runs[0].flaky_groups == 1
    assert report.safety_note.startswith("Derived evidence-quality analysis only")


def test_cross_run_disagreement_is_counted_per_pattern_variant(tmp_path: Path) -> None:
    _write_external_run(
        tmp_path,
        "left",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    _write_external_run(
        tmp_path,
        "right",
        model="m2",
        outcomes=["finding"],
        stability_status="stable_finding",
    )

    report = build_evidence_quality_report(tmp_path)

    assert report.comparable_groups == 1
    assert report.disagreement_groups == 1
    assert report.cross_run_disagreement_rate == 1.0


def test_write_evidence_quality_outputs_json_and_markdown(tmp_path: Path) -> None:
    _write_external_run(
        tmp_path,
        "run",
        model="m1",
        outcomes=["pass"],
        stability_status="stable_pass",
    )
    report = build_evidence_quality_report(tmp_path)
    paths = write_evidence_quality(report, tmp_path / "out")

    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["schema_version"] == "0.1"
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "Derived analysis only" in md
    assert "Raw hash coverage" in md


def test_cli_evidence_quality_writes_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentic_security_harness import cli

    _write_external_run(
        tmp_path / "reports",
        "run",
        model="m1",
        outcomes=["pass", "inconclusive"],
        stability_status="inconclusive",
    )

    rc = cli.main([
        "evidence-quality",
        "--root",
        str(tmp_path / "reports"),
        "--out",
        str(tmp_path / "quality"),
    ])

    assert rc == 0
    assert (tmp_path / "quality" / "evidence_quality.json").is_file()
    assert (tmp_path / "quality" / "evidence_quality.md").is_file()
    out = capsys.readouterr().out
    assert "Derived analysis only" in out
    assert "weak_evidence_rate" in out
