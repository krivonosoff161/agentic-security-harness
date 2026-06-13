"""Tests for the variant matrix foundation."""

from pathlib import Path

from agentic_security_harness.adapters import make_target
from agentic_security_harness.matrix import (
    MatrixReport,
    VariantKnobs,
    _select_patterns,
    load_matrix_report,
    run_matrix,
)


def test_select_patterns_data_boundary() -> None:
    patterns = _select_patterns("data-boundary")
    ids = [p.pattern_id for p in patterns]
    assert "data_boundary_recipient_confusion" in ids
    assert "data_boundary_classification_mutation" in ids
    assert "data_boundary_handoff_label_stripping" in ids
    assert "provider_boundary_leakage_sanitized" in ids
    assert len(patterns) == 4


def test_select_patterns_all() -> None:
    patterns = _select_patterns("all")
    assert len(patterns) == 22


def test_run_matrix_mock_data_boundary(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(target, "data-boundary", tmp_path / "matrix", target_id="mock")
    assert report.total_traces == 4
    assert report.total_failed == 4
    assert report.total_passed == 0
    assert report.scenario_id == "data-boundary"
    assert report.target_id == "mock"
    assert report.target_name == "demo-mock-agent"
    assert len(report.variants) == 1
    assert len(report.variants[0].trace_ids) == 4


def test_run_matrix_protected_data_boundary(tmp_path: Path) -> None:
    target = make_target("protected-demo-agent")
    report = run_matrix(
        target, "data-boundary", tmp_path / "matrix",
        target_id="protected-demo-agent",
    )
    assert report.total_traces == 4
    assert report.total_failed == 0
    assert report.total_passed == 4


def test_run_matrix_writes_expected_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "matrix"
    target = make_target("mock")
    run_matrix(target, "data-boundary", out, target_id="mock")
    for name in (
        "traces.json",
        "scorecard.json",
        "summary.md",
        "executive.md",
        "matrix.json",
        "matrix.md",
        "remediation.json",
        "remediation.md",
    ):
        assert (out / name).exists(), f"missing {name}"


def test_matrix_json_is_loadable(tmp_path: Path) -> None:
    out = tmp_path / "matrix"
    target = make_target("mock")
    run_matrix(target, "data-boundary", out, target_id="mock")
    report = load_matrix_report(out / "matrix.json")
    assert report.scenario_id == "data-boundary"
    assert report.total_traces == 4


def test_run_matrix_deterministic(tmp_path: Path) -> None:
    target = make_target("mock")
    r1 = run_matrix(target, "data-boundary", tmp_path / "m1", target_id="mock")
    r2 = run_matrix(target, "data-boundary", tmp_path / "m2", target_id="mock")
    assert r1.total_traces == r2.total_traces
    assert r1.total_failed == r2.total_failed
    assert r1.variants[0].trace_ids == r2.variants[0].trace_ids


def test_variant_knobs_defaults() -> None:
    knobs = VariantKnobs()
    assert knobs.scope == "single-step"
    assert knobs.memory_mode == "off"
    assert knobs.tool_mode == "none"


def test_run_matrix_all_mock(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(target, "all", tmp_path / "matrix", target_id="mock")
    assert report.total_traces == 22
    assert report.total_failed == 22
    assert report.total_passed == 0


def test_run_matrix_all_protected(tmp_path: Path) -> None:
    target = make_target("protected-demo-agent")
    report = run_matrix(
        target, "all", tmp_path / "matrix",
        target_id="protected-demo-agent",
    )
    assert report.total_traces == 22
    assert report.total_failed == 0
    assert report.total_passed == 22


def test_matrix_report_schema_version() -> None:
    report = MatrixReport(
        target_id="mock",
        target_name="demo-mock-agent",
        scenario_id="data-boundary",
        scenario_title="Data boundary failures",
    )
    assert report.schema_version == "0.1"
    assert report.generated_by == "agentic-security-harness"
