"""Tests for the variant matrix and aggregation."""

from pathlib import Path

from agentic_security_harness.adapters import make_target
from agentic_security_harness.matrix import (
    _variant_trace_id,
    load_matrix_report,
    run_matrix,
)
from agentic_security_harness.scenarios import get_variants


def test_variant_trace_id_deterministic() -> None:
    a = _variant_trace_id("pattern_x", "target_a", "var_1")
    b = _variant_trace_id("pattern_x", "target_a", "var_1")
    assert a == b
    assert a.startswith("trc_")


def test_variant_trace_id_unique_per_variant() -> None:
    a = _variant_trace_id("pattern_x", "target_a", "var_1")
    b = _variant_trace_id("pattern_x", "target_a", "var_2")
    assert a != b


def test_variant_trace_id_unique_per_pattern() -> None:
    a = _variant_trace_id("pattern_x", "target_a", "var_1")
    b = _variant_trace_id("pattern_y", "target_a", "var_1")
    assert a != b


def test_get_variants_default_cap() -> None:
    variants = get_variants("all")
    assert len(variants) == 4


def test_get_variants_max_clamped() -> None:
    variants = get_variants("all", max_variants=2)
    assert len(variants) == 2


def test_get_variants_single_by_id() -> None:
    variants = get_variants("all", only_variant_id="baseline-all")
    assert len(variants) == 1
    assert variants[0].variant_id == "baseline-all"


def test_get_variants_unknown_id_raises() -> None:
    import pytest

    with pytest.raises(KeyError, match="unknown variant"):
        get_variants("all", only_variant_id="nonexistent")


def test_run_matrix_data_boundary_multi_variant(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(
        target, "data-boundary", tmp_path / "m",
        target_id="mock",
    )
    assert report.scenario_id == "data-boundary"
    assert report.target_id == "mock"
    assert len(report.variants) == 3
    assert report.summary.total_variants == 3
    assert report.summary.failed_variants == 3
    assert report.summary.passed_variants == 0
    # Each variant has 5 traces
    for v in report.variants:
        assert v.total_traces == 5
        assert len(v.trace_ids) == 5
    # Total traces = 3 variants x 5 patterns = 15
    assert report.total_traces == 15


def test_run_matrix_protected_all_zero_findings(tmp_path: Path) -> None:
    target = make_target("protected-demo-agent")
    report = run_matrix(
        target, "all", tmp_path / "m",
        target_id="protected-demo-agent",
        max_variants=4,
    )
    assert report.summary.total_variants == 4
    assert report.summary.failed_variants == 0
    assert report.summary.passed_variants == 4
    assert report.summary.total_traces == 23 * 4
    for v in report.variants:
        assert len(v.failed_patterns) == 0


def test_run_matrix_single_variant(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(
        target, "data-boundary", tmp_path / "m",
        target_id="mock",
        only_variant_id="base-envelope",
    )
    assert len(report.variants) == 1
    assert report.variants[0].variant_id == "base-envelope"
    assert report.total_traces == 5


def test_run_matrix_writes_all_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "m"
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


def test_matrix_json_loadable(tmp_path: Path) -> None:
    out = tmp_path / "m"
    target = make_target("mock")
    run_matrix(target, "data-boundary", out, target_id="mock")
    report = load_matrix_report(out / "matrix.json")
    assert report.schema_version == "0.2"
    assert len(report.variants) == 3
    assert report.summary.total_variants == 3


def test_run_matrix_deterministic(tmp_path: Path) -> None:
    target = make_target("mock")
    r1 = run_matrix(target, "data-boundary", tmp_path / "m1", target_id="mock")
    r2 = run_matrix(target, "data-boundary", tmp_path / "m2", target_id="mock")
    assert r1.total_traces == r2.total_traces
    assert r1.summary.total_variants == r2.summary.total_variants
    for v1, v2 in zip(r1.variants, r2.variants, strict=True):
        assert v1.trace_ids == v2.trace_ids


def test_run_matrix_all_mock(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(target, "all", tmp_path / "m", target_id="mock")
    assert report.total_traces == 23 * 4  # 4 variants, 23 patterns each
    assert report.summary.failed_variants == 4


def test_run_matrix_all_protected(tmp_path: Path) -> None:
    target = make_target("protected-demo-agent")
    report = run_matrix(
        target, "all", tmp_path / "m",
        target_id="protected-demo-agent",
    )
    assert report.total_traces == 23 * 4
    assert report.summary.failed_variants == 0
    assert report.summary.passed_variants == 4


def test_summary_stable_failures_all_mock(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(
        target, "data-boundary", tmp_path / "m", target_id="mock",
    )
    # All 5 data-boundary patterns fail in all 3 variants
    assert len(report.summary.stable_failures) == 5
    assert len(report.summary.variant_sensitive_failures) == 0


def test_summary_control_families_populated(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(
        target, "data-boundary", tmp_path / "m", target_id="mock",
    )
    assert "data_boundary" in report.summary.findings_by_control_family
    assert "provider_boundary" in report.summary.findings_by_control_family


def test_variant_result_has_knobs(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(
        target, "data-boundary", tmp_path / "m", target_id="mock",
    )
    for v in report.variants:
        assert isinstance(v.knobs, dict)
        assert len(v.knobs) > 0
        assert v.title


def test_matrix_markdown_states_variant_scope(tmp_path: Path) -> None:
    target = make_target("mock")
    report = run_matrix(
        target, "data-boundary", tmp_path / "m", target_id="mock",
    )
    text = (tmp_path / "m" / "matrix.md").read_text(encoding="utf-8")

    assert report.summary.total_variants == 3
    assert "Variant knobs in this release are deterministic replay metadata" in text
    assert "do not mutate the underlying pattern content yet" in text
