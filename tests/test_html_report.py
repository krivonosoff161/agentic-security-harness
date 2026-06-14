"""Tests for the static HTML report renderer and the `ash report` command."""

from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.html_report import detect_kind, render_report

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

_FORBIDDEN_RESOURCE_MARKERS = ["src=", "<link", "<script"]
_ABS_PATH_MARKERS = ["C:\\Users", "C:/Users", "/home/", "/Users/", "AppData"]


def _assert_self_contained(html: str) -> None:
    assert html.startswith("<!doctype html")
    # No external/loaded resources of any kind.
    for marker in _FORBIDDEN_RESOURCE_MARKERS:
        assert marker not in html, f"unexpected resource marker: {marker}"
    # href= may only appear if it were a link; we render none.
    assert "href=" not in html
    # No absolute local paths leaked into the view.
    for marker in _ABS_PATH_MARKERS:
        assert marker not in html, f"absolute path leak: {marker}"
    # Honest framing present.
    assert "does not prove" in html.lower()


@pytest.mark.parametrize(
    "name,kind",
    [
        ("demo-report", "run"),
        ("demo-agent-report", "run"),
        ("comparison-report", "compare"),
        ("external-demo-report", "external"),
    ],
)
def test_render_examples(name: str, kind: str) -> None:
    run_dir = EXAMPLES / name
    assert detect_kind(run_dir) == kind
    html = render_report(run_dir)
    _assert_self_contained(html)


def test_detect_kind_unknown(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no recognizable run artifacts"):
        detect_kind(tmp_path)


def test_run_report_has_pattern_table() -> None:
    html = render_report(EXAMPLES / "demo-agent-report")
    assert "Pattern results" in html
    assert "Severity distribution" in html
    assert "data_boundary_recipient_confusion" in html


def test_compare_report_shows_before_after() -> None:
    html = render_report(EXAMPLES / "comparison-report")
    assert "Findings reduced" in html
    assert "Baseline" in html and "Protected" in html


def test_external_report_localhost_only(tmp_path: Path) -> None:
    # The committed external example references a localhost endpoint in metadata text;
    # that is data, not a loaded resource, and must be the only http reference.
    html = render_report(EXAMPLES / "external-demo-report")
    import re

    urls = re.findall(r"https?://[^< \"]+", html)
    assert all(u.startswith("http://127.0.0.1") for u in urls), urls


def test_matrix_report_renders_heatmap(tmp_path: Path) -> None:
    out = tmp_path / "mx"
    rc = cli.main([
        "run-matrix", "--target", "demo-agent", "--scenario", "data-boundary",
        "--max-variants", "3", "--out", str(out),
    ])
    assert rc == 0
    html = render_report(out)
    _assert_self_contained(html)
    assert "Coverage heatmap" in html
    assert "Stability" in html
    assert "stable_fail" in html  # demo-agent fails data-boundary in every variant


def test_cli_report_writes_default_out(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    rc = cli.main(["report", "--root", str(run_dir)])
    assert rc == 0
    assert (run_dir / "report.html").exists()
    _assert_self_contained((run_dir / "report.html").read_text(encoding="utf-8"))


def test_cli_report_custom_out(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    out = tmp_path / "html" / "r.html"
    rc = cli.main(["report", "--root", str(run_dir), "--out", str(out)])
    assert rc == 0
    assert out.exists()


def test_cli_report_missing_dir(tmp_path: Path) -> None:
    rc = cli.main(["report", "--root", str(tmp_path / "nope")])
    assert rc == 1


def test_cli_report_empty_dir(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    rc = cli.main(["report", "--root", str(tmp_path / "empty")])
    assert rc == 1
