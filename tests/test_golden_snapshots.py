"""Golden snapshot tests for deterministic public artifacts.

These tests intentionally compare selected generated artifacts byte-for-byte. If report
shape, trace content, or scorecard semantics change, update the implementation first,
then regenerate these fixtures in the same review.
"""

from pathlib import Path

from agentic_security_harness import cli

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden"


def _assert_same_file(actual: Path, expected: Path) -> None:
    assert actual.read_text(encoding="utf-8") == expected.read_text(encoding="utf-8")


def test_golden_demo_run_snapshot(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    assert cli.main(["run", "--target", "mock", "--out", str(out)]) == 0

    for name in (
        "traces.json",
        "scorecard.json",
        "summary.md",
        "executive.md",
        "remediation.json",
        "remediation.md",
    ):
        _assert_same_file(out / name, GOLDEN / "demo-run" / name)


def test_golden_comparison_snapshot(tmp_path: Path) -> None:
    out = tmp_path / "comparison"
    assert cli.main([
        "compare",
        "--baseline",
        "demo-agent",
        "--protected",
        "protected-demo-agent",
        "--out",
        str(out),
    ]) == 0

    _assert_same_file(
        out / "comparison.md", GOLDEN / "comparison" / "comparison.md"
    )
    _assert_same_file(
        out / "baseline" / "scorecard.json",
        GOLDEN / "comparison" / "baseline" / "scorecard.json",
    )
    _assert_same_file(
        out / "protected" / "scorecard.json",
        GOLDEN / "comparison" / "protected" / "scorecard.json",
    )
