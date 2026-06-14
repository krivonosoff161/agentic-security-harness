"""Tests for `ash diff-runs` and the run_diff artifacts."""

import json
import shutil
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.run_diff import diff_runs, write_run_diff
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _run(target: str, out: Path) -> Path:
    cli.main(["run", "--target", target, "--out", str(out)])
    return out


def test_diff_run_fixed(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.kind == "run"
    assert diff.fixed == 22
    assert diff.new == 0 and diff.changed == 0
    assert all(e.change == "fixed" for e in diff.entries)


def test_diff_run_unchanged(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("mock", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.unchanged == 22
    assert diff.fixed == 0 and diff.new == 0


def test_diff_run_new_findings(tmp_path: Path) -> None:
    # protected (all pass) -> demo-agent (all finding): every pattern is "new".
    a = _run("protected-demo-agent", tmp_path / "a")
    b = _run("demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    assert diff.new == 22


def test_diff_incompatible_kinds(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    with pytest.raises(ValueError, match="same kind"):
        diff_runs(a, EXAMPLES / "external-demo-report")


def test_diff_external_unchanged(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    shutil.copytree(EXAMPLES / "external-demo-report", left)
    shutil.copytree(EXAMPLES / "external-demo-report", right)
    diff = diff_runs(left, right)
    assert diff.kind == "external"
    assert diff.new == 0 and diff.fixed == 0
    assert diff.unchanged == len(diff.entries) > 0


def test_diff_matrix(tmp_path: Path) -> None:
    a = tmp_path / "ma"
    b = tmp_path / "mb"
    cli.main(["run-matrix", "--target", "demo-agent", "--scenario", "data-boundary",
              "--max-variants", "3", "--out", str(a)])
    cli.main(["run-matrix", "--target", "protected-demo-agent", "--scenario",
              "data-boundary", "--max-variants", "3", "--out", str(b)])
    diff = diff_runs(a, b)
    assert diff.kind == "matrix"
    # demo-agent fails data-boundary in every variant; protected passes -> fixed.
    assert diff.fixed > 0


def test_write_and_validate_diff(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    diff = diff_runs(a, b)
    out = tmp_path / "diff"
    paths = write_run_diff(diff, out)
    assert paths["run_diff_json"].exists() and paths["run_diff_md"].exists()
    result = validate_path(out)
    assert result.ok, result.errors
    assert result.run_diff_dirs == ["diff"]


def test_validate_diff_bad_counts(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    write_run_diff(diff_runs(a, b), tmp_path / "diff")
    data = json.loads((tmp_path / "diff" / "run_diff.json").read_text(encoding="utf-8"))
    data["fixed"] = 999  # tamper
    (tmp_path / "diff" / "run_diff.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(tmp_path / "diff")
    assert not result.ok
    assert any("change counts" in e for e in result.errors)


def test_cli_diff_runs_success(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    b = _run("protected-demo-agent", tmp_path / "b")
    rc = cli.main(["diff-runs", "--left", str(a), "--right", str(b),
                   "--out", str(tmp_path / "diff")])
    assert rc == 0
    assert (tmp_path / "diff" / "run_diff.json").exists()


def test_cli_diff_runs_missing_dir(tmp_path: Path) -> None:
    a = _run("mock", tmp_path / "a")
    rc = cli.main(["diff-runs", "--left", str(a), "--right",
                   str(tmp_path / "nope"), "--out", str(tmp_path / "diff")])
    assert rc == 1
