"""Tests for run stats, retention planning, and model comparisons."""

import shutil
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.run_manifest import build_manifest, write_run_manifest
from agentic_security_harness.stats import (
    apply_retention_plan,
    build_retention_plan,
    build_run_stats,
    write_run_stats,
)
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _manifested_run(root: Path, name: str, created_at: str, target: str = "mock") -> Path:
    run_dir = root / name
    run_dir.mkdir(parents=True)
    (run_dir / "executive.md").write_text("x\n", encoding="utf-8")
    manifest = build_manifest(
        "run",
        run_dir,
        target=target,
        scenario="seed-corpus",
        outcomes={"failed": 1, "passed": 2},
        artifacts=["executive.md"],
        created_at=created_at,
    )
    write_run_manifest(run_dir, manifest)
    return run_dir


def test_build_and_write_run_stats(tmp_path: Path) -> None:
    _manifested_run(tmp_path, "a", "2026-06-14T00:00:00Z")
    _manifested_run(tmp_path, "b", "2026-06-15T00:00:00Z", target="demo-agent")

    stats = build_run_stats(tmp_path)
    assert stats.total_runs == 2
    assert stats.by_kind == {"run": 2}
    assert stats.by_scenario == {"seed-corpus": 2}
    assert stats.outcome_totals == {"failed": 2, "passed": 4}

    paths = write_run_stats(stats, tmp_path / "stats")
    assert paths["run_stats_json"].exists()
    assert paths["run_stats_md"].exists()


def test_retention_plan_and_apply(tmp_path: Path) -> None:
    oldest = _manifested_run(tmp_path, "oldest", "2026-06-13T00:00:00Z")
    middle = _manifested_run(tmp_path, "middle", "2026-06-14T00:00:00Z")
    newest = _manifested_run(tmp_path, "newest", "2026-06-15T00:00:00Z")

    plan = build_retention_plan(tmp_path, keep_last=1, kinds=["run"])

    assert [Path(c.run_dir).name for c in plan.candidates] == ["oldest", "middle"]
    assert oldest.exists() and middle.exists() and newest.exists()

    applied = apply_retention_plan(plan)
    assert applied.applied is True
    assert applied.removed == 2
    assert not oldest.exists()
    assert not middle.exists()
    assert newest.exists()


def test_cli_stats_and_retention_dry_run(tmp_path: Path) -> None:
    run_dir = _manifested_run(tmp_path, "run1", "2026-06-15T00:00:00Z")
    assert cli.main(["stats", "--root", str(tmp_path), "--out", str(tmp_path / "stats")]) == 0
    assert (tmp_path / "stats" / "run_stats.json").exists()

    assert cli.main(["retention", "--root", str(tmp_path), "--keep-last", "1"]) == 0
    assert run_dir.exists()


def test_cli_retention_rejects_bad_kind(tmp_path: Path) -> None:
    assert cli.main(["retention", "--root", str(tmp_path), "--kind", "bogus"]) == 1


def test_cli_compare_models_writes_external_diff(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    shutil.copytree(EXAMPLES / "external-demo-report", left)
    shutil.copytree(EXAMPLES / "external-demo-report", right)

    out = tmp_path / "model-diff"
    assert cli.main(["compare-models", "--left", str(left), "--right", str(right),
                     "--out", str(out)]) == 0
    assert (out / "run_diff.json").exists()
    result = validate_path(out)
    assert result.ok, result.errors


def test_cli_compare_models_rejects_non_external(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    assert cli.main(["compare-models", "--left", str(run_dir), "--right", str(run_dir),
                     "--out", str(tmp_path / "out")]) == 1
