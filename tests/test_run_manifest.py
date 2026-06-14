"""Tests for the run manifest layer (run_index.json), list-runs CLI, and validation."""

import json
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.run_manifest import (
    RunManifest,
    build_manifest,
    load_run_manifests,
    make_run_id,
    write_run_manifest,
)
from agentic_security_harness.validation import validate_path

# --- module-level model tests ---


def test_make_run_id_is_deterministic() -> None:
    a = make_run_id("run", "mock", "", "seed-corpus", [], 1)
    b = make_run_id("run", "mock", "", "seed-corpus", [], 1)
    assert a == b
    assert a.startswith("run_")


def test_make_run_id_varies_with_config() -> None:
    a = make_run_id("run", "mock", "", "seed-corpus", [], 1)
    b = make_run_id("run", "demo-agent", "", "seed-corpus", [], 1)
    assert a != b


def test_build_manifest_rejects_unknown_kind(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown run_kind"):
        build_manifest("not-a-kind", tmp_path)


def test_write_and_load_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "r1"
    run_dir.mkdir()
    (run_dir / "executive.md").write_text("x", encoding="utf-8")
    manifest = build_manifest(
        "run",
        run_dir,
        target="mock",
        scenario="seed-corpus",
        outcomes={"failed": 0, "passed": 22},
        artifacts=["executive.md"],
        tool_version="0.11.0",
        created_at="2026-06-14T00:00:00Z",
    )
    path = write_run_manifest(run_dir, manifest)
    assert path.name == "run_index.json"
    loaded = RunManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert loaded.run_id == manifest.run_id
    assert loaded.outcomes == {"failed": 0, "passed": 22}


def test_load_run_manifests_skips_malformed(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    write_run_manifest(good, build_manifest("run", good, target="mock"))
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "run_index.json").write_text("{ not json", encoding="utf-8")

    found = load_run_manifests(tmp_path)
    assert len(found) == 1
    assert found[0][1].target == "mock"


def test_load_run_manifests_missing_root(tmp_path: Path) -> None:
    assert load_run_manifests(tmp_path / "nope") == []


# --- CLI integration ---


def test_cli_run_writes_manifest(tmp_path: Path) -> None:
    rc = cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    assert rc == 0
    manifest_path = tmp_path / "run" / "run_index.json"
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["run_kind"] == "run"
    assert data["run_id"].startswith("run_")
    assert "passed" in data["outcomes"]
    assert "traces.json" in data["artifacts"]


def test_cli_list_runs_lists_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    capsys.readouterr()  # clear
    rc = cli.main(["list-runs", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Found 1 run(s)" in out
    assert "run_" in out
    assert "seed-corpus" in out


def test_cli_list_runs_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(["list-runs", "--root", str(tmp_path / "empty")])
    assert rc == 0
    assert "No runs found" in capsys.readouterr().out


# --- validation ---


def test_validate_accepts_manifest(tmp_path: Path) -> None:
    cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    result = validate_path(tmp_path / "run")
    assert result.ok, result.errors


def test_validate_rejects_missing_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    data = json.loads((run_dir / "run_index.json").read_text(encoding="utf-8"))
    data["artifacts"].append("does_not_exist.md")
    (run_dir / "run_index.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(run_dir)
    assert not result.ok
    assert any("does_not_exist.md" in e for e in result.errors)


def test_validate_rejects_bad_run_kind(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    data = json.loads((run_dir / "run_index.json").read_text(encoding="utf-8"))
    data["run_kind"] = "bogus"
    (run_dir / "run_index.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(run_dir)
    assert not result.ok
    assert any("run_kind" in e for e in result.errors)
