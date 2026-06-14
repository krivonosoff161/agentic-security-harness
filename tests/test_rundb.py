"""Tests for the lightweight SQLite run index (metadata only)."""

import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.rundb import index_runs, list_db_runs


def _two_runs(root: Path) -> None:
    cli.main(["run", "--target", "mock", "--out", str(root / "r1")])
    cli.main(["run", "--target", "demo-agent", "--out", str(root / "r2")])


def test_index_and_list(tmp_path: Path) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    n = index_runs(tmp_path, db)
    assert n == 2
    rows = list_db_runs(db)
    assert len(rows) == 2
    kinds = {r["run_kind"] for r in rows}
    assert kinds == {"run"}
    for r in rows:
        assert isinstance(r["outcomes"], dict)
        assert "passed" in r["outcomes"]


def test_index_is_idempotent(tmp_path: Path) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    index_runs(tmp_path, db)
    index_runs(tmp_path, db)  # re-index
    assert len(list_db_runs(db)) == 2  # no duplicates


def test_list_missing_db_empty(tmp_path: Path) -> None:
    assert list_db_runs(tmp_path / "nope.db") == []


def test_db_metadata_only_no_secrets(tmp_path: Path) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    index_runs(tmp_path, db)
    blob = json.dumps(list_db_runs(db))
    assert "sk-" not in blob and "AKIA" not in blob
    # No trace bodies are stored - only manifest metadata fields.
    row = list_db_runs(db)[0]
    assert set(row) == {
        "run_id", "run_kind", "created_at", "tool_version", "target",
        "model", "scenario", "outcomes", "manifest_path",
    }


def test_cli_index_and_list_db(tmp_path: Path) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    assert cli.main(["index-runs", "--root", str(tmp_path), "--db", str(db)]) == 0
    assert cli.main(["list-runs", "--db", str(db)]) == 0


def test_cli_index_missing_root(tmp_path: Path) -> None:
    rc = cli.main(["index-runs", "--root", str(tmp_path / "nope"),
                   "--db", str(tmp_path / "runs.db")])
    assert rc == 1
