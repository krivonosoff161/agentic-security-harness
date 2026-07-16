"""Tests for the lightweight SQLite run index (metadata only)."""

import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.run_manifest import load_validated_run_records
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
    execution_ids = [str(row["execution_id"]) for row in rows]
    assert execution_ids == sorted(execution_ids)
    kinds = {r["run_kind"] for r in rows}
    assert kinds == {"run"}
    for r in rows:
        assert isinstance(r["outcomes"], dict)
        assert "passed" in r["outcomes"]
        assert r["expectation_status"] == "ok"
        assert r["expectation_mismatch_count"] == 0
        assert r["validation_scope"] == "independently_recomputed_at_index"


def test_index_is_idempotent(tmp_path: Path) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    index_runs(tmp_path, db)
    index_runs(tmp_path, db)  # re-index
    assert len(list_db_runs(db)) == 2  # no duplicates


def test_reindex_updates_validation_observation_not_execution_identity(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "r1"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    db = tmp_path / "runs.db"
    index_runs(tmp_path, db)
    with sqlite3.connect(db) as connection:
        execution_before = connection.execute(
            "SELECT * FROM run_executions"
        ).fetchone()
    record = load_validated_run_records(run_dir)[0]
    adverse = replace(record, expectations_ok=False, expectation_mismatch_count=3)

    with patch(
        "agentic_security_harness.rundb.load_validated_run_records",
        return_value=[adverse],
    ):
        assert index_runs(tmp_path, db) == 1

    with sqlite3.connect(db) as connection:
        execution_after = connection.execute(
            "SELECT * FROM run_executions"
        ).fetchone()
    assert execution_after == execution_before
    row = list_db_runs(db)[0]
    assert row["expectation_status"] == "mismatch"
    assert row["expectation_mismatch_count"] == 3


def test_index_preserves_two_executions_of_same_configuration(tmp_path: Path) -> None:
    cli.main(["run", "--target", "mock", "--out", str(tmp_path / "r1")])
    cli.main(["run", "--target", "mock", "--out", str(tmp_path / "r2")])
    db = tmp_path / "runs.db"

    index_runs(tmp_path, db)
    rows = list_db_runs(db)

    assert len(rows) == 2
    assert len({row["execution_id"] for row in rows}) == 2
    assert len({row["config_fingerprint"] for row in rows}) == 1


def test_index_rejects_mutation_under_existing_execution_id(tmp_path: Path) -> None:
    run_dir = tmp_path / "r1"
    cli.main(["run", "--target", "mock", "--out", str(run_dir)])
    db = tmp_path / "runs.db"
    index_runs(tmp_path, db)
    manifest_path = run_dir / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # created_at remains explicitly informational and is not derivable from run evidence;
    # append-only indexing must still reject changing it under an existing execution id.
    manifest["created_at"] = "2099-01-01T00:00:00Z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="identity collision"):
        index_runs(tmp_path, db)


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
        "run_id", "execution_id", "config_fingerprint", "run_kind", "created_at",
        "tool_version", "target", "model", "scenario", "outcomes", "manifest_path",
        "expectation_status", "expectation_mismatch_count", "validation_manifest_sha256",
        "validation_scope", "validator_tool_version", "corpus_version",
        "validator_source_fingerprint",
    }


def test_legacy_db_lists_unknown_status_read_only_then_reindex_populates(
    tmp_path: Path,
) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, run_kind TEXT NOT NULL, "
            "created_at TEXT, tool_version TEXT, target TEXT, model TEXT, "
            "scenario TEXT, outcomes TEXT, manifest_path TEXT)"
        )
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "run_legacy",
                "run",
                "2025-01-01T00:00:00Z",
                "0.1.0",
                "legacy-target",
                "",
                "legacy-scenario",
                "{\"passed\": 1}",
                "legacy/path",
            ),
        )

    legacy_rows = list_db_runs(db)
    assert len(legacy_rows) == 1
    assert legacy_rows[0]["expectation_status"] == "not_recorded"
    assert legacy_rows[0]["target"] == "legacy-target"
    with sqlite3.connect(db) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert tables == {"runs"}

    index_runs(tmp_path, db)
    reindexed_rows = list_db_runs(db)
    assert len(reindexed_rows) == 3
    assert [
        row["expectation_status"] for row in reindexed_rows
    ].count("not_recorded") == 1
    current_rows = [
        row for row in reindexed_rows if row["expectation_status"] == "ok"
    ]
    assert len(current_rows) == 2
    assert all(row["validation_manifest_sha256"] for row in current_rows)
    assert all(len(str(row["validator_source_fingerprint"])) == 64 for row in current_rows)
    with sqlite3.connect(db) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)


def test_cli_index_and_list_db(tmp_path: Path) -> None:
    _two_runs(tmp_path)
    db = tmp_path / "runs.db"
    assert cli.main(["index-runs", "--root", str(tmp_path), "--db", str(db)]) == 0
    assert cli.main(["list-runs", "--db", str(db)]) == 0


def test_cli_index_missing_root(tmp_path: Path) -> None:
    rc = cli.main(["index-runs", "--root", str(tmp_path / "nope"),
                   "--db", str(tmp_path / "runs.db")])
    assert rc == 1


def test_index_ignores_parseable_manifest_without_valid_artifacts(tmp_path: Path) -> None:
    forged = tmp_path / "forged"
    forged.mkdir()
    (forged / "run_index.json").write_text(
        json.dumps({
            "schema_version": "0.3",
            "run_id": "run_" + ("f" * 32),
            "execution_id": "run_" + ("f" * 32),
            "config_fingerprint": "cfg_0000000000",
            "run_kind": "run",
            "artifacts": [],
            "artifact_sha256": {},
        }),
        encoding="utf-8",
    )

    db = tmp_path / "runs.db"
    assert index_runs(tmp_path, db) == 0
    assert list_db_runs(db) == []
