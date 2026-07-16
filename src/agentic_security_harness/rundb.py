"""Lightweight local SQLite index of run manifests (metadata only).

Stdlib ``sqlite3`` only - no dependency, no network, no trace bodies, no secrets. The
index stores just the manifest metadata (run id, kind, target/model labels, scenario,
outcome counts, and the manifest path relative to the scanned root) so a user can keep a
local history of runs and query it later. The JSON ``run_index.json`` files remain the
source of truth; this is a derived convenience index.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from agentic_security_harness.run_manifest import (
    load_validated_run_records,
    make_config_fingerprint,
)
from agentic_security_harness.schema_versions import CORPUS_VERSION
from agentic_security_harness.version import __version__

_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_executions (
    execution_id TEXT PRIMARY KEY,
    config_fingerprint TEXT NOT NULL,
    legacy_run_id TEXT,
    run_kind TEXT NOT NULL,
    created_at TEXT,
    tool_version TEXT,
    target TEXT,
    model TEXT,
    scenario TEXT,
    outcomes TEXT,
    manifest_path TEXT
);
"""

_VALIDATION_STATUS_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_validation_status (
    execution_id TEXT PRIMARY KEY,
    manifest_sha256 TEXT NOT NULL,
    expectation_status TEXT NOT NULL CHECK(expectation_status IN ('ok', 'mismatch')),
    expectation_mismatch_count INTEGER NOT NULL CHECK(expectation_mismatch_count >= 0),
    validation_scope TEXT NOT NULL
        CHECK(validation_scope = 'independently_recomputed_at_index'),
    validator_tool_version TEXT NOT NULL,
    corpus_version TEXT NOT NULL,
    validator_source_fingerprint TEXT NOT NULL,
    CHECK(
        (expectation_status = 'ok' AND expectation_mismatch_count = 0)
        OR (expectation_status = 'mismatch' AND expectation_mismatch_count >= 1)
    )
);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(_SCHEMA)
    conn.execute(_VALIDATION_STATUS_SCHEMA)
    status_columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(run_validation_status)").fetchall()
    }
    if "validator_source_fingerprint" not in status_columns:
        conn.execute(
            "ALTER TABLE run_validation_status ADD COLUMN validator_source_fingerprint "
            "TEXT NOT NULL DEFAULT ''"
        )
    _migrate_legacy_runs(conn)
    conn.execute("PRAGMA user_version = 2")
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone() is not None


def _legacy_config_fingerprint(
    run_id: str,
    run_kind: str,
    target: str,
    model: str,
    scenario: str,
) -> str:
    raw = "|".join((run_id, run_kind, target, model, scenario))
    return f"legacy_cfg_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def _migrate_legacy_runs(conn: sqlite3.Connection) -> None:
    """Copy pre-v2 metadata rows without upgrading their validation authority."""

    if not _table_exists(conn, "runs"):
        return
    rows = conn.execute(
        "SELECT run_id, run_kind, created_at, tool_version, target, model, "
        "scenario, outcomes, manifest_path FROM runs"
    ).fetchall()
    for row in rows:
        legacy_run_id = str(row[0] or "")
        run_kind = str(row[1] or "")
        target = str(row[4] or "")
        model = str(row[5] or "")
        scenario = str(row[6] or "")
        manifest_path = str(row[8] or "")
        execution_id = _legacy_execution_id(legacy_run_id, manifest_path)
        conn.execute(
            "INSERT INTO run_executions (execution_id, config_fingerprint, "
            "legacy_run_id, run_kind, created_at, tool_version, target, model, "
            "scenario, outcomes, manifest_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(execution_id) DO NOTHING",
            (
                execution_id,
                _legacy_config_fingerprint(
                    legacy_run_id,
                    run_kind,
                    target,
                    model,
                    scenario,
                ),
                legacy_run_id,
                run_kind,
                str(row[2] or ""),
                str(row[3] or ""),
                target,
                model,
                scenario,
                str(row[7] or "{}"),
                manifest_path,
            ),
        )


def index_runs(root: Path, db_path: Path) -> int:
    """Scan ``root`` and index immutable execution identities.

    Re-indexing the same manifest is idempotent. Distinct schema-v0.2 executions with
    the same configuration remain distinct rows.
    """
    records = load_validated_run_records(root)
    conn = _connect(db_path)
    try:
        for record in records:
            path, manifest = record.path, record.manifest
            try:
                rel = path.parent.relative_to(root).as_posix()
            except ValueError:
                rel = path.parent.name
            execution_id = manifest.execution_id or _legacy_execution_id(
                manifest.run_id,
                rel,
            )
            config_fingerprint = manifest.config_fingerprint or make_config_fingerprint(
                manifest.run_kind,
                manifest.target,
                manifest.model,
                manifest.scenario,
                manifest.variants,
                manifest.repeats,
            )
            immutable_values = (
                execution_id,
                config_fingerprint,
                manifest.run_id,
                manifest.run_kind,
                manifest.created_at,
                manifest.tool_version,
                manifest.target,
                manifest.model,
                manifest.scenario,
                json.dumps(manifest.outcomes, sort_keys=True),
                rel,
            )
            conn.execute(
                "INSERT INTO run_executions (execution_id, config_fingerprint, "
                "legacy_run_id, run_kind, created_at, tool_version, target, model, "
                "scenario, outcomes, manifest_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(execution_id) DO NOTHING",
                immutable_values,
            )
            stored = conn.execute(
                "SELECT execution_id, config_fingerprint, legacy_run_id, run_kind, "
                "created_at, tool_version, target, model, scenario, outcomes, "
                "manifest_path FROM run_executions WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            if stored is None or tuple(stored) != immutable_values:
                raise ValueError(
                    f"execution identity collision for {execution_id}; "
                    "the index is append-only"
                )
            expectation_status = "ok" if record.expectations_ok else "mismatch"
            conn.execute(
                "INSERT INTO run_validation_status (execution_id, manifest_sha256, "
                "expectation_status, expectation_mismatch_count, validation_scope, "
                "validator_tool_version, corpus_version, validator_source_fingerprint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(execution_id) DO UPDATE SET "
                "manifest_sha256 = excluded.manifest_sha256, "
                "expectation_status = excluded.expectation_status, "
                "expectation_mismatch_count = excluded.expectation_mismatch_count, "
                "validation_scope = excluded.validation_scope, "
                "validator_tool_version = excluded.validator_tool_version, "
                "corpus_version = excluded.corpus_version, "
                "validator_source_fingerprint = excluded.validator_source_fingerprint",
                (
                    execution_id,
                    record.manifest_sha256,
                    expectation_status,
                    record.expectation_mismatch_count,
                    "independently_recomputed_at_index",
                    __version__,
                    CORPUS_VERSION,
                    record.validator_source_fingerprint,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return len(records)


def list_db_runs(db_path: Path) -> list[dict[str, object]]:
    """Read indexed runs in deterministic identity order, not unsigned time order."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        has_executions = _table_exists(conn, "run_executions")
        has_legacy_runs = _table_exists(conn, "runs")
        if not has_executions and has_legacy_runs:
            legacy_rows = conn.execute(
                "SELECT run_id, run_kind, created_at, tool_version, target, model, "
                "scenario, outcomes, manifest_path FROM runs ORDER BY created_at, run_id"
            ).fetchall()
            rows: list[dict[str, object]] = []
            for row in legacy_rows:
                legacy = dict(row)
                legacy_run_id = str(legacy.pop("run_id", "") or "")
                manifest_path = str(legacy.get("manifest_path", "") or "")
                execution_id = _legacy_execution_id(legacy_run_id, manifest_path)
                rows.append({
                    "run_id": execution_id,
                    "execution_id": execution_id,
                    "config_fingerprint": _legacy_config_fingerprint(
                        legacy_run_id,
                        str(legacy.get("run_kind", "") or ""),
                        str(legacy.get("target", "") or ""),
                        str(legacy.get("model", "") or ""),
                        str(legacy.get("scenario", "") or ""),
                    ),
                    **legacy,
                    "expectation_status": "not_recorded",
                    "expectation_mismatch_count": 0,
                    "validation_manifest_sha256": "",
                    "validation_scope": "not_recorded",
                    "validator_tool_version": "",
                    "corpus_version": "",
                    "validator_source_fingerprint": "",
                })
        elif not has_executions:
            return []
        else:
            has_validation_status = _table_exists(conn, "run_validation_status")
            status_join = (
                "COALESCE(v.expectation_status, 'not_recorded') AS expectation_status, "
                "COALESCE(v.expectation_mismatch_count, 0) AS expectation_mismatch_count, "
                "COALESCE(v.manifest_sha256, '') AS validation_manifest_sha256, "
                "COALESCE(v.validation_scope, 'not_recorded') AS validation_scope, "
                "COALESCE(v.validator_tool_version, '') AS validator_tool_version, "
                "COALESCE(v.corpus_version, '') AS corpus_version, "
                "COALESCE(v.validator_source_fingerprint, '') "
                "AS validator_source_fingerprint "
                "FROM run_executions AS e LEFT JOIN run_validation_status AS v "
                "ON v.execution_id = e.execution_id "
                if has_validation_status
                else "'not_recorded' AS expectation_status, "
                "0 AS expectation_mismatch_count, "
                "'' AS validation_manifest_sha256, 'not_recorded' AS validation_scope, "
                "'' AS validator_tool_version, '' AS corpus_version, "
                "'' AS validator_source_fingerprint "
                "FROM run_executions AS e "
            )
            rows = [
                dict(row)
                for row in conn.execute(
                    "SELECT e.execution_id AS run_id, e.execution_id, "
                    "e.config_fingerprint, e.run_kind, e.created_at, e.tool_version, "
                    "e.target, e.model, e.scenario, e.outcomes, e.manifest_path, "
                    + status_join
                    + "ORDER BY e.execution_id"
                ).fetchall()
            ]
    finally:
        conn.close()
    out: list[dict[str, object]] = []
    for r in rows:
        d = dict(r)
        raw_outcomes = d.get("outcomes")
        try:
            d["outcomes"] = json.loads(raw_outcomes if isinstance(raw_outcomes, str) else "{}")
        except (ValueError, TypeError):
            d["outcomes"] = {}
        out.append(d)
    return out


def _legacy_execution_id(run_id: str, manifest_path: str) -> str:
    """Give each legacy manifest path a stable index identity without conflating paths."""

    digest = hashlib.sha256(f"{run_id}|{manifest_path}".encode()).hexdigest()
    return f"legacy_{digest[:24]}"
