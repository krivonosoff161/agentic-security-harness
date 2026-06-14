"""Lightweight local SQLite index of run manifests (metadata only).

Stdlib ``sqlite3`` only - no dependency, no network, no trace bodies, no secrets. The
index stores just the manifest metadata (run id, kind, target/model labels, scenario,
outcome counts, and the manifest path relative to the scanned root) so a user can keep a
local history of runs and query it later. The JSON ``run_index.json`` files remain the
source of truth; this is a derived convenience index.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentic_security_harness.run_manifest import load_run_manifests

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
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


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(_SCHEMA)
    return conn


def index_runs(root: Path, db_path: Path) -> int:
    """Scan ``root`` for run manifests and upsert them into the SQLite index.

    Returns the number of runs indexed. Idempotent (upsert by run_id).
    """
    manifests = load_run_manifests(root)
    conn = _connect(db_path)
    try:
        for path, manifest in manifests:
            try:
                rel = path.parent.relative_to(root).as_posix()
            except ValueError:
                rel = path.parent.name
            conn.execute(
                "INSERT INTO runs (run_id, run_kind, created_at, tool_version, "
                "target, model, scenario, outcomes, manifest_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET "
                "run_kind=excluded.run_kind, created_at=excluded.created_at, "
                "tool_version=excluded.tool_version, target=excluded.target, "
                "model=excluded.model, scenario=excluded.scenario, "
                "outcomes=excluded.outcomes, manifest_path=excluded.manifest_path",
                (
                    manifest.run_id,
                    manifest.run_kind,
                    manifest.created_at,
                    manifest.tool_version,
                    manifest.target,
                    manifest.model,
                    manifest.scenario,
                    json.dumps(manifest.outcomes, sort_keys=True),
                    rel,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return len(manifests)


def list_db_runs(db_path: Path) -> list[dict[str, object]]:
    """Read all indexed runs from the SQLite index, newest path-sorted."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT run_id, run_kind, created_at, tool_version, target, model, "
            "scenario, outcomes, manifest_path FROM runs ORDER BY created_at, run_id"
        ).fetchall()
    finally:
        conn.close()
    out: list[dict[str, object]] = []
    for r in rows:
        d = dict(r)
        try:
            d["outcomes"] = json.loads(d.get("outcomes") or "{}")
        except (ValueError, TypeError):
            d["outcomes"] = {}
        out.append(d)
    return out
