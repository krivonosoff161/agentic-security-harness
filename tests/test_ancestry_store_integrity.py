"""Focused synthetic corruption and lock regressions for the Q315 store."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest

from agentic_security_harness import ancestry_store as module
from agentic_security_harness.ancestry_store import AncestryRecord, AncestryStore, IntegrityError


def _created(tmp_path: Path) -> tuple[AncestryStore, Path, Path]:
    db = tmp_path / "ancestry.db"
    witness = tmp_path / "witness.json"
    root = AncestryRecord("root", "case-one", b"synthetic", (), ("read",))
    store = AncestryStore.create(db, witness, context="case-one", root=root)
    return store, db, witness


def test_sqlite_like_wildcard_name_does_not_hide_extra_table(tmp_path: Path) -> None:
    store, db, _ = _created(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE sqliteXextra (value TEXT)")
    with pytest.raises(IntegrityError, match="schema differs"):
        store.checkpoint()


def test_unique_index_must_cover_record_id(tmp_path: Path) -> None:
    store, db, _ = _created(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE records RENAME TO old_records")
        conn.execute("""
            CREATE TABLE records (
                sequence INTEGER PRIMARY KEY,
                record_id TEXT NOT NULL,
                context TEXT UNIQUE NOT NULL,
                payload BLOB NOT NULL,
                parents TEXT NOT NULL,
                scope TEXT NOT NULL,
                digest TEXT NOT NULL
            )
        """)
        conn.execute("INSERT INTO records SELECT * FROM old_records")
        conn.execute("DROP TABLE old_records")
        index = conn.execute("PRAGMA index_list(records)").fetchone()
        indexed_column = conn.execute(f"PRAGMA index_info({index[1]})").fetchone()[2]
    assert indexed_column == "context"
    with pytest.raises(IntegrityError, match="index columns differ"):
        store.checkpoint()


def test_wrong_payload_storage_type_rejected_before_record_fetch(tmp_path: Path) -> None:
    store, db, _ = _created(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE records SET payload=? WHERE sequence=1", ("𝄞" * 65536,))
    statements: list[str] = []
    with closing(store._connection()) as conn:
        conn.set_trace_callback(statements.append)
        with pytest.raises(IntegrityError, match="stored column types"):
            store._verify_db(conn)
    assert not any("FROM records ORDER BY sequence" in statement for statement in statements)


def test_oversized_witness_fails_closed(tmp_path: Path) -> None:
    store, _, witness = _created(tmp_path)
    witness.write_bytes(b"X" * (module._MAX_WITNESS + 1))
    with pytest.raises(IntegrityError, match="witness too large"):
        store.checkpoint()


def test_second_thread_lock_wait_expires_with_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _, _ = _created(tmp_path)
    monkeypatch.setattr(module, "_LOCK_TIMEOUT_SECONDS", 0.05)
    with store._writer_guard():
        with ThreadPoolExecutor(max_workers=1) as pool:
            blocked = pool.submit(store.checkpoint)
            with pytest.raises(IntegrityError, match="lock wait expired"):
                blocked.result(timeout=2)
