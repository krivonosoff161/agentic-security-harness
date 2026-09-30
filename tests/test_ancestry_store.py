"""Synthetic, disposable data-only ancestry store checks."""

from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agentic_security_harness import ancestry_store as module
from agentic_security_harness.ancestry_store import (
    AncestryError,
    AncestryRecord,
    AncestryStore,
    CheckpointConflict,
    IntegrityError,
)


def record(name: str, parents: tuple[str, ...] = (),
           scope: tuple[str, ...] = ("read", "summarize"),
           payload: bytes = b"synthetic") -> AncestryRecord:
    return AncestryRecord(name, "case-one", payload, parents, scope)


def created(tmp_path: Path) -> tuple[AncestryStore, Path, Path, AncestryRecord]:
    db, witness = tmp_path / "ancestry.db", tmp_path / "witness.json"
    root = record("root")
    store = AncestryStore.create(db, witness, context="case-one", root=root)
    return store, db, witness, root


def test_narrowing_reopen_and_exact_closure(tmp_path: Path) -> None:
    store, db, witness, root = created(tmp_path)
    first = store.checkpoint()
    child = record("child", ("root",), ("read",), b"same bytes")
    second = store.append(child, expected=first)
    reopened = AncestryStore.open(db, witness, context="case-one",
                                 root_digest=first.root_digest)
    snapshot = reopened.snapshot(expected=second)
    assert snapshot.records == (root, child)
    assert snapshot.operational_authority == "none"
    assert snapshot.may_authorize_effects is False
    assert reopened.verify_candidate("child", (root, child), expected=second)
    assert not reopened.verify_candidate("child", (child,), expected=second)
    assert not reopened.verify_candidate("child", (root, record("child", ("root",),
                                                                ("read",), b"different")),
                                         expected=second)
    assert not reopened.verify_candidate("root", (root, child), expected=second)
    with pytest.raises(CheckpointConflict):
        reopened.snapshot(expected=first)


def test_reject_rebinding_missing_parent_and_expansion(tmp_path: Path) -> None:
    store, _, _, _ = created(tmp_path)
    first = store.checkpoint()
    with pytest.raises(AncestryError, match="already admitted"):
        store.append(record("root", ("root",)), expected=first)
    with pytest.raises(AncestryError, match="missing parent"):
        store.append(record("orphan", ("absent",)), expected=first)
    narrow = store.append(record("narrow", ("root",), ("read",)), expected=first)
    with pytest.raises(AncestryError, match="expands"):
        store.append(record("wide", ("narrow",), ("read", "summarize")), expected=narrow)
    with pytest.raises(CheckpointConflict):
        store.append(record("stale", ("root",)), expected=first)
    assert store.checkpoint() == narrow


def test_malformed_records_and_no_silent_bootstrap(tmp_path: Path) -> None:
    with pytest.raises(AncestryError):
        record("bad", ("z", "a"))
    with pytest.raises(AncestryError):
        record("bad", payload=b"x" * 65537)
    store, db, witness, root = created(tmp_path)
    with pytest.raises(IntegrityError, match="already exists"):
        AncestryStore.create(db, witness, context="case-one", root=root)
    witness.unlink()
    with pytest.raises(IntegrityError, match="database, witness and lock"):
        AncestryStore.open(db, witness, context="case-one",
                           root_digest=store.root_digest)


def test_record_and_event_tamper_fail_closed(tmp_path: Path) -> None:
    store, db, _, _ = created(tmp_path)
    cp = store.checkpoint()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE records SET payload=? WHERE sequence=1", (b"forged",))
    with pytest.raises(IntegrityError, match="record"):
        store.snapshot(expected=cp)


def test_integer_payload_is_not_coerced_to_bytes(tmp_path: Path) -> None:
    store, db, _, _ = created(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE records SET payload=? WHERE sequence=1", (10**12,))
    with pytest.raises(IntegrityError, match="column types"):
        store.checkpoint()


def test_witness_rollback_and_wrong_identity_fail_closed(tmp_path: Path) -> None:
    store, db, witness, _ = created(tmp_path)
    original = witness.read_bytes()
    first = store.checkpoint()
    store.append(record("child", ("root",)), expected=first)
    witness.write_bytes(original)
    with pytest.raises(IntegrityError, match="checkpoints differ"):
        AncestryStore.open(db, witness, context="case-one",
                           root_digest=first.root_digest)
    with pytest.raises(IntegrityError):
        AncestryStore.open(db, witness, context="wrong-context",
                           root_digest=first.root_digest)


@pytest.mark.parametrize("stage,expected_committed", [
    ("after_prepare", False), ("after_db_commit", True), ("after_finalize", True)
])
def test_pending_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                          stage: str, expected_committed: bool) -> None:
    store, db, witness, _ = created(tmp_path)
    first = store.checkpoint()

    def crash(at: str) -> None:
        if at == stage:
            raise SystemExit("synthetic crash")

    monkeypatch.setattr(module, "_fault_point", crash)
    with pytest.raises(SystemExit):
        store.append(record("child", ("root",)), expected=first)
    monkeypatch.setattr(module, "_fault_point", lambda _: None)
    reopened = AncestryStore.open(db, witness, context="case-one",
                                 root_digest=first.root_digest)
    snapshot = reopened.snapshot(expected=reopened.checkpoint())
    assert (len(snapshot.records) == 2) is expected_committed
    assert json.loads(witness.read_bytes())["pending"] is None


def test_event_tamper_and_unrelated_record_fail_closed(tmp_path: Path) -> None:
    store, db, _, _ = created(tmp_path)
    cp = store.checkpoint()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE events SET event_head=? WHERE sequence=1", ("f" * 64,))
    with pytest.raises(IntegrityError, match="event chain"):
        store.checkpoint()
    assert cp.sequence == 1


def test_schema_extension_and_forged_pending_fail_closed(tmp_path: Path) -> None:
    store, db, witness, _ = created(tmp_path)
    first = store.checkpoint()
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE injected (value TEXT)")
    with pytest.raises(IntegrityError, match="schema differs"):
        store.checkpoint()
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE injected")
    store.append(record("child", ("root",)), expected=first)
    body = json.loads(witness.read_bytes())
    body["pending"] = {"before": body["committed"], "after": body["committed"]}
    witness.write_bytes(module._json(body))
    with pytest.raises(IntegrityError, match="pending transition"):
        store.checkpoint()


def test_writer_lock_covers_commit_to_finalize(tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    store, _, _, _ = created(tmp_path)
    first = store.checkpoint()
    child = record("child", ("root",))
    second = module.Checkpoint(
        first.context, first.root_digest, first.version, first.sequence + 1,
        module._head(first.sequence + 1, first.event_head,
                     module._record_digest(child)),
    )
    paused = threading.Event()
    release = threading.Event()
    once = threading.Event()

    def pause_first(stage: str) -> None:
        if stage == "after_db_commit" and not once.is_set():
            once.set()
            paused.set()
            assert release.wait(5)

    monkeypatch.setattr(module, "_fault_point", pause_first)
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer_a = pool.submit(store.append, child, expected=first)
        assert paused.wait(5)
        writer_b = pool.submit(store.append, record("grandchild", ("child",)),
                               expected=second)
        try:
            assert not writer_b.done()
        finally:
            release.set()
        assert writer_a.result(timeout=5) == second
        third = writer_b.result(timeout=5)
    assert store.checkpoint() == third
    assert len(store.snapshot(expected=third).records) == 3
