"""Post-create fault injection; no claim about an unidentified external disk."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import ancestry_store as storage
from agentic_security_harness import cli
from agentic_security_harness import controlled_file_workflow as workflow
from agentic_security_harness._fixture_files import FixtureFiles
from agentic_security_harness.controlled_file_verifier import verify_controlled_file_workflow

_RAW = b'{"operation":"write_report","artifact":"report","approved_count":1,"rejected_count":2}'


def _io_error() -> sqlite3.OperationalError:
    error = sqlite3.OperationalError("PRIVATE_PATH_SENTINEL")
    # Exercise primary-code classification of extended codes, not just SQLITE_IOERR.
    error.sqlite_errorcode = sqlite3.SQLITE_IOERR_WRITE
    return error


def _inject(patch: pytest.MonkeyPatch, store: storage.AncestryStore, fault: str,
            cleanup: str | None = None) -> None:
    original_connect = sqlite3.connect
    original_connection = store._connection

    class FaultConnection(sqlite3.Connection):
        commits = 0

        def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
            if (
                (fault.endswith("_begin") and sql == "BEGIN IMMEDIATE")
                or (fault.endswith("_read") and sql.startswith("SELECT") and self.commits == 0)
                or (fault == "append_insert" and sql.startswith("INSERT INTO records"))
                or (fault == "append_verify" and sql.startswith("SELECT") and self.commits == 1)
            ):
                raise _io_error()
            return super().execute(sql, parameters)

        def commit(self) -> None:
            self.commits += 1
            if self.commits == 1 and fault in {"state_commit", "append_commit_before"}:
                raise _io_error()
            if self.commits == 2 and fault == "append_finalize_commit":
                raise _io_error()
            super().commit()
            if self.commits == 1 and fault == "append_commit_after":
                raise _io_error()

        def close(self) -> None:
            super().close()
            if cleanup == "database_close" or fault == "state_close":
                raise _io_error()

    def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = FaultConnection
        return original_connect(*args, **kwargs)  # type: ignore[call-overload]

    def connection() -> sqlite3.Connection:
        if fault.endswith("_open") and fault != "lock_open":
            raise _io_error()
        return original_connection()

    if fault.startswith(("state_", "append_")):
        patch.setattr(storage.sqlite3, "connect", connect)
        patch.setattr(store, "_connection", connection)
    if fault == "witness_read":
        original_path_open = Path.open

        def path_open(path: Path, *args: Any, **kwargs: Any) -> Any:
            if path == store.witness_path:
                raise OSError(5, "PRIVATE_PATH_SENTINEL")
            return original_path_open(path, *args, **kwargs)

        patch.setattr(Path, "open", path_open)
    if fault == "lock_open":
        original_os_open = os.open

        def os_open(path: Any, *args: Any, **kwargs: Any) -> int:
            if Path(path) == store.lock_path:
                raise OSError(13, "PRIVATE_PATH_SENTINEL")
            return original_os_open(path, *args, **kwargs)

        patch.setattr(os, "open", os_open)
    if fault.startswith(("prepare_", "finalize_")):
        target = 1 if fault.startswith("prepare_") else 2
        count = 0
        original_replace, original_fsync = os.replace, os.fsync

        def replace(src: Any, dst: Any) -> None:
            nonlocal count
            count += 1
            if count == target and fault.endswith("replace_before"):
                raise OSError(5, "PRIVATE_PATH_SENTINEL")
            original_replace(src, dst)
            if count == target and fault.endswith("replace_after"):
                # Models a failure reported after replacement (e.g. directory fsync).
                raise OSError(5, "PRIVATE_PATH_SENTINEL")

        def fsync(fd: int) -> None:
            nonlocal count
            if stat.S_ISREG(os.fstat(fd).st_mode):
                count += 1
                if count == target:
                    raise OSError(28, "PRIVATE_PATH_SENTINEL")
            original_fsync(fd)

        patch.setattr(os, "fsync" if fault.endswith("fsync") else "replace",
                      fsync if fault.endswith("fsync") else replace)


def _inject_lock_cleanup(patch: pytest.MonkeyPatch, store: storage.AncestryStore,
                         stage: str) -> None:
    if stage == "lock_release":
        if sys.platform == "win32":
            import msvcrt

            original_locking = msvcrt.locking

            def locking(fd: int, mode: int, count: int) -> None:
                original_locking(fd, mode, count)
                if mode == msvcrt.LK_UNLCK:
                    raise OSError(5, "PRIVATE_CLEANUP_SENTINEL")

            patch.setattr(msvcrt, "locking", locking)
        else:
            import fcntl

            original_flock = fcntl.flock

            def flock(fd: int, operation: int) -> None:
                original_flock(fd, operation)
                if operation == fcntl.LOCK_UN:
                    raise OSError(5, "PRIVATE_CLEANUP_SENTINEL")

            patch.setattr(fcntl, "flock", flock)
    elif stage == "lock_close":
        original_open, original_close = os.open, os.close
        lock_fd: int | None = None

        def opened(path: Any, *args: Any, **kwargs: Any) -> int:
            nonlocal lock_fd
            fd = original_open(path, *args, **kwargs)
            if Path(path) == store.lock_path:
                lock_fd = fd
            return fd

        def closed(fd: int) -> None:
            original_close(fd)
            if fd == lock_fd:
                raise OSError(5, "PRIVATE_CLEANUP_SENTINEL")

        patch.setattr(os, "open", opened)
        patch.setattr(os, "close", closed)


@pytest.mark.parametrize("fault,stage,record_count,pending", [
    ("state_open", "state_open", 1, False),
    ("state_begin", "state_begin", 1, False),
    ("state_read", "state_read", 1, False),
    ("state_commit", "state_commit", 1, False),
    ("state_close", "database_close", 1, False),
    ("witness_read", "read_witness", 1, False),
    ("lock_open", "lock_open", 1, False),
    ("append_open", "append_open", 1, False),
    ("append_begin", "append_begin", 1, False),
    ("append_read", "append_read", 1, False),
    ("prepare_fsync", "append_prepare_witness", 1, False),
    ("prepare_replace_before", "append_prepare_witness", 1, False),
    ("prepare_replace_after", "append_prepare_witness", 1, True),
    ("append_insert", "append_insert", 1, True),
    ("append_commit_before", "append_commit", 1, True),
    ("append_commit_after", "append_commit", 2, True),
    ("append_verify", "append_verify", 2, True),
    ("finalize_fsync", "append_finalize_witness", 2, True),
    ("finalize_replace_before", "append_finalize_witness", 2, True),
    ("finalize_replace_after", "append_finalize_witness", 2, False),
    ("append_finalize_commit", "append_finalize_commit", 2, False),
])
def test_post_create_failure_blocks_current_effect_and_preserves_actual_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    fault: str, stage: str, record_count: int, pending: bool,
) -> None:
    store = workflow._store(tmp_path, "case-one", "public synthetic")
    with FixtureFiles.create(tmp_path / "files") as files:
        before = files.snapshot()
        with monkeypatch.context() as patch:
            patch.setattr(workflow, "decide_file_write", lambda **kw: pytest.fail("Guard reached"))
            patch.setattr(FixtureFiles, "write_once", lambda *a: pytest.fail("write reached"))
            if fault.startswith(("state_", "witness_", "lock_")):
                _inject(patch, store, fault)
            else:
                original_append = store.append

                def append(record: storage.AncestryRecord, *, expected: storage.Checkpoint
                           ) -> storage.Checkpoint:
                    _inject(patch, store, fault)
                    return original_append(record, expected=expected)

                patch.setattr(store, "append", append)
            with pytest.raises(storage.StorageError) as raised:
                workflow._apply(files, store, _RAW, call_id="call-1", context="case-one")
        assert raised.value.stage == stage
        assert "PRIVATE_PATH_SENTINEL" not in str(raised.value)
        if fault.startswith(("state_", "append_")):
            assert raised.value.sqlite_errorcode == sqlite3.SQLITE_IOERR_WRITE
        else:
            assert raised.value.os_errno in {5, 13, 28}
        assert files.snapshot() == before
        with sqlite3.connect(store.db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM records").fetchone()[0] == record_count
        body = json.loads(store.witness_path.read_bytes())
        assert (body["pending"] is not None) is pending
        assert store.lock_path.is_file()
        # Explicit data recovery is not action replay. It may accept the already
        # committed record, but it never calls the file writer or deletes evidence.
        reopened = storage.AncestryStore.open(
            store.db_path, store.witness_path, context=store.context,
            root_digest=store.root_digest,
        )
        checkpoint = reopened.checkpoint()
        assert checkpoint.sequence == record_count
        assert files.snapshot() == before
        assert len(reopened.snapshot(expected=checkpoint).records) == record_count


@pytest.mark.parametrize("cleanup", ["database_close", "lock_release", "lock_close"])
@pytest.mark.parametrize("primary_failure", [False, True])
def test_cleanup_failure_preserves_primary_commit_diagnosis_and_blocks_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup: str, primary_failure: bool,
) -> None:
    store = workflow._store(tmp_path, "case-one", "fixed")
    with FixtureFiles.create(tmp_path / "files") as files:
        before = files.snapshot()
        with monkeypatch.context() as patch:
            patch.setattr(workflow, "decide_file_write", lambda **kw: pytest.fail("Guard reached"))
            original_append = store.append

            def append(record: storage.AncestryRecord, *, expected: storage.Checkpoint
                       ) -> storage.Checkpoint:
                _inject(patch, store, "append_commit_after" if primary_failure else "append_ok",
                        cleanup=cleanup)
                _inject_lock_cleanup(patch, store, cleanup)
                return original_append(record, expected=expected)

            patch.setattr(store, "append", append)
            with pytest.raises(storage.StorageError) as raised:
                workflow._apply(files, store, _RAW, call_id="call-1", context="case-one")
        assert raised.value.stage == ("append_commit" if primary_failure else cleanup)
        assert raised.value.cleanup_stages == ((cleanup,) if primary_failure else ())
        assert "SENTINEL" not in str(raised.value)
        assert files.snapshot() == before
        assert store.checkpoint().sequence == 2
        assert files.snapshot() == before


def test_witness_temp_cleanup_cannot_mask_primary_storage_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = workflow._store(tmp_path, "case-one", "fixed")
    checkpoint = store.checkpoint()
    with monkeypatch.context() as patch:
        _inject(patch, store, "prepare_fsync")
        original_unlink = os.unlink

        def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            if Path(path).parent == tmp_path and Path(path).name.startswith(".ancestry-"):
                raise OSError(13, "PRIVATE_CLEANUP_SENTINEL")
            original_unlink(path, *args, **kwargs)

        patch.setattr(os, "unlink", unlink)
        with pytest.raises(storage.StorageError) as raised:
            store.append(storage.AncestryRecord("child", "case-one", b"fixed", ("root",),
                                                ("fixture",)), expected=checkpoint)
    assert raised.value.stage == "append_prepare_witness"
    assert raised.value.os_errno == 28
    assert raised.value.cleanup_stages == ("witness_temp_cleanup",)
    assert len(list(tmp_path.glob(".ancestry-*"))) == 1
    assert store.checkpoint() == checkpoint


@pytest.mark.parametrize("crash,record_count", [("after_prepare", 1), ("after_db_commit", 2)])
def test_recovery_witness_failure_is_typed_without_replaying_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crash: str, record_count: int,
) -> None:
    store = workflow._store(tmp_path, "case-one", "public synthetic")
    checkpoint = store.checkpoint()

    def stop(stage: str) -> None:
        if stage == crash:
            raise SystemExit("declared local crash seam")

    with monkeypatch.context() as patch:
        patch.setattr(storage, "_fault_point", stop)
        with pytest.raises(SystemExit):
            store.append(storage.AncestryRecord("child", "case-one", b"fixed", ("root",),
                                                ("fixture",)), expected=checkpoint)
    witness_before = store.witness_path.read_bytes()
    with FixtureFiles.create(tmp_path / "files") as files:
        before = files.snapshot()
        with monkeypatch.context() as patch:
            _inject(patch, store, "prepare_replace_before")
            patch.setattr(workflow, "decide_file_write", lambda **kw: pytest.fail("Guard reached"))
            with pytest.raises(storage.StorageError, match="recover_witness"):
                workflow._apply(files, store, _RAW, call_id="call-2", context="case-one")
        assert store.witness_path.read_bytes() == witness_before
        assert files.snapshot() == before
        assert store.checkpoint().sequence == record_count
        assert files.snapshot() == before


@pytest.mark.parametrize("code", [sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB,
                                 sqlite3.SQLITE_ERROR])
def test_database_integrity_failure_is_not_relabelled_as_storage_availability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int,
) -> None:
    store = workflow._store(tmp_path, "case-one", "fixed")

    def fail() -> sqlite3.Connection:
        error = sqlite3.DatabaseError("PRIVATE_PATH_SENTINEL")
        error.sqlite_errorcode = code
        raise error

    monkeypatch.setattr(store, "_connection", fail)
    with pytest.raises(storage.IntegrityError) as raised:
        store.checkpoint()
    assert type(raised.value) is storage.IntegrityError
    assert "PRIVATE_PATH_SENTINEL" not in str(raised.value)


def test_cli_integrity_failure_is_content_free_nonzero_and_not_io_diagnosis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    original_store = workflow._store

    def corrupt(area: Path, context: str, document: str) -> storage.AncestryStore:
        store = original_store(area, context, document)
        store.witness_path.write_bytes(b"PRIVATE_PATH_SENTINEL invalid json")
        return store

    monkeypatch.setattr(workflow, "_store", corrupt)
    monkeypatch.setattr(workflow, "decide_file_write", lambda **kw: pytest.fail("Guard reached"))
    out = tmp_path / "incomplete"
    assert cli.main(["controlled-file-workflow", "--out", str(out)]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["reason"] == "ancestry_integrity_failure"
    assert "sqlite_errorcode" not in report
    assert "PRIVATE_PATH_SENTINEL" not in captured.out + captured.err
    assert str(tmp_path) not in captured.out + captured.err
    assert not (out / "result.json").exists()
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False


def test_later_case_storage_failure_does_not_erase_or_deny_prior_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    original_append = storage.AncestryStore.append

    def fail_second(store: storage.AncestryStore, record: storage.AncestryRecord, *,
                    expected: storage.Checkpoint) -> storage.Checkpoint:
        if store.context == "case-02":
            with monkeypatch.context() as patch:
                _inject(patch, store, "append_commit_after")
                return original_append(store, record, expected=expected)
        return original_append(store, record, expected=expected)

    monkeypatch.setattr(storage.AncestryStore, "append", fail_second)
    out = tmp_path / "partial"
    assert cli.main(["controlled-file-workflow", "--out", str(out)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["stage"] == "append_commit"
    assert report["completed_effects"] == "unknown_inspect_retained_evidence"
    first = json.loads((out / "case-01/call-1-result.json").read_bytes())
    assert first["applied"] is True
    assert first["reason"] == "write_completed"
    from agentic_security_harness._fixture_files import INITIAL_PROTECTED, INITIAL_REPORT

    assert (out / "case-01/files/report.txt").read_bytes() != INITIAL_REPORT
    assert (out / "case-02/files/report.txt").read_bytes() == INITIAL_REPORT
    for case in ("case-01", "case-02"):
        assert (out / case / "files/protected.txt").read_bytes() == INITIAL_PROTECTED
    assert not (out / "case-02/call-1-result.json").exists()
    assert not (out / "case-03").exists()
    assert not (out / "result.json").exists()
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False
    before = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    with pytest.raises((ValueError, FileExistsError)):
        workflow.run_controlled_file_workflow(out)
    assert before == {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
