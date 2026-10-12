"""Actual disposable file effects for same-operation bounded recovery.

These tests do not substitute semantic task quality or independent host history.
The test host owns its original policy, content, identity and durable coordinator.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import _workspace_files
from agentic_security_harness.workspace_operation import (
    WorkspaceOperation,
    WorkspaceOperationError,
)
from agentic_security_harness.workspace_writer import WorkspacePolicy

CONTENT = "# Summary\n\nApproved: 30\nRejected: 4\n"
RAW = CONTENT.encode("utf-8")
PROTECTED = b"preserve unrelated sibling\n"


@pytest.fixture
def host(tmp_path: Path) -> tuple[Path, WorkspacePolicy, dict[str, Any]]:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "protected.txt").write_bytes(PROTECTED)
    policy = WorkspacePolicy(root, (("document", "report.md"),), max_bytes=4096,
                             max_proposals=1, data_class="synthetic")
    return tmp_path / "operation.sqlite", policy, {
        "operation_id": "owned-report-operation", "artifact": "document",
        "content": CONTENT, "max_attempts": 3,
    }


def unknown(call: Callable[[], dict[str, Any]]) -> None:
    # A typed refusal is also acceptable for damaged/unknown state, never success.
    try:
        result = call()
    except WorkspaceOperationError:
        return
    assert result["state"] == "UNKNOWN"


def test_useful_write_and_exact_receipt(host: tuple[Path, WorkspacePolicy, dict[str, Any]]) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    permission = op.authorize()
    result = op.deliver(permission)
    assert result["state"] == "DELIVERED_RECEIPT"
    assert result["attempts_spent"] == 1
    assert (policy.output_dir / "report.md").read_bytes() == RAW
    assert (policy.output_dir / "protected.txt").read_bytes() == PROTECTED
    assert len(list(policy.output_dir.glob(".ash-*-result.json"))) == 1
    with pytest.raises(WorkspaceOperationError):
        op.authorize()


def test_redelivery_after_reopen_does_not_write_again(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    permission = op.authorize()
    op.deliver(permission)
    target = policy.output_dir / "report.md"
    before = target.stat()
    reopened = WorkspaceOperation.open(path, policy, **args)
    result = reopened.deliver(permission)
    after = target.stat()
    assert result["state"] == "DELIVERED_RECEIPT"
    assert result["attempts_spent"] == 1
    assert (after.st_ino, after.st_mtime_ns, after.st_size) == (
        before.st_ino, before.st_mtime_ns, before.st_size,
    )
    assert len(list(policy.output_dir.glob(".ash-*-intent.json"))) == 1


def test_spent_permission_needs_fenced_absence_then_fresh_authorization(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    old = op.authorize()
    op = WorkspaceOperation.open(path, policy, **args)
    with pytest.raises(WorkspaceOperationError):
        op.authorize()
    fenced = op.fence()
    assert fenced["state"] == "FENCED_ABSENT" and fenced["attempts_spent"] == 1
    assert fenced["generation"] == 1
    current = op.authorize()
    with pytest.raises(WorkspaceOperationError):
        op.deliver(old)
    assert not (policy.output_dir / "report.md").exists()
    result = op.deliver(current)
    assert result["state"] == "DELIVERED_RECEIPT" and result["attempts_spent"] == 2
    with pytest.raises(WorkspaceOperationError):
        op.deliver(old)


def test_delivery_before_fence_returns_existing_result(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    op.deliver(op.authorize())
    result = op.fence()
    assert result["state"] == "DELIVERED_RECEIPT" and result["generation"] == 0
    assert result["attempts_spent"] == 1


def test_abrupt_owned_child_after_file_before_coordinator_commit(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    WorkspaceOperation.create(path, policy, **args)
    package_file = sys.modules[WorkspaceOperation.__module__].__file__
    assert isinstance(package_file, str)
    package_root = Path(package_file).parent.parent
    # Only a fixed test-owned file writer and explicit process exit; no model code.
    code = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from agentic_security_harness.workspace_operation import WorkspaceOperation
from agentic_security_harness.workspace_writer import WorkspacePolicy, GuardedWorkspace
policy = WorkspacePolicy(Path(sys.argv[3]), (("document", "report.md"),),
                         max_bytes=4096, max_proposals=1, data_class="synthetic")
op = WorkspaceOperation.open(Path(sys.argv[2]), policy,
    operation_id="owned-report-operation", artifact="document", content=sys.argv[4], max_attempts=3)
original = GuardedWorkspace.submit
def crash(self, proposal):
    result = original(self, proposal)
    if result.get("applied") is not True:
        raise AssertionError("owned write did not complete")
    os._exit(23)
GuardedWorkspace.submit = crash
op.deliver(op.authorize())
raise AssertionError("child did not exit")
"""
    child = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(package_root), str(path),
         str(policy.output_dir), CONTENT], capture_output=True, timeout=30, check=False,
    )
    assert child.returncode == 23, child.stderr.decode("utf-8", errors="replace")
    assert child.stdout == child.stderr == b""
    op = WorkspaceOperation.open(path, policy, **args)
    target = policy.output_dir / "report.md"
    before = target.stat()
    result = op.reconcile()
    after = target.stat()
    assert result["state"] == "RECONCILED_POSTCONDITION"
    assert result["attempts_spent"] == 1
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert target.read_bytes() == RAW
    with pytest.raises(WorkspaceOperationError):
        op.authorize()


def test_real_partial_output_is_unknown_and_preserved(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    original = _workspace_files._write_all

    def short_write(fd: int, raw: bytes) -> None:
        if raw != RAW:
            original(fd, raw)
            return
        os.write(fd, raw[:7])
        os.fsync(fd)
        raise OSError("injected owned output fault")

    with monkeypatch.context() as patch:
        patch.setattr(_workspace_files, "_write_all", short_write)
        unknown(lambda: op.deliver(op.authorize()))
    assert (policy.output_dir / "report.md").read_bytes() == RAW[:7]
    op = WorkspaceOperation.open(path, policy, **args)
    unknown(op.reconcile)
    unknown(op.fence)
    with pytest.raises(WorkspaceOperationError):
        op.authorize()
    assert (policy.output_dir / "report.md").read_bytes() == RAW[:7]
    assert (policy.output_dir / "protected.txt").read_bytes() == PROTECTED


@pytest.mark.parametrize("field,value", [
    ("operation_id", "different-operation"), ("content", "different content"),
    ("max_attempts", 4), ("artifact", "protected"),
])
def test_reopen_requires_original_host_binding_and_budget(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], field: str, value: object,
) -> None:
    path, policy, args = host
    WorkspaceOperation.create(path, policy, **args)
    with pytest.raises((WorkspaceOperationError, ValueError)):
        WorkspaceOperation.open(path, policy, **{**args, field: value})
    assert not (policy.output_dir / "report.md").exists()


def test_budget_survives_reopen_and_fence(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    for index in range(3):
        if index:
            assert op.fence()["state"] == "FENCED_ABSENT"
        op.authorize()
        op = WorkspaceOperation.open(path, policy, **args)
    assert op.fence()["attempts_spent"] == 3
    with pytest.raises(WorkspaceOperationError):
        op.authorize()
    assert not (policy.output_dir / "report.md").exists()


def test_changed_permission_is_not_authority(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    grant = op.authorize()
    for forged in (replace(grant, ordinal=grant.ordinal + 1),
                   replace(grant, nonce="0" * 64), replace(grant, generation=99),
                   replace(grant, binding_sha256="0" * 64)):
        with pytest.raises(WorkspaceOperationError):
            op.deliver(forged)
    assert not (policy.output_dir / "report.md").exists()
    assert op.deliver(grant)["state"] == "DELIVERED_RECEIPT"


@pytest.mark.parametrize("preexisting", [RAW, b"different\n"])
def test_new_operation_cannot_adopt_existing_file(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], preexisting: bytes,
) -> None:
    path, policy, args = host
    (policy.output_dir / "report.md").write_bytes(preexisting)
    with pytest.raises((WorkspaceOperationError, ValueError)):
        WorkspaceOperation.create(path, policy, **args)
    assert (policy.output_dir / "report.md").read_bytes() == preexisting
    assert not path.exists()


def test_expired_source_refuses_permission(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    policy = replace(policy, source_restrictions_sha256="1" * 64,
                     source_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    op = WorkspaceOperation.create(path, policy, **args)
    with pytest.raises(WorkspaceOperationError):
        op.authorize()
    assert not (policy.output_dir / "report.md").exists()


def test_parallel_delivery_of_same_permission_creates_one_file(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    grant = op.authorize()

    def deliver() -> dict[str, Any]:
        try:
            return op.deliver(grant)
        except WorkspaceOperationError as exc:
            # A competing call can see the durable reservation before its result.
            # It must not start a second attempt; replay after completion is tested above.
            assert str(exc) == "outcome_less_replay"
            return {"state": "PENDING_REFUSAL"}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(deliver), pool.submit(deliver))]
    assert any(r["state"] == "DELIVERED_RECEIPT" for r in results)
    assert all(r["state"] in {"DELIVERED_RECEIPT", "PENDING_REFUSAL"} for r in results)
    assert op.reconcile()["attempts_spent"] == 1
    assert (policy.output_dir / "report.md").read_bytes() == RAW
    assert len(list(policy.output_dir.glob(".ash-*-intent.json"))) == 1


def test_physical_root_replacement_refuses_original_intent(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    permission = op.authorize()
    old = policy.output_dir.with_name("preserved-original")
    policy.output_dir.rename(old)
    policy.output_dir.mkdir()
    with pytest.raises((WorkspaceOperationError, ValueError)):
        WorkspaceOperation.open(path, policy, **args)
    unknown(lambda: op.deliver(permission))
    assert (old / "protected.txt").read_bytes() == PROTECTED
    assert not (old / "report.md").exists()
    assert not (policy.output_dir / "report.md").exists()


def test_changed_receipt_or_output_never_recreates_target(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    grant = op.authorize()
    op.deliver(grant)
    receipt = next(policy.output_dir.glob(".ash-*-result.json"))
    receipt.write_bytes(b"{}\n")
    unknown(op.reconcile)
    unknown(lambda: op.deliver(grant))
    assert receipt.read_bytes() == b"{}\n"
    assert (policy.output_dir / "report.md").read_bytes() == RAW


def test_coordinator_cannot_be_an_output_file(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    _, policy, args = host
    with pytest.raises((WorkspaceOperationError, ValueError)):
        WorkspaceOperation.create(policy.output_dir / "report.md", policy, **args)
    assert not (policy.output_dir / "report.md").exists()


def test_consumed_budget_and_schema_corruption_are_not_repaired(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    op.authorize()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE operation SET max_attempts=4")
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.open(path, policy, **args)
    with pytest.raises(WorkspaceOperationError):
        op.authorize()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT max_attempts FROM operation").fetchone() == (4,)
        assert db.execute("SELECT count(*) FROM permissions").fetchone() == (1,)
        db.execute("UPDATE operation SET max_attempts=3")
        db.execute("CREATE TABLE unexpected(value TEXT)")
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.open(path, policy, **args)
    assert not (policy.output_dir / "report.md").exists()


def test_held_sqlite_writer_is_unavailable_not_absent_or_new_permission(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    grant = op.authorize()
    blocker = sqlite3.connect(path)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(WorkspaceOperationError):
            op.fence()
        assert not (policy.output_dir / "report.md").exists()
    finally:
        blocker.rollback()
        blocker.close()
    result = op.deliver(grant)
    assert result["state"] == "DELIVERED_RECEIPT" and result["attempts_spent"] == 1


def test_expiry_rechecked_after_consumption_before_effect(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentic_security_harness import workspace_writer

    path, policy, args = host
    expires = datetime.now(UTC) + timedelta(minutes=5)
    policy = replace(policy, source_restrictions_sha256="1" * 64, source_expires_at=expires)
    op = WorkspaceOperation.create(path, policy, **args)
    grant = op.authorize()

    class ExpiredClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> ExpiredClock:
            return cls.fromtimestamp((expires + timedelta(seconds=1)).timestamp(), tz)

    # Deterministic clock at the existing writer; not a wall-clock timing claim.
    monkeypatch.setattr(workspace_writer, "datetime", ExpiredClock)
    unknown(lambda: op.deliver(grant))
    assert not (policy.output_dir / "report.md").exists()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM permissions").fetchone() == (1,)


def test_fence_wins_between_committed_attempt_and_file_delivery(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from collections.abc import Iterator

    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    old = op.authorize()
    committed = threading.Event()
    resume = threading.Event()
    original = op._connection
    delayed = False

    @contextmanager
    def connection_window() -> Iterator[sqlite3.Connection]:
        nonlocal delayed
        with original() as db:
            yield db
        if threading.current_thread().name.startswith("old-delivery") and not delayed:
            delayed = True
            committed.set()
            assert resume.wait(10), "test-owned old request was not resumed"

    monkeypatch.setattr(op, "_connection", connection_window)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="old-delivery") as pool:
        pending = pool.submit(op.deliver, old)
        try:
            assert committed.wait(10), "attempt reservation did not commit"
            with pytest.raises(WorkspaceOperationError, match="outcome_less_replay"):
                op.deliver(old)
            assert op.fence()["state"] == "FENCED_ABSENT"
            fresh = op.authorize()
        finally:
            resume.set()
        with pytest.raises(WorkspaceOperationError, match="stale_generation"):
            pending.result(timeout=10)
    assert not (policy.output_dir / "report.md").exists()
    result = op.deliver(fresh)
    assert result["state"] == "DELIVERED_RECEIPT" and result["attempts_spent"] == 2


def test_delivery_holds_coordinator_until_fence_observes_result(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentic_security_harness import workspace_operation
    from agentic_security_harness.workspace_writer import GuardedWorkspace

    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    permission = op.authorize()
    entered = threading.Event()
    resume = threading.Event()
    observed_busy = threading.Event()
    observations: list[str] = []
    original_submit = GuardedWorkspace.submit
    original_connect = sqlite3.connect

    class LockProbeConnection(sqlite3.Connection):
        def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
            if (sql != "BEGIN IMMEDIATE"
                    or not threading.current_thread().name.startswith("fence-lock-probe")):
                return super().execute(sql, parameters)
            try:
                super().execute("PRAGMA busy_timeout=0")
                try:
                    super().execute(sql, parameters)
                except sqlite3.OperationalError as exc:
                    code = getattr(exc, "sqlite_errorcode", None)
                    observations.append("busy" if isinstance(code, int) and
                                        code & 0xFF in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
                                        else "unexpected_error")
                else:
                    observations.append("lock_acquired_without_wait")
                    super().execute("ROLLBACK")
            finally:
                super().execute("PRAGMA busy_timeout=3000")
                observed_busy.set()
            assert observations == ["busy"], "fence did not contend with held writer lock"
            return super().execute(sql, parameters)

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        if threading.current_thread().name.startswith("fence-lock-probe"):
            return original_connect(*args, **kwargs, factory=LockProbeConnection)
        return original_connect(*args, **kwargs)

    def held_submit(self: GuardedWorkspace, proposal: bytes) -> dict[str, Any]:
        entered.set()
        assert resume.wait(10), "test-owned writer was not resumed"
        return original_submit(self, proposal)

    monkeypatch.setattr(GuardedWorkspace, "submit", held_submit)
    monkeypatch.setattr(workspace_operation.sqlite3, "connect", connect)
    with (ThreadPoolExecutor(max_workers=1, thread_name_prefix="held-writer") as writer_pool,
          ThreadPoolExecutor(max_workers=1, thread_name_prefix="fence-lock-probe") as fence_pool):
        write = writer_pool.submit(op.deliver, permission)
        try:
            assert entered.wait(10)
            fence = fence_pool.submit(op.fence)
            assert observed_busy.wait(10), "fence did not reach SQLite lock probe"
            assert observations == ["busy"]
            assert not fence.done(), "fence completed while writer held SQLite lock"
        finally:
            resume.set()
        assert write.result(timeout=10)["state"] == "DELIVERED_RECEIPT"
        result = fence.result(timeout=10)
    assert result["state"] == "DELIVERED_RECEIPT" and result["generation"] == 0
    assert result["attempts_spent"] == 1
    assert len(list(policy.output_dir.glob(".ash-*-intent.json"))) == 1


@pytest.mark.parametrize("name", ["CON", "NUL.sqlite", "state:stream", "trailing."])
def test_nonportable_state_names_refuse_before_file_creation(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], name: str,
) -> None:
    path, policy, args = host
    before = set(path.parent.iterdir())
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.create(path.with_name(name), policy, **args)
    assert set(path.parent.iterdir()) == before


def test_state_setup_failure_closes_connection(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentic_security_harness import workspace_operation

    path, policy, args = host
    WorkspaceOperation.create(path, policy, **args)
    opened: list[FailingConnection] = []
    original = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        closed = False

        def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
            if sql == "PRAGMA synchronous=FULL":
                raise sqlite3.OperationalError("injected setup failure")
            return super().execute(sql, parameters)

        def close(self) -> None:
            self.closed = True
            super().close()

    def connect(*args: Any, **kwargs: Any) -> FailingConnection:
        conn = original(*args, **kwargs, factory=FailingConnection)
        opened.append(conn)
        return conn

    monkeypatch.setattr(workspace_operation.sqlite3, "connect", connect)
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.open(path, policy, **args)
    assert len(opened) == 1 and opened[0].closed


def test_coordinator_has_no_raw_document_text(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]],
) -> None:
    path, policy, args = host
    op = WorkspaceOperation.create(path, policy, **args)
    op.deliver(op.authorize())
    assert RAW not in path.read_bytes()
    assert (policy.output_dir / "report.md").read_bytes() == RAW


@pytest.mark.parametrize("damaged", [b"", b"not a SQLite database\n"])
def test_incomplete_state_is_preserved_not_reinitialized(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], damaged: bytes,
) -> None:
    path, policy, args = host
    path.write_bytes(damaged)
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.open(path, policy, **args)
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.create(path, policy, **args)
    assert path.read_bytes() == damaged
    assert not (policy.output_dir / "report.md").exists()


@pytest.mark.parametrize("budget", [0, 33, True, 3.0, "3"])
def test_invalid_attempt_budget_has_no_state_or_effect(
    host: tuple[Path, WorkspacePolicy, dict[str, Any]], budget: object,
) -> None:
    path, policy, args = host
    with pytest.raises(WorkspaceOperationError):
        WorkspaceOperation.create(path, policy, **{**args, "max_attempts": budget})
    assert not path.exists()
    assert not (policy.output_dir / "report.md").exists()
