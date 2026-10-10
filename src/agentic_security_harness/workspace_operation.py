"""Durable, host-bound coordination for one create-only workspace text output.

The operator owns the policy, SQLite state, and caller inputs. This coordinates
supported writers; it is not an OS sandbox or producer authentication. File and
SQLite commits are not atomic. Exact bytes recovered after an interruption are
labelled as a postcondition, never as proof that a former call returned.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_security_harness._fixture_files import _checked_directory, _identity, _not_reparse
from agentic_security_harness._workspace_files import _validate_filename
from agentic_security_harness.workspace_writer import (
    GuardedWorkspace,
    WorkspacePolicy,
    _decide,
    _read_file,
    verify_workspace_output,
)

_VERSION = "ash.workspace-operation.v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_RECEIPT = re.compile(r"\.ash-[a-f0-9]{32}-[0-9]{2}-result\.json\Z", re.ASCII)
_MAX_DB_BYTES = 2 * 1024 * 1024
_SCHEMA = """
CREATE TABLE operation (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    binding_json TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 32),
    initial_absent INTEGER NOT NULL CHECK (initial_absent = 1),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 32),
    outcome TEXT,
    receipt_name TEXT,
    receipt_sha256 TEXT
);
CREATE TABLE permissions (
    ordinal INTEGER PRIMARY KEY CHECK (ordinal BETWEEN 1 AND 32),
    nonce TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 32),
    binding_sha256 TEXT NOT NULL,
    consumed INTEGER NOT NULL CHECK (consumed = 1),
    attempted INTEGER NOT NULL CHECK (attempted IN (0, 1))
);
"""
_TABLES = frozenset({"operation", "permissions"})


class WorkspaceOperationError(ValueError):
    """Content-free, stable refusal reason; raw SQLite/path errors are suppressed."""


@dataclass(frozen=True)
class WorkspacePermission:
    ordinal: int
    nonce: str
    generation: int
    binding_sha256: str


@dataclass(frozen=True)
class _Binding:
    actor: str
    operation_id: str
    action: str
    payload_sha256: str
    payload_length: int
    root_path: str
    root_device: int
    root_inode: int
    filename: str
    artifact: str
    policy_sha256: str
    scope: str
    key: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _regular_unique(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not _not_reparse(info) or info.st_nlink != 1:
        raise WorkspaceOperationError("state_file_invalid")
    if info.st_size > _MAX_DB_BYTES:
        raise WorkspaceOperationError("state_file_oversize")
    return _identity(info)


class WorkspaceOperation:
    """One trusted operator-owned, create-only logical operation.

    ``create`` and ``open`` require the same host-supplied content and policy.
    No database value is used to choose a new target or widen a budget.
    """

    def __init__(self, state_path: Path, policy: WorkspacePolicy, binding: _Binding,
                 content: bytes, max_attempts: int, state_identity: tuple[int, int]):
        self._state_path = state_path
        self._policy = policy
        self._binding = binding
        self._binding_json = _canonical(asdict(binding)).decode("utf-8")
        self._binding_sha256 = _sha(self._binding_json.encode("utf-8"))
        self._content = content
        self._max_attempts = max_attempts
        self._state_identity = state_identity

    @classmethod
    def _inputs(cls, state_path: Path, policy: WorkspacePolicy, operation_id: str,
                artifact: str, content: str, max_attempts: int
                ) -> tuple[Path, _Binding, bytes]:
        if (not isinstance(state_path, Path) or not state_path.is_absolute()
                or type(policy) is not WorkspacePolicy or type(operation_id) is not str
                or _ID.fullmatch(operation_id) is None or type(artifact) is not str
                or artifact not in dict(policy.outputs) or type(content) is not str
                or type(max_attempts) is not int or not 1 <= max_attempts <= 32):
            raise WorkspaceOperationError("invalid_host_input")
        try:
            _validate_filename(state_path.name)
        except ValueError as exc:
            raise WorkspaceOperationError("invalid_host_input") from exc
        state_path = Path(os.path.abspath(state_path))
        try:
            _validate_filename(state_path.name)
        except ValueError as exc:
            raise WorkspaceOperationError("invalid_host_input") from exc
        try:
            raw = content.encode("utf-8")
        except UnicodeError as exc:
            raise WorkspaceOperationError("invalid_host_input") from exc
        if not 0 < len(raw) <= policy.max_bytes or b"\x00" in raw:
            raise WorkspaceOperationError("invalid_host_input")
        try:
            policy.check()
            root = policy.output_dir
            root_info = _checked_directory(root)
            state_parent = state_path.parent
            _checked_directory(state_parent)
            if state_path == root or root in state_path.parents:
                raise WorkspaceOperationError("state_inside_workspace")
        except (OSError, ValueError) as exc:
            if isinstance(exc, WorkspaceOperationError):
                raise
            raise WorkspaceOperationError("path_or_policy_unavailable") from exc
        binding = _Binding(
            actor="workspace-agent", operation_id=operation_id, action="write_text",
            payload_sha256=_sha(raw), payload_length=len(raw), root_path=str(root),
            root_device=root_info.st_dev, root_inode=root_info.st_ino,
            filename=dict(policy.outputs)[artifact], artifact=artifact,
            policy_sha256=policy.sha256, scope="workspace:create",
            key=_sha(_canonical([operation_id, str(root), artifact])),
        )
        return state_path, binding, raw

    @classmethod
    def create(cls, state_path: Path, policy: WorkspacePolicy, *, operation_id: str,
               artifact: str, content: str, max_attempts: int = 3) -> WorkspaceOperation:
        path, binding, raw = cls._inputs(state_path, policy, operation_id, artifact,
                                         content, max_attempts)
        if path.exists() or path.is_symlink():
            raise WorkspaceOperationError("state_already_exists")
        if cls._file_state_for(binding, policy) != "ABSENT":
            raise WorkspaceOperationError("new_operation_requires_absence")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
            os.close(fd)
            identity = _regular_unique(path)
            instance = cls(path, policy, binding, raw, max_attempts, identity)
            with instance._connection() as connection:
                connection.executescript(_SCHEMA)
                connection.execute("INSERT INTO operation VALUES (1,?,?,?,1,0,NULL,NULL,NULL)",
                                   (instance._binding_json, instance._binding_sha256,
                                    max_attempts))
            return instance
        except (OSError, sqlite3.Error, ValueError) as exc:
            # An exclusively created but failed state is retained for inspection.
            raise WorkspaceOperationError("state_create_unavailable") from exc

    @classmethod
    def open(cls, state_path: Path, policy: WorkspacePolicy, *, operation_id: str,
             artifact: str, content: str, max_attempts: int = 3) -> WorkspaceOperation:
        path, binding, raw = cls._inputs(state_path, policy, operation_id, artifact,
                                         content, max_attempts)
        try:
            identity = _regular_unique(path)
            instance = cls(path, policy, binding, raw, max_attempts, identity)
            with instance._connection() as connection:
                instance._validate(connection)
            return instance
        except (OSError, sqlite3.Error) as exc:
            raise WorkspaceOperationError("state_open_unavailable") from exc

    @staticmethod
    def _file_state_for(binding: _Binding, policy: WorkspacePolicy) -> str:
        try:
            root_info = _checked_directory(policy.output_dir)
            if ((root_info.st_dev, root_info.st_ino) !=
                    (binding.root_device, binding.root_inode)
                    or str(policy.output_dir) != binding.root_path):
                return "UNKNOWN"
        except (OSError, ValueError):
            return "UNKNOWN"
        try:
            raw = _read_file(policy.output_dir / binding.filename, policy.max_bytes)
        except FileNotFoundError:
            return "ABSENT"
        except (OSError, ValueError):
            return "UNKNOWN"
        if len(raw) == binding.payload_length and _sha(raw) == binding.payload_sha256:
            return "EXACT"
        return "MISMATCH"

    def _file_state(self) -> str:
        return self._file_state_for(self._binding, self._policy)

    def _receipt_bound(self, record: object) -> bool:
        return (type(record) is dict
                and record.get("artifact") == self._binding.artifact
                and record.get("content_sha256") == self._binding.payload_sha256
                and type(record.get("bytes")) is int
                and record["bytes"] == self._binding.payload_length
                and record.get("policy_sha256") == self._binding.policy_sha256
                and record.get("output_sha256") == self._binding.payload_sha256)

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            _checked_directory(self._state_path.parent)
            if _regular_unique(self._state_path) != self._state_identity:
                raise WorkspaceOperationError("state_identity_changed")
            connection = sqlite3.connect(f"{self._state_path.as_uri()}?mode=rw",
                                         uri=True, isolation_level=None, timeout=3)
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_DB_BYTES)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA journal_mode=DELETE")
            if _regular_unique(self._state_path) != self._state_identity:
                raise WorkspaceOperationError("state_identity_changed")
            return connection
        except BaseException as exc:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass  # Preserve the primary setup failure.
            if isinstance(exc, WorkspaceOperationError):
                raise
            if isinstance(exc, (OSError, sqlite3.Error, ValueError)):
                raise WorkspaceOperationError("state_storage_unavailable") from exc
            raise

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _validate(self, connection: sqlite3.Connection) -> tuple[int, int, str | None,
                                                                  str | None, str | None]:
        try:
            tables = connection.execute(
                "SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            expected_sql = {
                name: re.sub(r"\s+", " ", statement.strip())
                for statement in _SCHEMA.split(";") if (name := (
                    "operation" if "CREATE TABLE operation" in statement else
                    "permissions" if "CREATE TABLE permissions" in statement else ""))
            }
            if (len(tables) != len(_TABLES)
                    or {row[0] for row in tables} != _TABLES
                    or any(row[1] != "table" or re.sub(r"\s+", " ", row[2]) !=
                           expected_sql[row[0]] for row in tables)):
                raise WorkspaceOperationError("state_schema_invalid")
            expected_columns = {
                "operation": ("id", "binding_json", "binding_sha256", "max_attempts",
                              "initial_absent", "generation", "outcome", "receipt_name",
                              "receipt_sha256"),
                "permissions": ("ordinal", "nonce", "generation", "binding_sha256",
                                "consumed", "attempted"),
            }
            for table, names in expected_columns.items():
                actual = tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
                if actual != names:
                    raise WorkspaceOperationError("state_schema_invalid")
            rows = connection.execute("SELECT * FROM operation").fetchall()
            if len(rows) != 1:
                raise WorkspaceOperationError("state_binding_invalid")
            row = rows[0]
            if (row[:5] != (1, self._binding_json, self._binding_sha256,
                            self._max_attempts, 1)
                    or type(row[5]) is not int or not 0 <= row[5] <= 32):
                raise WorkspaceOperationError("state_binding_invalid")
            permissions = connection.execute(
                "SELECT ordinal,nonce,generation,binding_sha256,consumed,attempted "
                "FROM permissions ORDER BY ordinal"
            ).fetchall()
            if len(permissions) > self._max_attempts:
                raise WorkspaceOperationError("state_budget_invalid")
            for ordinal, item in enumerate(permissions, 1):
                nonce = _sha(f"{self._binding_sha256}:{ordinal}".encode())
                if (item != (ordinal, nonce, item[2], self._binding_sha256, 1, item[5])
                        or type(item[2]) is not int or not 0 <= item[2] <= row[5]
                        or item[5] not in (0, 1)):
                    raise WorkspaceOperationError("state_permission_invalid")
            outcome, receipt_name, receipt_sha = row[6:9]
            if outcome is None:
                if receipt_name is not None or receipt_sha is not None:
                    raise WorkspaceOperationError("state_outcome_invalid")
            elif outcome == "DELIVERED_RECEIPT":
                if (not permissions or type(receipt_name) is not str
                        or _RECEIPT.fullmatch(receipt_name) is None
                        or type(receipt_sha) is not str
                        or re.fullmatch(r"[a-f0-9]{64}", receipt_sha) is None):
                    raise WorkspaceOperationError("state_outcome_invalid")
            elif outcome == "RECONCILED_POSTCONDITION":
                if not permissions or receipt_name is not None or receipt_sha is not None:
                    raise WorkspaceOperationError("state_outcome_invalid")
            else:
                raise WorkspaceOperationError("state_outcome_invalid")
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise WorkspaceOperationError("state_integrity_invalid")
            return len(permissions), row[5], outcome, receipt_name, receipt_sha
        except sqlite3.Error as exc:
            raise WorkspaceOperationError("state_storage_unavailable") from exc

    def _verified_outcome(self, outcome: str, receipt_name: str | None,
                          receipt_sha: str | None) -> dict[str, Any]:
        if self._file_state() != "EXACT":
            raise WorkspaceOperationError("stored_outcome_file_mismatch")
        result = {"state": outcome, "reason": "verified_retained_outcome"}
        if outcome == "DELIVERED_RECEIPT":
            if receipt_name is None or receipt_sha is None:
                raise WorkspaceOperationError("state_outcome_invalid")
            try:
                raw = _read_file(self._policy.output_dir / receipt_name, 16384)
                if _sha(raw) != receipt_sha or not verify_workspace_output(
                        self._policy, self._policy.output_dir / receipt_name)["integrity_ok"]:
                    raise WorkspaceOperationError("stored_receipt_invalid")
                record = json.loads(raw)
                if not self._receipt_bound(record):
                    raise WorkspaceOperationError("stored_receipt_invalid")
                result["writer_receipt"] = record
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                if isinstance(exc, WorkspaceOperationError):
                    raise
                raise WorkspaceOperationError("stored_receipt_invalid") from exc
        return result

    @staticmethod
    def _result(state: str, spent: int, generation: int, reason: str,
                writer_receipt: dict[str, Any] | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {"state": state, "attempts_spent": spent,
                                  "generation": generation, "reason": reason}
        if writer_receipt is not None:
            result["writer_receipt"] = writer_receipt
        return result

    def authorize(self) -> WorkspacePermission:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                spent, generation, outcome, _, _ = self._validate(connection)
                if outcome is not None:
                    raise WorkspaceOperationError("operation_completed")
                if spent >= self._max_attempts:
                    raise WorkspaceOperationError("budget_exhausted")
                if spent:
                    previous = connection.execute(
                        "SELECT generation FROM permissions WHERE ordinal=?", (spent,)
                    ).fetchone()
                    if previous is None or generation <= previous[0]:
                        raise WorkspaceOperationError("fence_required")
                if self._file_state() != "ABSENT":
                    raise WorkspaceOperationError("target_not_absent")
                session = self._binding_sha256[:32]
                try:
                    decision = _decide(self._policy, self._binding.artifact, self._content,
                                       f"{session}:{spent + 1}", session)
                except (TypeError, ValueError) as exc:
                    raise WorkspaceOperationError("fresh_policy_denied") from exc
                if (decision.disposition != "allow"
                        or (self._policy.source_expires_at is not None
                            and datetime.now(UTC) >= self._policy.source_expires_at)):
                    raise WorkspaceOperationError("fresh_policy_denied")
                ordinal = spent + 1
                nonce = _sha(f"{self._binding_sha256}:{ordinal}".encode())
                connection.execute("INSERT INTO permissions VALUES (?,?,?,?,1,0)",
                                   (ordinal, nonce, generation, self._binding_sha256))
                connection.commit()  # Durable spend precedes any writer call.
                return WorkspacePermission(ordinal, nonce, generation,
                                           self._binding_sha256)
        except sqlite3.Error as exc:
            raise WorkspaceOperationError("state_storage_unavailable") from exc

    def _permission_row(self, connection: sqlite3.Connection,
                        permission: WorkspacePermission) -> tuple[int, int]:
        if type(permission) is not WorkspacePermission:
            raise WorkspaceOperationError("invalid_permission")
        if (type(permission.ordinal) is not int or not 1 <= permission.ordinal <= 32
                or type(permission.generation) is not int
                or not 0 <= permission.generation <= 32
                or type(permission.nonce) is not str
                or re.fullmatch(r"[a-f0-9]{64}", permission.nonce) is None
                or type(permission.binding_sha256) is not str
                or re.fullmatch(r"[a-f0-9]{64}", permission.binding_sha256) is None):
            raise WorkspaceOperationError("invalid_permission")
        row = connection.execute(
            "SELECT generation,attempted FROM permissions WHERE ordinal=? AND nonce=? "
            "AND binding_sha256=? AND consumed=1",
            (permission.ordinal, permission.nonce, permission.binding_sha256),
        ).fetchone()
        if (row is None or row[0] != permission.generation
                or permission.binding_sha256 != self._binding_sha256):
            raise WorkspaceOperationError("permission_not_consumed")
        return row[0], row[1]

    def deliver(self, permission: WorkspacePermission) -> dict[str, Any]:
        try:
            # This committed reservation survives a process crash even if the
            # subsequent file/SQL transaction rolls back. An outcome-less replay
            # of the same grant refuses; fence+fresh policy may still progress.
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                spent, generation, outcome, receipt_name, receipt_sha = self._validate(connection)
                perm_generation, attempted = self._permission_row(connection, permission)
                if perm_generation != generation:
                    raise WorkspaceOperationError("stale_generation")
                if outcome is not None:
                    verified = self._verified_outcome(outcome, receipt_name, receipt_sha)
                    return self._result(outcome, spent, generation,
                                        "verified_retained_outcome", verified.get("writer_receipt"))
                if attempted:
                    raise WorkspaceOperationError("outcome_less_replay")
                connection.execute("UPDATE permissions SET attempted=1 WHERE ordinal=?",
                                   (permission.ordinal,))
                connection.commit()
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                spent, generation, outcome, receipt_name, receipt_sha = self._validate(connection)
                self._permission_row(connection, permission)
                if permission.generation != generation:
                    raise WorkspaceOperationError("stale_generation")
                if outcome is not None:
                    verified = self._verified_outcome(outcome, receipt_name, receipt_sha)
                    return self._result(outcome, spent, generation,
                                        "verified_retained_outcome", verified.get("writer_receipt"))
                state = self._file_state()
                if state == "EXACT":
                    connection.execute(
                        "UPDATE operation SET outcome='RECONCILED_POSTCONDITION' WHERE id=1"
                    )
                    return self._result("RECONCILED_POSTCONDITION", spent, generation,
                                        "exact_retained_postcondition_not_original_receipt")
                if state != "ABSENT":
                    return self._result("UNKNOWN", spent, generation, "target_uncertain")
                proposal = _canonical({
                    "operation": "write_text", "artifact": self._binding.artifact,
                    "content": self._content.decode("utf-8"),
                })
                with GuardedWorkspace(self._policy) as writer:
                    returned = writer.submit(proposal)
                if self._file_state() != "EXACT":
                    return self._result("UNKNOWN", spent, generation, "writer_effect_uncertain")
                if (returned.get("applied") is not True
                        or returned.get("reason") != "write_completed"
                        or returned.get("receipt_complete") is not True
                        or returned.get("output_sha256") != self._binding.payload_sha256):
                    return self._result("UNKNOWN", spent, generation,
                                        "writer_receipt_uncertain")
                receipt_name = returned.get("receipt")
                if type(receipt_name) is not str or _RECEIPT.fullmatch(receipt_name) is None:
                    return self._result("UNKNOWN", spent, generation, "writer_receipt_uncertain")
                path = self._policy.output_dir / receipt_name
                raw = _read_file(path, 16384)
                persisted = dict(returned)
                if "timing_ms" not in persisted:
                    return self._result("UNKNOWN", spent, generation, "writer_receipt_uncertain")
                del persisted["timing_ms"]
                if (json.loads(raw) != persisted
                        or not self._receipt_bound(persisted)
                        or not verify_workspace_output(self._policy, path)["integrity_ok"]):
                    return self._result("UNKNOWN", spent, generation, "writer_receipt_uncertain")
                receipt_sha = _sha(raw)
                connection.execute(
                    "UPDATE operation SET outcome='DELIVERED_RECEIPT',receipt_name=?,"
                    "receipt_sha256=? WHERE id=1", (receipt_name, receipt_sha)
                )
                return self._result("DELIVERED_RECEIPT", spent, generation,
                                    "writer_receipt_durable", persisted)
        except (OSError, sqlite3.Error, ValueError, UnicodeError) as exc:
            if isinstance(exc, WorkspaceOperationError):
                raise
            raise WorkspaceOperationError("delivery_unavailable") from exc

    def reconcile(self) -> dict[str, Any]:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                spent, generation, outcome, receipt_name, receipt_sha = self._validate(connection)
                if outcome is not None:
                    verified = self._verified_outcome(outcome, receipt_name, receipt_sha)
                    return self._result(outcome, spent, generation,
                                        "verified_retained_outcome", verified.get("writer_receipt"))
                if spent == 0:
                    return self._result("UNKNOWN", spent, generation, "no_prior_spend")
                if self._file_state() == "EXACT":
                    connection.execute(
                        "UPDATE operation SET outcome='RECONCILED_POSTCONDITION' WHERE id=1"
                    )
                    return self._result("RECONCILED_POSTCONDITION", spent, generation,
                                        "exact_retained_postcondition_not_original_receipt")
                return self._result("UNKNOWN", spent, generation, "target_not_exact")
        except sqlite3.Error as exc:
            raise WorkspaceOperationError("state_storage_unavailable") from exc

    def fence(self) -> dict[str, Any]:
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                spent, generation, outcome, receipt_name, receipt_sha = self._validate(connection)
                if outcome is not None:
                    verified = self._verified_outcome(outcome, receipt_name, receipt_sha)
                    return self._result(outcome, spent, generation,
                                        "verified_retained_outcome", verified.get("writer_receipt"))
                state = self._file_state()
                if state == "EXACT" and spent:
                    connection.execute(
                        "UPDATE operation SET outcome='RECONCILED_POSTCONDITION' WHERE id=1"
                    )
                    return self._result("RECONCILED_POSTCONDITION", spent, generation,
                                        "exact_retained_postcondition_not_original_receipt")
                if state != "ABSENT":
                    return self._result("UNKNOWN", spent, generation, "target_uncertain")
                if spent == 0:
                    return self._result("UNKNOWN", spent, generation, "no_prior_spend")
                if generation >= 32:
                    return self._result("UNKNOWN", spent, generation, "generation_exhausted")
                generation += 1
                connection.execute("UPDATE operation SET generation=? WHERE id=1", (generation,))
                return self._result("FENCED_ABSENT", spent, generation,
                                    "serialized_absence_fence")
        except sqlite3.Error as exc:
            raise WorkspaceOperationError("state_storage_unavailable") from exc
