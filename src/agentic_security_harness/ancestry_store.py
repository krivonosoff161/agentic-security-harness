"""Opt-in, local, data-only ancestry registry.

The witness is retained separately from the SQLite database. Its integrity assumes
the trusted caller protects at least one of those stores from coordinated tampering.
Neither snapshots nor labels in this module grant permission to perform effects.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_VERSION = 1
_ZERO = "0" * 64
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_MAX_RECORDS = 4096
_MAX_PAYLOAD = 65536
_MAX_PARENTS = 32
_MAX_SCOPE = 64
_MAX_WITNESS = 4096
_LOCK_TIMEOUT_SECONDS = 10.0


class AncestryError(ValueError):
    """Invalid input or integrity failure; no positive result is available."""

    cleanup_stages: tuple[str, ...] = ()


class CheckpointConflict(AncestryError):
    """The caller's expected checkpoint is no longer current."""


class IntegrityError(AncestryError):
    """The database/witness pair cannot be trusted or recovered."""


class StorageError(IntegrityError):
    """Storage did not complete; partial state must not be treated as success.

    Only a fixed stage and numeric OS/SQLite codes are exposed. The underlying
    message can contain paths or other private data and is deliberately omitted.
    This is not an assertion that a failed commit wrote nothing.
    """

    def __init__(self, stage: str, cause: OSError | sqlite3.Error) -> None:
        self.stage = stage
        self.sqlite_errorcode = getattr(cause, "sqlite_errorcode", None)
        self.os_errno = getattr(cause, "errno", None)
        self.cleanup_stages = getattr(cause, "_ancestry_cleanup_stages", ())
        super().__init__(f"ancestry_storage_unavailable:{stage}")


def _storage_failure(stage: str, cause: OSError | sqlite3.Error) -> IntegrityError:
    if isinstance(cause, sqlite3.Error):
        code = getattr(cause, "sqlite_errorcode", None)
        # Extended SQLite codes retain the primary code in the low byte.
        # Corrupt data, invalid schema and programming errors are not an I/O
        # diagnosis. Both classes stop the caller, but remain distinguishable.
        if type(code) is not int or code & 0xff not in {
            sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_READONLY,
            sqlite3.SQLITE_IOERR, sqlite3.SQLITE_FULL, sqlite3.SQLITE_CANTOPEN,
            sqlite3.SQLITE_NOMEM, sqlite3.SQLITE_PROTOCOL, sqlite3.SQLITE_PERM,
        }:
            failure = IntegrityError("database unavailable or corrupt")
            failure.cleanup_stages = getattr(cause, "_ancestry_cleanup_stages", ())
            return failure
    return StorageError(stage, cause)


@contextmanager
def _storage_boundary(stage: str) -> Iterator[None]:
    try:
        yield
    except (OSError, sqlite3.Error) as exc:
        raise _storage_failure(stage, exc) from None


@contextmanager
def _cleanup_boundary(stage: str, primary: BaseException | None) -> Iterator[None]:
    """Keep the first failure while recording a fixed secondary cleanup stage."""
    try:
        yield
    except (OSError, sqlite3.Error) as exc:
        if primary is None:
            raise _storage_failure(stage, exc) from None
        if isinstance(primary, AncestryError):
            primary.cleanup_stages += (stage,)
        else:
            previous = getattr(primary, "_ancestry_cleanup_stages", ())
            primary._ancestry_cleanup_stages = (*previous, stage)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class AncestryRecord:
    record_id: str
    context: str
    payload: bytes
    parents: tuple[str, ...]
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        _label(self.record_id)
        _label(self.context)
        if type(self.payload) is not bytes or len(self.payload) > _MAX_PAYLOAD:
            raise AncestryError("payload must be bytes of at most 65536 bytes")
        _labels(self.parents, _MAX_PARENTS)
        _labels(self.scope, _MAX_SCOPE)


@dataclass(frozen=True)
class Checkpoint:
    context: str
    root_digest: str
    version: int
    sequence: int
    event_head: str


@dataclass(frozen=True)
class AncestrySnapshot:
    checkpoint: Checkpoint
    records: tuple[AncestryRecord, ...]
    operational_authority: Literal["none"] = "none"
    may_authorize_effects: Literal[False] = False


def _label(value: object) -> None:
    if type(value) is not str or _LABEL.fullmatch(value) is None:
        raise AncestryError("identifier/context/scope must be bounded ASCII labels")


def _labels(values: object, limit: int) -> None:
    if type(values) is not tuple or len(values) > limit:
        raise AncestryError("labels must be a bounded tuple")
    for value in values:
        _label(value)
    if tuple(sorted(set(values))) != values:
        raise AncestryError("labels must be sorted and unique")


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _record_digest(record: AncestryRecord) -> str:
    return _digest(_json({
        "context": record.context,
        "id": record.record_id,
        "parents": record.parents,
        "payload_hex": record.payload.hex(),
        "scope": record.scope,
        "version": _VERSION,
    }))


def _head(sequence: int, before: str, record_digest: str) -> str:
    return _digest(_json({"before": before, "record_digest": record_digest,
                          "sequence": sequence, "version": _VERSION}))


def _checkpoint_data(checkpoint: Checkpoint) -> dict[str, object]:
    return {"context": checkpoint.context, "event_head": checkpoint.event_head,
            "root_digest": checkpoint.root_digest, "sequence": checkpoint.sequence,
            "version": checkpoint.version}


def _parse_checkpoint(value: object) -> Checkpoint:
    if type(value) is not dict or set(value) != {
        "context", "event_head", "root_digest", "sequence", "version"
    }:
        raise IntegrityError("invalid checkpoint shape")
    try:
        cp = Checkpoint(**value)
        _label(cp.context)
        if type(cp.sequence) is not int or not 1 <= cp.sequence <= _MAX_RECORDS:
            raise ValueError
        if type(cp.version) is not int or cp.version != _VERSION:
            raise ValueError
        for digest in (cp.root_digest, cp.event_head):
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError
        return cp
    except (TypeError, ValueError) as exc:
        raise IntegrityError("invalid checkpoint value") from exc


def _fault_point(stage: str) -> None:
    """Private process-crash injection seam; production implementation is inert."""


class AncestryStore:
    """A synchronous local store. Each operation opens a fresh locked connection."""

    def __init__(self, db_path: Path, witness_path: Path, context: str,
                 root_digest: str) -> None:
        self.db_path = db_path
        self.witness_path = witness_path
        self.lock_path = db_path.with_name(db_path.name + ".lock")
        self.context = context
        self.root_digest = root_digest

    @classmethod
    def create(cls, db_path: str | Path, witness_path: str | Path, *,
               context: str, root: AncestryRecord) -> AncestryStore:
        _label(context)
        if type(root) is not AncestryRecord or root.context != context or root.parents:
            raise AncestryError("root must be a parentless record in context")
        db, witness = _paths(db_path, witness_path)
        lock = db.with_name(db.name + ".lock")
        if db.exists() or witness.exists() or lock.exists() or witness == lock:
            raise IntegrityError("store already exists; create cannot overwrite it")
        # O_EXCL makes simultaneous creators fail. An interrupted creation is
        # intentionally unrecoverable without explicit owner handling.
        digest = _record_digest(root)
        store = cls(db, witness, context, digest)
        stage = "reserve_database"
        try:
            fd = os.open(db, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
            # Reserve each path exclusively; never replace a rival's witness.
            stage = "reserve_witness"
            witness_fd = os.open(witness, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(witness_fd)
            stage = "reserve_lock"
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            with os.fdopen(lock_fd, "wb") as lock_stream:
                lock_stream.write(b"\0")
                lock_stream.flush()
                os.fsync(lock_stream.fileno())
            stage = "initialize_database"
            with store._database() as conn:
                conn.executescript("""
                    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE records (sequence INTEGER PRIMARY KEY,
                        record_id TEXT UNIQUE NOT NULL,
                        context TEXT NOT NULL, payload BLOB NOT NULL, parents TEXT NOT NULL,
                        scope TEXT NOT NULL, digest TEXT NOT NULL);
                    CREATE TABLE events (sequence INTEGER PRIMARY KEY, before_head TEXT NOT NULL,
                        record_digest TEXT NOT NULL, event_head TEXT NOT NULL);
                """)
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO meta VALUES ('context', ?)", (context,))
                conn.execute("INSERT INTO meta VALUES ('root_digest', ?)", (digest,))
                conn.execute("INSERT INTO meta VALUES ('version', ?)", (str(_VERSION),))
                after = store._insert(conn, 1, _ZERO, root)
                stage = "commit_database"
                conn.commit()
            stage = "write_witness"
            store._write_witness(Checkpoint(context, digest, _VERSION, 1, after), None)
        except (OSError, sqlite3.Error) as exc:
            # Never erase ambiguous partial state automatically.
            raise StorageError(stage, exc) from None
        return store

    @classmethod
    def open(cls, db_path: str | Path, witness_path: str | Path, *,
             context: str, root_digest: str) -> AncestryStore:
        _label(context)
        if type(root_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", root_digest) is None:
            raise AncestryError("root_digest must be a SHA-256 lowercase hex digest")
        db, witness = _paths(db_path, witness_path)
        lock = db.with_name(db.name + ".lock")
        if not db.is_file() or not witness.is_file() or not lock.is_file():
            raise IntegrityError("existing database, witness and lock are required")
        store = cls(db, witness, context, root_digest)
        store.checkpoint()
        return store

    def _connection(self) -> sqlite3.Connection:
        if not self.db_path.is_file():
            raise IntegrityError("database missing")
        conn = sqlite3.connect(f"{self.db_path.as_uri()}?mode=rw", uri=True,
                               timeout=10, isolation_level=None)
        try:
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA foreign_keys=ON")
        except BaseException as primary:
            with _cleanup_boundary("connection_setup_close", primary):
                conn.close()
            raise
        return conn

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        conn = self._connection()
        primary: BaseException | None = None
        try:
            yield conn
        except BaseException as exc:
            primary = exc
            raise
        finally:
            with _cleanup_boundary("database_close", primary):
                conn.close()

    @contextmanager
    def _writer_guard(self) -> Iterator[None]:
        """Hold one stable OS lock across DB commit and witness finalization."""
        if not self.lock_path.is_file():
            raise IntegrityError("lock file missing")
        primary: BaseException | None = None
        try:
            fd = os.open(self.lock_path, os.O_RDWR)
        except OSError as exc:
            raise StorageError("lock_open", exc) from None
        try:
            if sys.platform == "win32":
                import msvcrt
            else:
                import fcntl
            deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    if sys.platform == "win32":
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise StorageError("lock_acquire", exc) from None
                    if time.monotonic() >= deadline:
                        raise StorageError("lock_wait", exc) from None
                    time.sleep(0.01)
            body_failure: BaseException | None = None
            try:
                with _storage_boundary("lock_read"):
                    os.lseek(fd, 0, os.SEEK_SET)
                    if os.read(fd, 1) != b"\0":
                        raise IntegrityError("lock file corrupt")
                yield
            except BaseException as exc:
                body_failure = exc
                raise
            finally:
                with _cleanup_boundary("lock_release", body_failure):
                    os.lseek(fd, 0, os.SEEK_SET)
                    if sys.platform == "win32":
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_UN)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            with _cleanup_boundary("lock_close", primary):
                os.close(fd)

    def _write_witness(self, committed: Checkpoint,
                       pending: tuple[Checkpoint, Checkpoint] | None) -> None:
        body = {"committed": _checkpoint_data(committed), "pending": None if pending is None
                else {"before": _checkpoint_data(pending[0]),
                      "after": _checkpoint_data(pending[1])}, "version": _VERSION}
        data = _json(body)
        if len(data) > _MAX_WITNESS:
            raise IntegrityError("witness too large")
        fd, temp = tempfile.mkstemp(prefix=".ancestry-", dir=self.witness_path.parent)
        primary: BaseException | None = None
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.witness_path)
            if os.name != "nt":
                directory = os.open(self.witness_path.parent, os.O_RDONLY)
                directory_failure: BaseException | None = None
                try:
                    os.fsync(directory)
                except BaseException as exc:
                    directory_failure = exc
                    raise
                finally:
                    with _cleanup_boundary("witness_directory_close", directory_failure):
                        os.close(directory)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            with _cleanup_boundary("witness_temp_cleanup", primary):
                if os.path.exists(temp):
                    os.unlink(temp)

    def _read_witness(self) -> tuple[Checkpoint, tuple[Checkpoint, Checkpoint] | None]:
        try:
            with self.witness_path.open("rb") as stream:
                raw = stream.read(_MAX_WITNESS + 1)
            if len(raw) > _MAX_WITNESS:
                raise IntegrityError("witness too large")
            body = json.loads(raw)
            if raw != _json(body) or type(body) is not dict or set(body) != {
                "committed", "pending", "version"
            } or type(body["version"]) is not int or body["version"] != _VERSION:
                raise IntegrityError("invalid witness encoding")
            committed = _parse_checkpoint(body["committed"])
            pending_data = body["pending"]
            pending = None
            if pending_data is not None:
                if type(pending_data) is not dict or set(pending_data) != {"before", "after"}:
                    raise IntegrityError("invalid pending witness")
                pending = (_parse_checkpoint(pending_data["before"]),
                           _parse_checkpoint(pending_data["after"]))
            return committed, pending
        except OSError as exc:
            raise StorageError("read_witness", exc) from None
        except (UnicodeError, json.JSONDecodeError):
            raise IntegrityError("witness unavailable or corrupt") from None

    def _insert(self, conn: sqlite3.Connection, sequence: int, before: str,
                record: AncestryRecord) -> str:
        digest = _record_digest(record)
        after = _head(sequence, before, digest)
        conn.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (sequence, record.record_id, record.context, record.payload,
                      _json(record.parents).decode("ascii"),
                      _json(record.scope).decode("ascii"), digest))
        conn.execute("INSERT INTO events VALUES (?, ?, ?, ?)",
                     (sequence, before, digest, after))
        return after

    def _verify_db(self, conn: sqlite3.Connection) -> tuple[Checkpoint, tuple[AncestryRecord, ...]]:
        schema = conn.execute("SELECT type, name FROM sqlite_master "
                              "WHERE substr(name, 1, 7) != 'sqlite_'").fetchall()
        if set(schema) != {("table", "meta"), ("table", "records"),
                           ("table", "events")} or len(schema) != 3:
            raise IntegrityError("database schema differs")
        expected_columns = {
            "meta": (("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0)),
            "records": (("sequence", "INTEGER", 0, 1),
                        ("record_id", "TEXT", 1, 0),
                        ("context", "TEXT", 1, 0),
                        ("payload", "BLOB", 1, 0),
                        ("parents", "TEXT", 1, 0),
                        ("scope", "TEXT", 1, 0),
                        ("digest", "TEXT", 1, 0)),
            "events": (("sequence", "INTEGER", 0, 1),
                       ("before_head", "TEXT", 1, 0),
                       ("record_digest", "TEXT", 1, 0),
                       ("event_head", "TEXT", 1, 0)),
        }
        for table, columns in expected_columns.items():
            actual = tuple((row[1], row[2], row[3], row[5])
                           for row in conn.execute(f"PRAGMA table_info({table})"))
            if actual != columns:
                raise IntegrityError("database columns differ")
        for table, indexed_column, origin in (("meta", "key", "pk"),
                                              ("records", "record_id", "u"),
                                              ("events", None, None)):
            indexes = conn.execute(f"PRAGMA index_list({table})").fetchall()
            if len(indexes) != int(indexed_column is not None):
                raise IntegrityError("database indexes differ")
            for row in indexes:
                if row[2:] != (1, origin, 0):
                    raise IntegrityError("database index identity differs")
                # Fixed internal name checked before interpolation.
                if row[1] != f"sqlite_autoindex_{table}_1":
                    raise IntegrityError("database index name differs")
                index_columns = conn.execute(f"PRAGMA index_info({row[1]})").fetchall()
                if len(index_columns) != 1 or index_columns[0][2] != indexed_column:
                    raise IntegrityError("database index columns differ")
        wrong_types = conn.execute(
            "SELECT 1 FROM records WHERE typeof(sequence)!='integer' OR "
            "typeof(record_id)!='text' OR typeof(context)!='text' OR "
            "typeof(payload)!='blob' OR typeof(parents)!='text' OR "
            "typeof(scope)!='text' OR typeof(digest)!='text' LIMIT 1"
        ).fetchone()
        if wrong_types:
            raise IntegrityError("invalid stored column types")
        meta_rows = conn.execute("SELECT key, value FROM meta").fetchall()
        meta = dict(meta_rows)
        if len(meta_rows) != 3 or meta != {"context": self.context, "root_digest": self.root_digest,
                    "version": str(_VERSION)}:
            raise IntegrityError("database identity differs from caller")
        counts = conn.execute("SELECT COUNT(*), MAX(LENGTH(payload)), "
                              "MAX(LENGTH(record_id)), MAX(LENGTH(context)), "
                              "MAX(LENGTH(parents)), MAX(LENGTH(scope)), "
                              "MAX(LENGTH(digest)) FROM records").fetchone()
        if (counts[0] < 1 or counts[0] > _MAX_RECORDS or
                (counts[1] or 0) > _MAX_PAYLOAD or
                (counts[2] or 0) > 128 or (counts[3] or 0) > 128 or
                (counts[4] or 0) > 4200 or (counts[5] or 0) > 8400 or
                (counts[6] or 0) > 64):
            raise IntegrityError("stored record limits exceeded")
        if conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] != counts[0]:
            raise IntegrityError("record/event count invalid")
        rows = conn.execute("SELECT sequence, record_id, context, payload, parents, scope, digest "
                            "FROM records ORDER BY sequence").fetchall()
        events = conn.execute("SELECT sequence, before_head, record_digest, event_head "
                              "FROM events ORDER BY sequence").fetchall()
        if not rows or len(rows) != len(events) or len(rows) > _MAX_RECORDS:
            raise IntegrityError("record/event count invalid")
        known: dict[str, AncestryRecord] = {}
        records: list[AncestryRecord] = []
        before = _ZERO
        for sequence, (row, event) in enumerate(zip(rows, events, strict=True), 1):
            index, record_id, context, payload, parents_raw, scope_raw, digest = row
            if (type(record_id) is not str or type(context) is not str or
                    type(payload) is not bytes or type(parents_raw) is not str or
                    type(scope_raw) is not str or type(digest) is not str):
                raise IntegrityError("invalid stored column types")
            try:
                parents = tuple(json.loads(parents_raw))
                scope = tuple(json.loads(scope_raw))
                record = AncestryRecord(record_id, context, payload, parents, scope)
            except (TypeError, ValueError, UnicodeError) as exc:
                raise IntegrityError("invalid stored record") from exc
            if (index != sequence or record_id in known or context != self.context or
                    parents_raw != _json(parents).decode("ascii") or
                    scope_raw != _json(scope).decode("ascii") or
                    digest != _record_digest(record)):
                raise IntegrityError("record identity or encoding mismatch")
            if sequence == 1:
                if parents or digest != self.root_digest:
                    raise IntegrityError("root mismatch")
            elif not parents:
                raise IntegrityError("additional root forbidden")
            for parent_id in parents:
                parent = known.get(parent_id)
                if parent is None or not set(scope).issubset(parent.scope):
                    raise IntegrityError("missing parent or scope expansion")
            after = _head(sequence, before, digest)
            if event != (sequence, before, digest, after):
                raise IntegrityError("event chain mismatch")
            known[record_id] = record
            records.append(record)
            before = after
        checkpoint = Checkpoint(self.context, self.root_digest, _VERSION,
                                len(rows), before)
        return checkpoint, tuple(records)

    def _locked_state(
        self, conn: sqlite3.Connection
    ) -> tuple[Checkpoint, tuple[AncestryRecord, ...]]:
        db_cp, records = self._verify_db(conn)
        committed, pending = self._read_witness()
        if committed.context != self.context or committed.root_digest != self.root_digest:
            raise IntegrityError("witness identity differs from caller")
        if pending is None:
            if db_cp != committed:
                raise IntegrityError("database and witness checkpoints differ")
        else:
            before, after = pending
            if (before != committed or after.context != self.context or
                    after.root_digest != self.root_digest or
                    after.version != _VERSION or
                    after.sequence != before.sequence + 1):
                raise IntegrityError("invalid pending transition")
            if db_cp == after:
                prior_head = _ZERO if len(records) == 1 else conn.execute(
                    "SELECT event_head FROM events WHERE sequence=?",
                    (db_cp.sequence - 1,)).fetchone()[0]
                if before.sequence != db_cp.sequence - 1 or before.event_head != prior_head:
                    raise IntegrityError("pending before does not bind database prefix")
            with _storage_boundary("recover_witness"):
                if db_cp == before:
                    self._write_witness(before, None)
                elif db_cp == after:
                    self._write_witness(after, None)
                else:
                    raise IntegrityError("pending transition cannot be recovered")
        return db_cp, records

    def _state(self) -> tuple[Checkpoint, tuple[AncestryRecord, ...]]:
        stage = "state_open"
        try:
            with self._writer_guard():
                with self._database() as conn:
                    stage = "state_begin"
                    conn.execute("BEGIN IMMEDIATE")
                    stage = "state_read"
                    state = self._locked_state(conn)
                    stage = "state_commit"
                    conn.commit()
                    stage = "state_close"
                    return state
        except (OSError, sqlite3.Error) as exc:
            raise _storage_failure(stage, exc) from None

    def checkpoint(self) -> Checkpoint:
        """Return the fully verified current checkpoint, recovering a pending write."""
        return self._state()[0]

    def append(self, record: AncestryRecord, *, expected: Checkpoint) -> Checkpoint:
        """CAS append; raises CheckpointConflict, AncestryError, or IntegrityError."""
        if type(record) is not AncestryRecord or type(expected) is not Checkpoint:
            raise AncestryError("record and expected checkpoint required")
        if record.context != self.context or not record.parents:
            raise AncestryError("child needs context and at least one parent")
        stage = "append_open"
        try:
            with self._writer_guard(), self._database() as conn:
                stage = "append_begin"
                conn.execute("BEGIN IMMEDIATE")
                stage = "append_read"
                before, records = self._locked_state(conn)
                if before != expected:
                    raise CheckpointConflict("stale expected checkpoint")
                if len(records) >= _MAX_RECORDS:
                    raise AncestryError("record limit reached")
                known = {item.record_id: item for item in records}
                if record.record_id in known:
                    raise AncestryError("record id already admitted")
                for parent_id in record.parents:
                    parent = known.get(parent_id)
                    if parent is None:
                        raise AncestryError("missing parent")
                    if not set(record.scope).issubset(parent.scope):
                        raise AncestryError("child scope expands parent scope")
                digest = _record_digest(record)
                after = Checkpoint(self.context, self.root_digest, _VERSION,
                                   before.sequence + 1,
                                   _head(before.sequence + 1, before.event_head, digest))
                stage = "append_prepare_witness"
                self._write_witness(before, (before, after))
                _fault_point("after_prepare")
                stage = "append_insert"
                actual = self._insert(conn, after.sequence, before.event_head, record)
                if actual != after.event_head:
                    raise IntegrityError("event commitment mismatch")
                stage = "append_commit"
                conn.commit()
                _fault_point("after_db_commit")
                # The append itself has committed. Reacquire the DB writer lock
                # and verify every persisted row before reporting success.
                stage = "append_verify"
                conn.execute("BEGIN IMMEDIATE")
                verified, _ = self._verify_db(conn)
                if verified != after:
                    raise IntegrityError("committed append failed full verification")
                stage = "append_finalize_witness"
                self._write_witness(after, None)
                _fault_point("after_finalize")
                stage = "append_finalize_commit"
                conn.commit()
                stage = "append_close"
                return after
        except (OSError, sqlite3.Error) as exc:
            raise _storage_failure(stage, exc) from None

    def snapshot(self, *, expected: Checkpoint) -> AncestrySnapshot:
        """Return immutable data only after exact checkpoint and full scan."""
        if type(expected) is not Checkpoint:
            raise AncestryError("expected checkpoint required")
        checkpoint, records = self._state()
        if checkpoint != expected:
            raise CheckpointConflict("stale expected checkpoint")
        return AncestrySnapshot(checkpoint, records)

    def verify_candidate(self, target: str, records: tuple[AncestryRecord, ...], *,
                         expected: Checkpoint) -> bool:
        """Accept only the exact, ordered ancestor closure from this snapshot.

        This is data admission, never action authorization. Invalid candidates
        return False; a stale checkpoint or damaged store raises.
        """
        _label(target)
        snapshot = self.snapshot(expected=expected)
        if type(records) is not tuple or any(type(item) is not AncestryRecord for item in records):
            return False
        known = {record.record_id: record for record in snapshot.records}
        if target not in known:
            return False
        closure: set[str] = set()
        pending = [target]
        while pending:
            item = pending.pop()
            if item not in closure:
                closure.add(item)
                pending.extend(known[item].parents)
        exact = tuple(record for record in snapshot.records if record.record_id in closure)
        return records == exact


def _paths(db_path: str | Path, witness_path: str | Path) -> tuple[Path, Path]:
    db, witness = Path(db_path).absolute(), Path(witness_path).absolute()
    if db == witness or not db.parent.is_dir() or not witness.parent.is_dir():
        raise AncestryError("distinct paths with existing parent directories required")
    return db, witness
