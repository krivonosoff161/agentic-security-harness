"""Host-owned one-action authority coordinator over the installed Harness.

Expose submit(content) to the agent, not this object's host configuration or its
filesystem. Signed decisions are verified, never converted from narrative text.
The OS/host/state store and enrolled public key remain trusted. This is not an
OS sandbox, rollback witness, generic distributed transaction or semantic judge.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from agentic_security_harness.workspace_admission import WorkspaceAdmission
from agentic_security_harness.workspace_operation import WorkspaceOperation, WorkspaceOperationError
from agentic_security_harness.workspace_writer import WorkspacePolicy

from .protocol import build_request, canonical, request_digest, verify_decision

MAX_CONTROL_EVENTS = 128
TERMINAL = frozenset({"DELIVERED_RECEIPT", "RECONCILED_POSTCONDITION", "FENCED_ABSENT"})
STATUSES = TERMINAL | {"PENDING_APPROVAL", "APPROVED", "EXECUTING", "UNKNOWN", "INVALIDATED"}


class AuthorityError(ValueError):
    pass


class AuthorityBusy(AuthorityError):
    """No approval/revocation acknowledgement: another serialized owner is busy."""


def _json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _directory(path):
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise AuthorityError("invalid_host_directory")
    for part in (path, *path.parents):
        info = part.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or part.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise AuthorityError("linked_or_invalid_host_directory")


def _regular(path):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or path.is_symlink()
        or getattr(info, "st_file_attributes", 0) & 0x400
        or info.st_size > 2_097_152
    ):
        raise AuthorityError("invalid_host_store")
    return info.st_dev, info.st_ino


class ActionGate:
    """One host-bound exact document, one execution attempt, no implicit retry.

    BEGIN is the outer durable EXECUTING commit, not the first filesystem byte.
    A revoke before that commit prevents execution. A revoke that loses the
    serialization race returns too_late_or_in_flight, never cancellation success.
    The expiry bounds admission at BEGIN; it does not promise completion by that
    wall-clock instant. The installed writer separately enforces source expiry.
    """

    def __init__(
        self,
        root,
        workspace,
        *,
        content,
        operation_id,
        artifact,
        public_key,
        key_id,
        app_id,
        task_id,
        initiator,
        expires_at,
        dependencies=None,
        admission=None,
        clock=None,
    ):
        _directory(root.parent)
        if (
            type(workspace) is not WorkspacePolicy
            or type(content) is not str
            or type(public_key) is not bytes
            or len(public_key) != 32
            or (admission is not None and type(admission) is not WorkspaceAdmission)
        ):
            raise AuthorityError("invalid_host_configuration")
        workspace.check()
        if (
            root == workspace.output_dir
            or workspace.output_dir in root.parents
            or root in workspace.output_dir.parents
        ):
            raise AuthorityError("state_and_output_must_be_disjoint")
        try:
            raw = content.encode("utf-8")
        except UnicodeError as exc:
            raise AuthorityError("invalid_content") from exc
        if not 0 < len(raw) <= workspace.max_bytes or b"\0" in raw:
            raise AuthorityError("invalid_content")
        if artifact not in dict(workspace.outputs):
            raise AuthorityError("unknown_host_artifact")
        if (
            workspace.source_expires_at is not None
            and expires_at > workspace.source_expires_at.timestamp()
        ):
            raise AuthorityError("approval_exceeds_source_lifetime")
        info = workspace.output_dir.stat()
        self.binding = {
            "app_id": app_id,
            "task_id": task_id,
            "operation_id": operation_id,
            "initiator": initiator,
            "action": "write_text",
            "artifact": artifact,
            "policy_sha256": workspace.sha256,
            "source_admission_sha256": admission.binding_sha256 if admission is not None else None,
            "root_path": str(workspace.output_dir),
            "root_device": str(info.st_dev),
            "root_inode": str(info.st_ino),
            "filename": dict(workspace.outputs)[artifact],
            "payload_sha256": _sha(raw),
            "payload_length": len(raw),
            "dependencies": dict(dependencies or {}),
            "operator_key_fingerprint": _sha(public_key),
        }
        # Full schema validation, independent of any persisted bytes.
        self._binding_json = canonical(
            build_request(
                self.binding, epoch=0, challenge="0" * 64, expires_at=expires_at, key_id=key_id
            )
        ).decode("ascii")
        self.root, self.workspace, self.content = root, workspace, content
        self.public_key, self.key_id, self.expires_at = public_key, key_id, expires_at
        self.operation_id, self.artifact, self.admission = operation_id, artifact, admission
        self.clock = clock or (lambda: int(time.time()))
        self._identities = {}

    @classmethod
    def create(cls, root, workspace, **configuration):
        gate = cls(root, workspace, **configuration)
        if root.exists() or root.is_symlink():
            raise AuthorityError("state_already_exists_use_new_directory")
        root.mkdir(mode=0o700)
        for name in ("serialization.sqlite", "authority.sqlite"):
            fd = os.open(root / name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
            con = sqlite3.connect(root / name)
            try:
                con.execute("PRAGMA synchronous=FULL")
                con.execute(
                    "CREATE TABLE identity (binding TEXT NOT NULL, sealed INTEGER NOT NULL)"
                )
                con.execute("INSERT INTO identity VALUES(?,0)", (gate._binding_json,))
                if name == "authority.sqlite":
                    con.execute(
                        "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), "
                        "value TEXT NOT NULL)"
                    )
                    state = {
                        "epoch": 0,
                        "challenge": secrets.token_hex(32),
                        "status": "PENDING_APPROVAL",
                        "approval": None,
                        "floor": 0,
                        "controls": 0,
                    }
                    con.execute("INSERT INTO state VALUES(1,?)", (_json(state),))
                    con.execute(
                        "CREATE TABLE events (seq INTEGER PRIMARY KEY, "
                        "kind TEXT NOT NULL, detail TEXT NOT NULL)"
                    )
                    con.execute(
                        "CREATE TABLE denials (reason TEXT PRIMARY KEY, count INTEGER NOT NULL)"
                    )
                con.commit()
            finally:
                con.close()
        # If this fails, unsealed state is retained. Never auto-adopt partial setup.
        WorkspaceOperation.create(
            root / "operation.sqlite",
            workspace,
            operation_id=gate.operation_id,
            artifact=gate.artifact,
            content=gate.content,
            max_attempts=1,
            admission=gate.admission,
        )
        for name in ("serialization.sqlite", "authority.sqlite"):
            con = sqlite3.connect(root / name)
            try:
                con.execute("PRAGMA synchronous=FULL")
                con.execute("UPDATE identity SET sealed=1")
                con.commit()
            finally:
                con.close()
        return cls.open(root, workspace, **configuration)

    @classmethod
    def open(cls, root, workspace, **configuration):
        gate = cls(root, workspace, **configuration)
        _directory(root)
        gate._identities = {
            name: _regular(root / name)
            for name in ("serialization.sqlite", "authority.sqlite", "operation.sqlite")
        }
        with gate._exclusive():
            gate._load()
            gate._operation()
        return gate

    def _connect(self, name):
        _directory(self.root)
        if _regular(self.root / name) != self._identities[name]:
            raise AuthorityError("host_store_replaced")
        con = sqlite3.connect((self.root / name).as_uri() + "?mode=rw", uri=True, timeout=3)
        try:
            con.execute("PRAGMA synchronous=FULL")
            if con.execute("SELECT binding,sealed FROM identity").fetchall() != [
                (self._binding_json, 1)
            ]:
                raise AuthorityError("unsealed_or_different_setup_use_new_directory")
        except BaseException:
            con.close()
            raise
        return con

    @contextmanager
    def _exclusive(self):
        con = self._connect("serialization.sqlite")
        try:
            try:
                con.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower():
                    raise AuthorityBusy("busy_no_decision_acknowledged") from exc
                raise
            yield
        finally:
            con.rollback()
            con.close()

    def _load(self):
        con = self._connect("authority.sqlite")
        try:
            row = con.execute("SELECT value FROM state WHERE id=1").fetchone()
            if row is None or len(row[0]) > 32768:
                raise AuthorityError("invalid_state")
            state = json.loads(row[0])
            if (
                type(state) is not dict
                or set(state) != {"epoch", "challenge", "status", "approval", "floor", "controls"}
                or state["status"] not in STATUSES
                or any(
                    type(state[k]) is not int or not 0 <= state[k] < 2**53
                    for k in ("epoch", "floor", "controls")
                )
                or state["controls"] > MAX_CONTROL_EVENTS
            ):
                raise AuthorityError("invalid_state")
            self._request(state)
            count, maximum = con.execute(
                "SELECT count(*),coalesce(max(seq),0) FROM events"
            ).fetchone()
            if count != state["controls"] or maximum != count:
                raise AuthorityError("control_history_inconsistent")
            if (
                state["status"] == "APPROVED"
                and state["approval"] is None
                or state["approval"] is not None
                and (
                    type(state["approval"]) is not dict
                    or set(state["approval"]) != {"message", "signature"}
                )
            ):
                raise AuthorityError("invalid_approval_state")
            return state
        finally:
            con.close()

    def _request(self, state):
        return build_request(
            self.binding,
            epoch=state["epoch"],
            challenge=state["challenge"],
            expires_at=self.expires_at,
            key_id=self.key_id,
        )

    def _now(self, state):
        now = self.clock()
        if type(now) is not int or not state["floor"] <= now < 2**53:
            raise AuthorityError("clock_regression")
        return now

    def _save(self, state, *, kind=None, detail=None, reserve=0, denial=None):
        if kind is not None and state["controls"] + 1 + reserve > MAX_CONTROL_EVENTS:
            raise AuthorityError("control_capacity_before_effect")
        if denial is not None and denial not in {
            "invalid_content",
            "object_changed",
            "not_approved",
            "expired",
            "already_consumed",
            "capacity",
        }:
            raise AuthorityError("invalid_denial_reason")
        con = self._connect("authority.sqlite")
        try:
            with con:
                if kind is not None:
                    state["controls"] += 1
                    con.execute(
                        "INSERT INTO events VALUES(?,?,?)",
                        (state["controls"], kind, _json(detail or {})),
                    )
                con.execute("UPDATE state SET value=? WHERE id=1", (_json(state),))
                if denial is not None:
                    con.execute(
                        "INSERT INTO denials VALUES(?,1) ON CONFLICT(reason) DO UPDATE SET "
                        "count=min(count+1,9223372036854775806)",
                        (denial,),
                    )
        finally:
            con.close()

    def _operation(self):
        if _regular(self.root / "operation.sqlite") != self._identities["operation.sqlite"]:
            raise AuthorityError("operation_store_replaced")
        return WorkspaceOperation.open(
            self.root / "operation.sqlite",
            self.workspace,
            operation_id=self.operation_id,
            artifact=self.artifact,
            content=self.content,
            max_attempts=1,
            admission=self.admission,
        )

    def request(self):
        with self._exclusive():
            return self._request(self._load())

    def apply_decision(self, message, signature):
        """Authenticated operator ingress; agent-generated approval text is invalid."""
        with self._exclusive():
            state = self._load()
            now = self._now(state)
            verified = verify_decision(
                self._request(state), message, signature, self.public_key, now=now
            )
            if state["status"] in TERMINAL | {"EXECUTING", "UNKNOWN", "INVALIDATED"}:
                return {
                    "accepted": False,
                    "reason": "too_late_or_in_flight",
                    "status": state["status"],
                }
            state["floor"] = now
            if verified["decision"] == "revoke":
                state.update(
                    epoch=state["epoch"] + 1,
                    challenge=secrets.token_hex(32),
                    status="PENDING_APPROVAL",
                    approval=None,
                )
                self._save(
                    state, kind="revoke", detail={"decision_sha256": _sha(canonical(verified))}
                )
                return {"accepted": True, "reason": "revoked_before_begin", "epoch": state["epoch"]}
            if state["status"] == "APPROVED":
                self._save(state)
                return {"accepted": True, "reason": "already_approved", "epoch": state["epoch"]}
            state.update(
                status="APPROVED",
                approval={
                    "message": verified,
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            )
            self._save(
                state,
                kind="approve",
                detail={"decision_sha256": _sha(canonical(verified))},
                reserve=3,
            )
            return {"accepted": True, "reason": "approved_exact_action", "epoch": state["epoch"]}

    def invalidate(self):
        """Trusted host reports a changed required context; new root/approval needed."""
        with self._exclusive():
            state = self._load()
            if state["status"] in TERMINAL | {"EXECUTING", "UNKNOWN"}:
                return {"accepted": False, "reason": "too_late_or_in_flight"}
            if state["status"] != "INVALIDATED":
                state.update(
                    status="INVALIDATED",
                    approval=None,
                    epoch=state["epoch"] + 1,
                    challenge=secrets.token_hex(32),
                    floor=self._now(state),
                )
                self._save(state, kind="invalidate")
            return {"accepted": True, "reason": "context_invalidated_new_request_required"}

    def submit(self, content):
        """The only agent-facing surface. No paths, keys, approval flags or retries."""
        with self._exclusive():
            state = self._load()
            now = self._now(state)
            state["floor"] = now
            reason = None
            try:
                raw = content.encode("utf-8") if type(content) is str else b""
            except UnicodeError:
                raw = b""
            if not 0 < len(raw) <= self.workspace.max_bytes:
                reason = "invalid_content"
            elif _sha(raw) != self.binding["payload_sha256"]:
                reason = "object_changed"
            elif state["status"] in TERMINAL | {"EXECUTING", "UNKNOWN"}:
                reason = "already_consumed"
            elif state["status"] != "APPROVED":
                reason = "not_approved"
            elif now >= self.expires_at:
                reason = "expired"
            elif state["controls"] + 3 > MAX_CONTROL_EVENTS:
                reason = "capacity"
            if reason:
                self._save(state, denial=reason)
                return {"applied": False, "reason": reason, "status": state["status"]}
            approval = state["approval"]
            verify_decision(
                self._request(state),
                approval["message"],
                base64.b64decode(approval["signature"], validate=True),
                self.public_key,
                now=now,
            )
            # Linearization point: irrevocable admission of ONE attempt. Host
            # serialization is held until the supported effect/recovery result.
            state["status"] = "EXECUTING"
            self._save(
                state,
                kind="begin",
                detail={"request_sha256": request_digest(self._request(state))},
                reserve=2,
            )
            try:
                operation = self._operation()
                permission = operation.authorize()
                result = operation.deliver(permission)
            except (WorkspaceOperationError, AuthorityError, sqlite3.Error, OSError):
                result = {"state": "UNKNOWN", "reason": "writer_unavailable_recovery_required"}
            if result["state"] not in TERMINAL | {"UNKNOWN"}:
                result = {"state": "UNKNOWN", "reason": "unexpected_writer_outcome"}
            state["status"] = result["state"]
            self._save(
                state,
                kind="outcome",
                detail={"state": result["state"]},
                reserve=1 if result["state"] == "UNKNOWN" else 0,
            )
            return {
                "applied": result["state"] == "DELIVERED_RECEIPT",
                "outcome": result,
                "status": state["status"],
                "reason": result["reason"],
            }

    def recover(self):
        """No delivery calls. Verify/readback/fence; never replay an uncertain effect."""
        with self._exclusive():
            state = self._load()
            state["floor"] = self._now(state)
            recorded = state["status"]
            if recorded not in TERMINAL | {"EXECUTING", "UNKNOWN"}:
                self._save(state)
                return {
                    "state": recorded,
                    "current_verified": False,
                    "reason": "no_started_attempt",
                }
            if recorded == "FENCED_ABSENT":
                # The supported writer is already fenced and its sole attempt
                # consumed. Repeated status must not consume more generations.
                try:
                    self.workspace.check()
                    _directory(self.workspace.output_dir)
                    info = self.workspace.output_dir.stat()
                    if (
                        str(info.st_dev) != self.binding["root_device"]
                        or str(info.st_ino) != self.binding["root_inode"]
                    ):
                        raise AuthorityError("workspace_identity_changed")
                    try:
                        (self.workspace.output_dir / self.binding["filename"]).lstat()
                    except FileNotFoundError:
                        absent = True
                    else:
                        absent = False
                except (OSError, ValueError):
                    absent = False
                self._save(state)
                return {
                    "state": "FENCED_ABSENT" if absent else "UNKNOWN",
                    "recorded_outcome": recorded,
                    "current_verified": absent,
                    "reason": "verified_fenced_absence"
                    if absent
                    else "fenced_target_changed_or_unavailable",
                }
            try:
                result = self._operation().fence()
            except (WorkspaceOperationError, AuthorityError, OSError, sqlite3.Error):
                result = {"state": "UNKNOWN", "reason": "readback_unavailable"}
            if (
                result.get("state") == "UNKNOWN"
                and result.get("reason") == "no_prior_spend"
                and result.get("attempts_spent") == 0
            ):
                # No permission existed; shared outer serialization rules out
                # an old live executor, and fence checked actual target absence.
                result = {"state": "FENCED_ABSENT", "reason": "no_permission_issued_target_absent"}
            if recorded in TERMINAL:
                self._save(state)
                return {
                    **result,
                    "recorded_outcome": recorded,
                    "current_verified": result["state"] == recorded,
                }
            if result["state"] != recorded:
                state["status"] = result["state"]
                self._save(
                    state,
                    kind="reconcile",
                    detail={"state": result["state"]},
                    reserve=1 if result["state"] == "UNKNOWN" else 0,
                )
            else:
                self._save(state)
            return {
                **result,
                "recorded_outcome": recorded,
                "current_verified": result["state"] in TERMINAL,
            }

    def status(self):
        """Historical state only. Use recover() for an actual current postcondition."""
        with self._exclusive():
            state = self._load()
            return {
                "status": state["status"],
                "epoch": state["epoch"],
                "control_events": state["controls"],
                "current_postcondition_verified": False,
                "request_sha256": request_digest(self._request(state)),
            }
