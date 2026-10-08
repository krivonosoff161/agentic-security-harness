"""Host-configured, create-only text output for an application's agent loop.

The host owns configuration, paths, classification and this process. Model output
is only a proposal. This is a file-writing tool boundary, not an OS sandbox, a
semantic classifier, or authentication of a remote producer. Receipts omit text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, cast

from agentic_security_harness._fixture_files import _checked_directory, _identity, _not_reparse
from agentic_security_harness._workspace_files import WorkspaceFiles
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.runtime_guard_foundation import (
    ActionEnvelope,
    CapabilityGrant,
    ConsentReceipt,
    GuardContext,
    GuardDataClass,
    GuardDecision,
    RuntimeDataEnvelope,
    evaluate_action,
)

_ALIAS = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_DATA_CLASSES = frozenset({"public", "synthetic", "sanitized", "restricted", "private"})
_VERSION = "ash.workspace-write.v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_file(path: Path, limit: int) -> bytes:
    """Bounded read of an explicitly host-selected ordinary file; no link following."""
    path = path.absolute()
    root_identity = _identity(_checked_directory(path.parent))
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not _not_reparse(before) or before.st_nlink != 1:
        raise ValueError("expected a unique regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if _identity(info) != _identity(before) or info.st_size > limit:
            raise ValueError("file identity or size rejected")
        raw = bytearray()
        while len(raw) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(fd)
        if (len(raw) > limit or len(raw) != info.st_size
                or (after.st_size, after.st_mtime_ns) != (info.st_size, info.st_mtime_ns)
                or _identity(path.lstat()) != _identity(info)
                or _identity(_checked_directory(path.parent)) != root_identity):
            raise ValueError("file changed during read")
        return bytes(raw)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class WorkspacePolicy:
    """Immutable host policy, never populated from a model's proposal.

    Paths in a JSON config are relative to that config, not the process cwd.
    Classification is a host declaration, not an inference about text contents.
    """

    output_dir: Path
    outputs: tuple[tuple[str, str], ...]
    max_bytes: int = 65536
    max_proposals: int = 8
    data_class: str = "private"
    source_restrictions_sha256: str | None = None
    source_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.output_dir, Path) or not self.output_dir.is_absolute():
            raise ValueError("output_dir must be an absolute Path")
        object.__setattr__(self, "output_dir", Path(os.path.abspath(self.output_dir)))
        if (type(self.outputs) is not tuple or not 1 <= len(self.outputs) <= 32
                or any(type(pair) is not tuple or len(pair) != 2 for pair in self.outputs)):
            raise ValueError("outputs must be 1..32 immutable alias/filename pairs")
        if len(dict(self.outputs)) != len(self.outputs):
            raise ValueError("duplicate output alias")
        for alias, filename in self.outputs:
            if type(alias) is not str or not _ALIAS.fullmatch(alias):
                raise ValueError("invalid output alias")
            if type(filename) is not str or filename.lower().startswith(".ash-"):
                raise ValueError("invalid or reserved output filename")
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 65536:
            raise ValueError("max_bytes must be 1..65536")
        if type(self.max_proposals) is not int or not 1 <= self.max_proposals <= 32:
            raise ValueError("max_proposals must be 1..32")
        if self.data_class not in _DATA_CLASSES:
            raise ValueError("unsupported host data classification")
        if self.source_restrictions_sha256 is not None and (
            type(self.source_restrictions_sha256) is not str
            or re.fullmatch(r"[a-f0-9]{64}", self.source_restrictions_sha256) is None
        ):
            raise ValueError("invalid source restrictions binding")
        if self.source_expires_at is not None:
            if (type(self.source_expires_at) is not datetime
                    or self.source_expires_at.tzinfo is None
                    or self.source_expires_at.utcoffset() is None
                    or self.source_restrictions_sha256 is None):
                raise ValueError("bound aware source expiry required")
            object.__setattr__(self, "source_expires_at", self.source_expires_at.astimezone(UTC))

    @classmethod
    def load(cls, path: Path) -> WorkspacePolicy:
        path = path.absolute()
        value = _json(_read_file(path, 16384), 16384)
        if (set(value) - {"schema_version", "output_dir", "outputs", "max_bytes",
                          "max_proposals", "data_class"}
                or value.get("schema_version") != _VERSION
                or type(value.get("output_dir")) is not str
                or type(value.get("outputs")) is not dict):
            raise ValueError("invalid workspace policy")
        root = Path(value["output_dir"])
        if not root.is_absolute():
            root = path.parent / root
        return cls(root.absolute(), tuple(value["outputs"].items()),
                   value.get("max_bytes", 65536), value.get("max_proposals", 8),
                   value.get("data_class", "private"))

    @property
    def sha256(self) -> str:
        record = {"schema_version": _VERSION, "output_dir": str(self.output_dir),
                  "outputs": dict(self.outputs), "max_bytes": self.max_bytes,
                  "max_proposals": self.max_proposals, "data_class": self.data_class}
        # Preserve legacy policy digests; a restricted job binds the additional
        # host-owned admission contract into its existing effect receipt.
        if self.source_restrictions_sha256 is not None:
            record["source_restrictions_sha256"] = self.source_restrictions_sha256
        if self.source_expires_at is not None:
            record["source_expires_at"] = self.source_expires_at.isoformat()
        return _sha(_canonical(record))

    def check(self) -> None:
        """Read-only validation; never creates a directory or output file."""
        with WorkspaceFiles.open(self.output_dir, dict(self.outputs), self.max_bytes):
            pass


def text_proposal_schema() -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False,
            "required": ["operation", "artifact", "content"],
            "properties": {"operation": {"type": "string", "const": "write_text"},
                           "artifact": {"type": "string"}, "content": {"type": "string"}}}


def _decide(policy: WorkspacePolicy, alias: str, content: bytes, call_id: str,
            session_id: str) -> GuardDecision:
    """Bind host-configured authority to these bytes and this exact destination."""
    now = datetime.now(UTC)
    created, expires = now - timedelta(seconds=1), now + timedelta(seconds=60)
    digest, policy_sha = _sha(content), policy.sha256
    envelope = RuntimeDataEnvelope(
        data_class=cast(GuardDataClass, policy.data_class),
        allowed_recipients=[], allowed_purpose=["local_text_output"],
        can_store=True, can_forward=False, ttl_seconds=60, requires_confirmation=False,
        classification_source="trusted_application_configuration", classification_mutable=False,
        classification_receipt_sha256=_sha(f"class:{session_id}:{call_id}:{digest}".encode()),
        classified_content_sha256=digest, classifier_policy_sha256=policy_sha,
        classifier_trust_root_id="workspace-host", classification_checked_at=created,
        classification_expires_at=expires, classification_verification="verified",
    )
    action = ActionEnvelope(
        action_id=call_id, actor_id="workspace-agent", session_id_hash=_sha(session_id.encode()),
        sponsor_id_hash=_sha(b"workspace-host"), call_chain_digest=_sha(call_id.encode()),
        action_type="filesystem_write", target=f"local://workspace/{policy_sha}/{alias}",
        purpose="local_text_output", requested_scopes=("workspace:create",),
        data_envelope=envelope, content_sha256=digest, policy_sha256=policy_sha,
        created_at=created, expires_at=expires,
    )
    binding = action.action_digest()
    allowed = alias in dict(policy.outputs)
    capability = CapabilityGrant(
        grant_id=f"grant:{call_id}", issuer="workspace-host", subject="workspace-agent",
        scopes=("workspace:create",), target_patterns=(action.target,), purpose="local_text_output",
        issued_at=created, expires_at=expires, policy_sha256=policy_sha,
        authority_receipt_sha256=_sha(f"grant:{binding}".encode()),
        authorized_action_digest=binding,
        issuer_trust_root_id="workspace-host", nonce_sha256=_sha(f"grant:{call_id}".encode()),
        verification="verified",
    )
    consent = ConsentReceipt(
        receipt_id=f"consent:{call_id}", action_id=call_id, actor_id="workspace-agent",
        action_digest=binding, policy_sha256=policy_sha,
        receipt_sha256=_sha(f"consent:{binding}".encode()), issuer_trust_root_id="workspace-host",
        nonce_sha256=_sha(f"consent:{call_id}".encode()), issued_at=created, expires_at=expires,
        approved=True, verification="verified",
    )
    return evaluate_action(action, GuardContext(
        evaluated_at=now, policy_version=_VERSION, active_policy_sha256=policy_sha,
        capabilities=(capability,) if allowed else (),
        consent_receipts=(consent,) if allowed else (), evidence_previous_hash="0" * 64,
        trusted_authority_root_ids=("workspace-host",),
        trusted_consent_root_ids=("workspace-host",),
        trusted_classifier_root_ids=("workspace-host",),
        trusted_handoff_root_ids=("unused-handoff",),
        trusted_budget_root_ids=("unused-budget",),
        trusted_tool_registry_root_ids=("unused-tool",),
        trusted_provider_policy_root_ids=("unused-provider",),
        authenticated_classification_bindings=(envelope.classification_binding_digest(),),
    ))


class GuardedWorkspace:
    """A trusted host's create-only tool. Pass ``submit`` to an agent, not this object.

    Repeated use of an artifact is denied, including after restarting while the
    file exists. An I/O failure stops this instance; a partial file is preserved.
    The caller must inspect it, not blindly retry an ambiguous operation.
    """

    def __init__(self, policy: WorkspacePolicy) -> None:
        self.policy = policy
        self.session_id = uuid.uuid4().hex
        self._opened_policy = policy
        self._opened_policy_sha256 = policy.sha256
        self._opened_session_id = self.session_id
        self._files = WorkspaceFiles.open(policy.output_dir, dict(policy.outputs), policy.max_bytes)
        self._audit_names = {
            f"{phase}{index}": f".ash-{self.session_id}-{index:02d}-{phase}.json"
            for index in range(1, policy.max_proposals + 1) for phase in ("intent", "result")
        }
        try:
            self._audit = WorkspaceFiles.open(policy.output_dir, self._audit_names, 16384)
        except BaseException:
            self._files.close()
            raise
        self._lock = threading.RLock()
        self._attempts = 0
        self._closed = False
        self._fenced = False
        self._failed = False

    def bind_text_tool(self, artifact: str) -> Callable[[str], dict[str, Any]]:
        """Give an agent a text-only tool for one host-selected output alias."""
        with self._lock:
            if type(artifact) is not str or artifact not in dict(self._opened_policy.outputs):
                raise ValueError("artifact is not in host policy")
            if self._closed or self._failed:
                raise ValueError("workspace is unavailable")
            if not self._identity_matches_open_files():
                self._failed = True
                raise ValueError("workspace_identity_changed")

        def write_text(content: str) -> dict[str, Any]:
            # Non-text values are recorded as rejected proposals without serializing
            # an arbitrary object or letting it supply paths or policy fields.
            try:
                proposal = (_canonical({"operation": "write_text", "artifact": artifact,
                                        "content": content}) if type(content) is str
                            and len(content) <= self._opened_policy.max_bytes else b"")
            except UnicodeError:
                proposal = b""
            return self.submit(proposal)

        return write_text

    def _identity_matches_open_files(self) -> bool:
        return (self.policy is self._opened_policy
                and self.policy.sha256 == self._opened_policy_sha256
                and self.session_id == self._opened_session_id)

    def submit(self, proposal: bytes) -> dict[str, Any]:
        """Validate one untrusted JSON proposal; return a content-free tool result."""
        with self._lock:
            started = time.perf_counter()
            self._policy_ms = 0.0
            try:
                result = self._submit(proposal)
                total = (time.perf_counter() - started) * 1000
                # Observation only: not part of the authorization/receipt contract.
                return {**result, "timing_ms": {"boundary": total,
                        "policy": self._policy_ms, "storage": max(0.0, total - self._policy_ms)}}
            except BaseException:
                # An interrupt can arrive after an effect and before its receipt.
                # Preserve evidence and never allow continuation on this instance.
                self._failed = True
                raise

    def _submit(self, proposal: bytes) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._failed:
                return {"applied": False, "reason": "session_unavailable", "effect": "none"}
            if not self._identity_matches_open_files():
                self._failed = True
                return {"applied": False, "reason": "workspace_identity_changed", "effect": "none"}
            if self._attempts >= self.policy.max_proposals:
                return {"applied": False, "reason": "proposal_budget_exhausted", "effect": "none"}
            self._attempts += 1
            index = self._attempts
            call_id = f"{self.session_id}:{index}"
            result: dict[str, Any] = {
                "schema_version": _VERSION, "session_id": self.session_id,
                "call_id": call_id, "policy_sha256": self.policy.sha256,
                "proposal_sha256": _sha(proposal) if type(proposal) is bytes
                and len(proposal) <= self.policy.max_bytes * 6 + 1024 else None,
                "applied": False, "effect": "none", "reason": "proposal_rejected",
                "receipt_complete": False,
            }
            content = b""
            policy_started = time.perf_counter()
            try:
                value = _json(proposal, self.policy.max_bytes * 6 + 1024)
                if (set(value) != {"operation", "artifact", "content"}
                        or value["operation"] != "write_text"
                        or type(value["artifact"]) is not str
                        or not _ALIAS.fullmatch(value["artifact"])
                        or type(value["content"]) is not str):
                    raise ValueError("proposal shape rejected")
                content = value["content"].encode("utf-8")
                if not 0 < len(content) <= self.policy.max_bytes or b"\x00" in content:
                    raise ValueError("text content rejected")
                alias = value["artifact"]
                decision = _decide(self.policy, alias, content, call_id, self.session_id)
                result.update(artifact=alias, bytes=len(content), content_sha256=_sha(content),
                              decision=decision.model_dump(mode="json"), reason="guard_rejected")
                may_write = decision.disposition == "allow"
            except (ValueError, TypeError, UnicodeError, RecursionError):
                may_write = False
            self._policy_ms = (time.perf_counter() - policy_started) * 1000
            try:
                # Durable intent precedes every attempted effect, including denials.
                self._audit.write_once(f"intent{index}", _canonical({
                    **result, "phase": "intent", "write_authorized": may_write,
                }) + b"\n")
            except (OSError, ValueError):
                self._failed = True
                return {**result, "reason": "intent_storage_unavailable"}
            # Durable intent can be slow. Check again at the last userspace
            # checkpoint before exclusive create; this is not an atomic OS TTL.
            if (may_write and self.policy.source_expires_at is not None
                    and datetime.now(UTC) >= self.policy.source_expires_at):
                may_write = False
                result["reason"] = "source_expired"
            if may_write:
                try:
                    written = self._files.write_once(result["artifact"], content)
                    if self._files.readback_sha(result["artifact"]) != written:
                        raise ValueError("output readback differs from proposed bytes")
                    result.update(applied=True, effect="created", reason="write_completed",
                                  output_sha256=written["sha256"])
                except FileExistsError:
                    self._failed = True
                    result.update(reason="target_already_exists", effect="none")
                except (OSError, ValueError):
                    self._failed = True
                    result.update(reason="output_unavailable", effect="unknown_inspect_output")
            result["receipt_complete"] = True
            result["receipt"] = self._audit_names[f"result{index}"]
            try:
                self._audit.write_once(f"result{index}", _canonical(result) + b"\n")
            except (OSError, ValueError):
                self._failed = True
                result.update(reason="result_storage_unavailable", receipt_complete=False)
            return result

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._files.close()
                finally:
                    self._audit.close()
                self._fenced = True

    def closure_record(self) -> dict[str, Any]:
        """Describe a successfully closed instance without reopening or persisting it."""
        with self._lock:
            if (not self._closed or not self._fenced
                    or not self._identity_matches_open_files()
                    or type(self._attempts) is not int
                    or not 0 <= self._attempts <= self._opened_policy.max_proposals):
                raise ValueError("workspace closure is not fenced")
            return {
                "schema_version": "ash.workspace-session-closed.v1",
                "session_id": self._opened_session_id,
                "policy_sha256": self._opened_policy_sha256,
                "attempts": self._attempts,
                "closed": True,
                "replay_allowed": False,
            }

    def __enter__(self) -> GuardedWorkspace:
        return self

    def __exit__(self, exc_type: type[BaseException] | None,
                 exc_value: BaseException | None, traceback: TracebackType | None) -> None:
        self.close()


def verify_workspace_output(policy: WorkspacePolicy, receipt: Path) -> dict[str, Any]:
    """Read-only check of one successful receipt against its configured output.

    This checks consistency, not remote authenticity, chronology or text accuracy.
    Receipt-supplied paths are never opened.
    """
    try:
        policy.check()
        record = _json(_read_file(receipt, 16384), 16384)
        alias = record["artifact"]
        decision = GuardDecision.model_validate(record["decision"])
        if (record["schema_version"] != _VERSION or record["policy_sha256"] != policy.sha256
                or record["applied"] is not True or record["receipt_complete"] is not True
                or record["effect"] != "created" or record["reason"] != "write_completed"
                or decision.disposition != "allow"
                or decision.evidence.policy_sha256 != policy.sha256
                or decision.evidence.content_sha256 != record["content_sha256"]
                or type(record["bytes"]) is not int
                or type(alias) is not str or alias not in dict(policy.outputs)):
            raise ValueError("invalid successful-write receipt")
        sid, call_id = record["session_id"], record["call_id"]
        if (type(sid) is not str or not re.fullmatch(r"[a-f0-9]{32}", sid)
                or type(call_id) is not str
                or not re.fullmatch(re.escape(sid) + r":[1-9][0-9]?", call_id)):
            raise ValueError("invalid receipt identity")
        index = int(call_id.split(":")[1])
        name = f".ash-{sid}-{index:02d}-result.json"
        if (index > policy.max_proposals or record["receipt"] != name
                or Path(os.path.abspath(receipt)) != policy.output_dir / name):
            raise ValueError("receipt location or budget mismatch")
        intent = _json(_read_file(policy.output_dir / f".ash-{sid}-{index:02d}-intent.json",
                                 16384), 16384)
        if (intent.get("phase") != "intent" or intent.get("write_authorized") is not True
                or any(intent.get(key) != record[key] for key in
                       ("artifact", "bytes", "content_sha256", "decision", "call_id",
                        "session_id", "policy_sha256", "proposal_sha256"))):
            raise ValueError("intent/result mismatch")
        raw = _read_file(policy.output_dir / dict(policy.outputs)[alias], policy.max_bytes)
        if (_sha(raw) != record["output_sha256"] or _sha(raw) != record["content_sha256"]
                or len(raw) != record["bytes"]):
            raise ValueError("output differs from receipt")
        return {"integrity_ok": True, "artifact": alias, "bytes": len(raw), "sha256": _sha(raw),
                "meaning_checked": False, "origin_authenticated": False}
    except (OSError, ValueError, KeyError, TypeError):
        return {"integrity_ok": False, "reason": "workspace_output_invalid_or_unavailable"}
