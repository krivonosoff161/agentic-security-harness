"""Local-only Runtime Gateway development contour.

The gateway is deliberately useful without becoming an ambient execution surface:

* the only executable tools are two deterministic, synthetic built-ins;
* unknown, denied, and approval-required calls fail closed before dispatch;
* request bodies are bounded and never written to the audit ledger;
* the audit ledger retains hashes and closed reason codes, not prompts, arguments,
  responses, credentials, headers, or machine paths;
* the host listener is fixed to IPv4 loopback; an explicit synthetic-container mode may
  bind inside a container when the host publication remains loopback-only.

This is a local product increment, not a production firewall or an authorization service.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import importlib
import json
import os
import secrets
import socket
import stat
import threading
import time
import tomllib
import uuid
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.safe_io import is_link_or_reparse

SHA256_PATTERN = r"^[0-9a-f]{64}$"
SAFE_TOKEN_PATTERN = r"^[a-z0-9][a-z0-9._:-]{0,127}$"
MAX_AUDIT_RECORDS = 100_000
MAX_AUDIT_BYTES = 96 * 1024 * 1024
ZERO_SHA256 = "0" * 64
MCP_PROTOCOL_VERSION = "2026-07-28"
MCP_META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
MCP_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
MCP_META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
MCP_REQUIRED_META_KEYS = {
    MCP_META_PROTOCOL_VERSION,
    MCP_META_CLIENT_INFO,
    MCP_META_CLIENT_CAPABILITIES,
}

GatewayDisposition = Literal["allow", "deny", "require_approval"]
GatewayProtocol = Literal[
    "openai_compatible",
    "openai_responses",
    "anthropic_messages",
    "google_interactions",
    "mcp",
]


class GatewayContractError(ValueError):
    """Raised when untrusted gateway input violates a closed contract."""


class GatewayToolRuleV1(BaseModel):
    """One exact-name tool policy rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    disposition: GatewayDisposition
    effect: Literal["pure", "external", "process"]
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)


class GatewayPolicyV1(BaseModel):
    """Closed policy used by the local gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayPolicy.v1"] = (
        "AgenticSecurityHarnessGatewayPolicy.v1"
    )
    policy_id: Literal["ash-local-synthetic-default-v1"] = "ash-local-synthetic-default-v1"
    rules: tuple[GatewayToolRuleV1, ...]
    default_disposition: Literal["deny"] = "deny"

    @model_validator(mode="after")
    def _closed_rules(self) -> GatewayPolicyV1:
        names = [rule.tool_name for rule in self.rules]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("gateway rules must use sorted unique tool names")
        expected = {
            "external.send": ("require_approval", "external", "owner_approval_required"),
            "synthetic.lookup": ("allow", "pure", "synthetic_tool_allowed"),
            "synthetic.sha256": ("allow", "pure", "synthetic_tool_allowed"),
            "system.shell": ("deny", "process", "process_execution_denied"),
        }
        actual = {
            rule.tool_name: (rule.disposition, rule.effect, rule.reason_code)
            for rule in self.rules
        }
        if actual != expected:
            raise ValueError("gateway policy must match the closed local synthetic ruleset")
        return self

    def sha256(self) -> str:
        return _sha256_json(self.model_dump(mode="json"))


class GatewayToolCallV1(BaseModel):
    """Untrusted call envelope; raw arguments stay in memory only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    protocol: GatewayProtocol
    tool_name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    arguments: dict[str, Any] = Field(default_factory=dict, repr=False)

    @model_validator(mode="after")
    def _bounded_arguments(self) -> GatewayToolCallV1:
        _validate_json_value(self.arguments, depth=0)
        encoded = _canonical_json_bytes(self.arguments)
        if len(encoded) > 16_384:
            raise ValueError("tool arguments exceed the 16384-byte gateway limit")
        return self

    def arguments_sha256(self) -> str:
        return _sha256_domain("ash-gateway-tool-arguments-v1", self.arguments)


class GatewayDecisionV1(BaseModel):
    """Safe pre-execution policy result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayDecision.v1"] = (
        "AgenticSecurityHarnessGatewayDecision.v1"
    )
    call_id_sha256: str = Field(pattern=SHA256_PATTERN)
    tool_name_sha256: str = Field(pattern=SHA256_PATTERN)
    arguments_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition: GatewayDisposition
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    effect: Literal["pure", "external", "process", "unknown"]
    execution_permitted: bool

    @model_validator(mode="after")
    def _coherent(self) -> GatewayDecisionV1:
        if self.execution_permitted != (self.disposition == "allow"):
            raise ValueError("only allow decisions may permit execution")
        return self

    def approval_request(self) -> GatewayApprovalRequestV1:
        """Derive a privacy-minimized request without granting execution authority."""

        if self.disposition != "require_approval" or self.effect == "pure":
            raise GatewayContractError("only approval-required decisions create requests")
        return GatewayApprovalRequestV1(
            call_id_sha256=self.call_id_sha256,
            tool_name_sha256=self.tool_name_sha256,
            arguments_sha256=self.arguments_sha256,
            policy_sha256=self.policy_sha256,
            effect=self.effect,
            reason_code=self.reason_code,
        )


class GatewayApprovalRequestV1(BaseModel):
    """Safe pending-approval identity; not a grant, token, or consent receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayApprovalRequest.v1"] = (
        "AgenticSecurityHarnessGatewayApprovalRequest.v1"
    )
    status: Literal["pending_non_executable"] = "pending_non_executable"
    call_id_sha256: str = Field(pattern=SHA256_PATTERN)
    tool_name_sha256: str = Field(pattern=SHA256_PATTERN)
    arguments_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    effect: Literal["external", "process", "unknown"]
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    execution_permitted: Literal[False] = False
    grant_endpoint_available: Literal[False] = False

    def sha256(self) -> str:
        return _sha256_domain(
            "ash-gateway-approval-request-v1", self.model_dump(mode="json")
        )


class GatewayPolicySnapshotV1(BaseModel):
    """Dashboard-safe description of the exact active local policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayPolicySnapshot.v1"] = (
        "AgenticSecurityHarnessGatewayPolicySnapshot.v1"
    )
    policy_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    default_disposition: Literal["deny"] = "deny"
    rules: tuple[GatewayToolRuleV1, ...]
    approval_grant_available: Literal[False] = False


class GatewayAuditRecordV1(BaseModel):
    """Privacy-minimized hash-chain audit record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayAudit.v1"] = (
        "AgenticSecurityHarnessGatewayAudit.v1"
    )
    sequence: int = Field(ge=1)
    occurred_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    request_id_commitment: str = Field(pattern=SHA256_PATTERN)
    protocol: GatewayProtocol
    operation: Literal["chat_completion", "mcp_discover", "mcp_tools_list", "tool_call"]
    subject_commitment: str = Field(pattern=SHA256_PATTERN)
    payload_commitment: str = Field(pattern=SHA256_PATTERN)
    privacy_key_id_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition: GatewayDisposition
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    previous_entry_sha256: str = Field(pattern=SHA256_PATTERN)
    entry_sha256: str = Field(pattern=SHA256_PATTERN)

    def unsigned_payload(self) -> dict[str, Any]:
        value = self.model_dump(mode="json")
        value.pop("entry_sha256")
        return value

    def verify(self) -> None:
        expected = _sha256_domain("ash-gateway-audit-entry-v1", self.unsigned_payload())
        if self.entry_sha256 != expected:
            raise GatewayContractError("gateway audit entry digest mismatch")


class GatewayAuditSnapshotV1(BaseModel):
    """Dashboard-safe aggregate; no request-level payloads are exposed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayAuditSnapshot.v1"] = (
        "AgenticSecurityHarnessGatewayAuditSnapshot.v1"
    )
    records: int = Field(ge=0)
    allow: int = Field(ge=0)
    deny: int = Field(ge=0)
    require_approval: int = Field(ge=0)
    head_sha256: str = Field(pattern=SHA256_PATTERN)
    chain_valid: Literal[True] = True


class GatewayConfigV1(BaseModel):
    """Closed operator configuration for the local synthetic contour."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessGatewayConfig.v1"] = (
        "AgenticSecurityHarnessGatewayConfig.v1"
    )
    host: Literal["127.0.0.1", "0.0.0.0"] = "127.0.0.1"  # nosec B104
    port: int = Field(default=8787, ge=1, le=65_535)
    audit_dir: Path
    max_body_bytes: int = Field(default=65_536, ge=1_024, le=1_048_576)
    dashboard_enabled: bool = True
    synthetic_container_mode: bool = False

    @model_validator(mode="after")
    def _absolute_audit_root(self) -> GatewayConfigV1:
        if not self.audit_dir.is_absolute():
            raise ValueError("gateway audit_dir must be absolute after config resolution")
        if (self.host == "0.0.0.0") != self.synthetic_container_mode:  # nosec B104
            raise ValueError(
                "0.0.0.0 is permitted only for explicit synthetic_container_mode"
            )
        return self


def default_gateway_policy_v1() -> GatewayPolicyV1:
    """Return the only policy accepted by the local synthetic gateway."""

    return GatewayPolicyV1(
        rules=(
            GatewayToolRuleV1(
                tool_name="external.send",
                disposition="require_approval",
                effect="external",
                reason_code="owner_approval_required",
            ),
            GatewayToolRuleV1(
                tool_name="synthetic.lookup",
                disposition="allow",
                effect="pure",
                reason_code="synthetic_tool_allowed",
            ),
            GatewayToolRuleV1(
                tool_name="synthetic.sha256",
                disposition="allow",
                effect="pure",
                reason_code="synthetic_tool_allowed",
            ),
            GatewayToolRuleV1(
                tool_name="system.shell",
                disposition="deny",
                effect="process",
                reason_code="process_execution_denied",
            ),
        )
    )


def load_gateway_config_v1(path: Path) -> GatewayConfigV1:
    """Load a stable regular TOML config without following link/reparse aliases."""

    candidate = path.resolve(strict=False)
    _require_safe_existing_file(path, label="gateway config")
    raw = _read_safe_existing_file(path, label="gateway config", max_bytes=65_536)
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise GatewayContractError("gateway config must be valid UTF-8 TOML") from exc
    if not isinstance(payload, dict):
        raise GatewayContractError("gateway config must be a TOML table")
    audit_value = payload.get("audit_dir")
    if isinstance(audit_value, str):
        audit_path = Path(audit_value)
        if not audit_path.is_absolute():
            audit_path = candidate.parent / audit_path
        payload["audit_dir"] = audit_path.resolve(strict=False)
    try:
        return GatewayConfigV1.model_validate(payload)
    except ValueError as exc:
        raise GatewayContractError("gateway config violates the closed V1 contract") from exc


def gateway_example_config_v1_bytes() -> bytes:
    """Return the portable host-loopback example config shipped by the CLI."""

    return (
        b'schema_version = "AgenticSecurityHarnessGatewayConfig.v1"\n'
        b'host = "127.0.0.1"\n'
        b"port = 8787\n"
        b'audit_dir = "./.internal/runtime-gateway"\n'
        b"max_body_bytes = 65536\n"
        b"dashboard_enabled = true\n"
        b"synthetic_container_mode = false\n"
    )


def write_gateway_example_config_v1(path: Path) -> None:
    """Create exactly one portable config without overwriting an existing file."""

    candidate = path.resolve(strict=False)
    if not candidate.name or not candidate.parent.exists():
        raise GatewayContractError("gateway config parent must already exist")
    _require_safe_existing_ancestors(candidate.parent)
    if candidate.exists():
        raise GatewayContractError("gateway config destination must not exist")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(candidate, flags, 0o600)
    try:
        payload = gateway_example_config_v1_bytes()
        if os.write(fd, payload) != len(payload):
            raise GatewayContractError("gateway config write was incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)
    _require_safe_existing_file(candidate, label="gateway config")


def evaluate_gateway_tool_call(
    call: GatewayToolCallV1,
    policy: GatewayPolicyV1 | None = None,
) -> GatewayDecisionV1:
    """Evaluate a call before any tool implementation is selected."""

    active = policy or default_gateway_policy_v1()
    rule = next((item for item in active.rules if item.tool_name == call.tool_name), None)
    if rule is None:
        disposition: GatewayDisposition = "deny"
        effect: Literal["pure", "external", "process", "unknown"] = "unknown"
        reason = "unknown_tool_denied"
    else:
        disposition = rule.disposition
        effect = rule.effect
        reason = rule.reason_code
    if disposition == "allow":
        argument_error = _validate_builtin_arguments(call)
        if argument_error is not None:
            disposition = "deny"
            reason = argument_error
    return GatewayDecisionV1(
        call_id_sha256=_sha256_domain("ash-gateway-call-id-v1", call.call_id),
        tool_name_sha256=_sha256_domain("ash-gateway-tool-name-v1", call.tool_name),
        arguments_sha256=call.arguments_sha256(),
        policy_sha256=active.sha256(),
        disposition=disposition,
        reason_code=reason,
        effect=effect,
        execution_permitted=disposition == "allow",
    )


class GatewayAuditLedger:
    """Single-writer append-only audit ledger with a verified SHA-256 chain."""

    _root: Path
    _ledger_path: Path
    _lock_path: Path
    _privacy_key_path: Path
    _privacy_key: bytes
    _lock_handle: Any
    _mutex: threading.RLock
    _closed: bool

    def __init__(self, root: Path) -> None:
        self._root = root.resolve(strict=False)
        self._ledger_path = self._root / "gateway-audit.jsonl"
        self._lock_path = self._root / "gateway-audit.lock"
        self._privacy_key_path = self._root / "gateway-audit.key"
        self._mutex = threading.RLock()
        self._closed = False
        _prepare_private_directory(self._root)
        self._privacy_key = self._load_or_create_privacy_key()
        self._lock_handle = self._acquire_process_lock()
        try:
            self.read_records()
        except Exception:
            self.close()
            raise

    @property
    def root(self) -> Path:
        return self._root

    def __enter__(self) -> GatewayAuditLedger:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        handle = getattr(self, "_lock_handle", None)
        if handle is not None:
            _unlock_file(handle)
            handle.close()

    def _acquire_process_lock(self) -> Any:
        if self._lock_path.exists():
            _require_safe_existing_file(self._lock_path, label="gateway audit lock")
        else:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, b"0")
                os.fsync(fd)
            finally:
                os.close(fd)
        _require_safe_existing_file(self._lock_path, label="gateway audit lock")
        handle = _open_safe_existing_rw_file(
            self._lock_path, label="gateway audit lock"
        )
        try:
            _lock_file_nonblocking(handle)
        except Exception:
            handle.close()
            raise GatewayContractError("another gateway process owns the audit ledger") from None
        return handle

    def _load_or_create_privacy_key(self) -> bytes:
        if not self._privacy_key_path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(self._privacy_key_path, flags, 0o600)
            try:
                key = secrets.token_bytes(32)
                if os.write(fd, key) != len(key):
                    raise GatewayContractError("gateway privacy key write was incomplete")
                os.fsync(fd)
            finally:
                os.close(fd)
        _require_safe_existing_file(self._privacy_key_path, label="gateway privacy key")
        key = _read_safe_existing_file(
            self._privacy_key_path,
            label="gateway privacy key",
            max_bytes=32,
        )
        if len(key) != 32:
            raise GatewayContractError("gateway privacy key is invalid or unstable")
        return key

    def commitment(self, domain: str, value: Any) -> str:
        """Return a ledger-local HMAC commitment without exposing the key."""

        return hmac.new(
            self._privacy_key,
            domain.encode("ascii") + b"\0" + _canonical_json_bytes(value),
            hashlib.sha256,
        ).hexdigest()

    def read_records(self) -> tuple[GatewayAuditRecordV1, ...]:
        with self._mutex:
            if not self._ledger_path.exists():
                return ()
            _require_safe_existing_file(self._ledger_path, label="gateway audit ledger")
            raw = _read_safe_existing_file(
                self._ledger_path,
                label="gateway audit ledger",
                max_bytes=MAX_AUDIT_BYTES,
            )
            if raw and not raw.endswith(b"\n"):
                raise GatewayContractError("gateway audit ledger has a partial record")
            lines = raw.splitlines()
            if len(lines) > MAX_AUDIT_RECORDS:
                raise GatewayContractError("gateway audit ledger exceeds the record limit")
            records: list[GatewayAuditRecordV1] = []
            previous = ZERO_SHA256
            for index, line in enumerate(lines, start=1):
                if len(line) > 8_192:
                    raise GatewayContractError("gateway audit record exceeds 8192 bytes")
                payload = _strict_json_object(line)
                try:
                    record = GatewayAuditRecordV1.model_validate(payload)
                except ValueError as exc:
                    raise GatewayContractError("gateway audit record violates V1") from exc
                if _canonical_json_bytes(record.model_dump(mode="json")) != line:
                    raise GatewayContractError("gateway audit record is not canonical JSON")
                record.verify()
                if record.privacy_key_id_sha256 != hashlib.sha256(
                    self._privacy_key
                ).hexdigest():
                    raise GatewayContractError("gateway audit privacy key identity mismatch")
                if record.sequence != index or record.previous_entry_sha256 != previous:
                    raise GatewayContractError("gateway audit chain continuity failed")
                previous = record.entry_sha256
                records.append(record)
            return tuple(records)

    def append(
        self,
        *,
        request_id: str,
        protocol: GatewayProtocol,
        operation: Literal[
            "chat_completion", "mcp_discover", "mcp_tools_list", "tool_call"
        ],
        subject: str,
        payload: Any,
        policy_sha256: str,
        disposition: GatewayDisposition,
        reason_code: str,
    ) -> GatewayAuditRecordV1:
        with self._mutex:
            if self._closed:
                raise GatewayContractError("gateway audit ledger is closed")
            records = self.read_records()
            unsigned: dict[str, Any] = {
                "schema_version": "AgenticSecurityHarnessGatewayAudit.v1",
                "sequence": len(records) + 1,
                "occurred_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "request_id_commitment": self.commitment(
                    "ash-gateway-request-id-v1", request_id
                ),
                "protocol": protocol,
                "operation": operation,
                "subject_commitment": self.commitment(
                    "ash-gateway-subject-v1", subject
                ),
                "payload_commitment": self.commitment(
                    "ash-gateway-request-payload-v1", payload
                ),
                "privacy_key_id_sha256": hashlib.sha256(self._privacy_key).hexdigest(),
                "policy_sha256": policy_sha256,
                "disposition": disposition,
                "reason_code": reason_code,
                "previous_entry_sha256": (
                    records[-1].entry_sha256 if records else ZERO_SHA256
                ),
            }
            record = GatewayAuditRecordV1(
                **unsigned,
                entry_sha256=_sha256_domain("ash-gateway-audit-entry-v1", unsigned),
            )
            encoded = _canonical_json_bytes(record.model_dump(mode="json")) + b"\n"
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self._ledger_path, flags, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise GatewayContractError(
                        "gateway audit ledger must be a regular single-link file"
                    )
                _require_safe_existing_file(
                    self._ledger_path, label="gateway audit ledger"
                )
                if _file_reference(info) != _file_reference(self._ledger_path.lstat()):
                    raise GatewayContractError(
                        "gateway audit ledger path changed while it was opened"
                    )
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise GatewayContractError("gateway audit append was incomplete")
                os.fsync(fd)
            finally:
                os.close(fd)
            if self.read_records()[-1] != record:
                raise GatewayContractError("gateway audit append verification failed")
            return record

    def snapshot(self) -> GatewayAuditSnapshotV1:
        records = self.read_records()
        counts = Counter(record.disposition for record in records)
        return GatewayAuditSnapshotV1(
            records=len(records),
            allow=counts["allow"],
            deny=counts["deny"],
            require_approval=counts["require_approval"],
            head_sha256=records[-1].entry_sha256 if records else ZERO_SHA256,
        )


class GatewayEngine:
    """Policy-before-dispatch engine for deterministic synthetic tools."""

    policy: GatewayPolicyV1
    audit: GatewayAuditLedger
    _executions: int

    def __init__(
        self,
        audit: GatewayAuditLedger,
        policy: GatewayPolicyV1 | None = None,
    ) -> None:
        self.policy = policy or default_gateway_policy_v1()
        self.audit = audit
        self._executions = 0

    @property
    def execution_count(self) -> int:
        return self._executions

    def policy_snapshot(self) -> GatewayPolicySnapshotV1:
        return GatewayPolicySnapshotV1(
            policy_id=self.policy.policy_id,
            policy_sha256=self.policy.sha256(),
            rules=self.policy.rules,
        )

    def record_operation(
        self,
        *,
        request_id: str,
        protocol: GatewayProtocol,
        operation: Literal["chat_completion", "mcp_discover", "mcp_tools_list"],
        subject: str,
        payload: Any,
        reason_code: str,
    ) -> None:
        self.audit.append(
            request_id=request_id,
            protocol=protocol,
            operation=operation,
            subject=subject,
            payload=payload,
            policy_sha256=self.policy.sha256(),
            disposition="allow",
            reason_code=reason_code,
        )

    def call_tool(
        self,
        call: GatewayToolCallV1,
        *,
        request_id: str,
    ) -> tuple[GatewayDecisionV1, dict[str, Any] | None]:
        decision = evaluate_gateway_tool_call(call, self.policy)
        self.audit.append(
            request_id=request_id,
            protocol=call.protocol,
            operation="tool_call",
            subject=call.tool_name,
            payload=call.arguments,
            policy_sha256=decision.policy_sha256,
            disposition=decision.disposition,
            reason_code=decision.reason_code,
        )
        if not decision.execution_permitted:
            return decision, None
        result = self._execute_synthetic(call)
        self._executions += 1
        return decision, result

    def _execute_synthetic(self, call: GatewayToolCallV1) -> dict[str, Any]:
        if call.tool_name == "synthetic.sha256":
            value = cast(str, call.arguments["text"])
            return {
                "schema_version": "AgenticSecurityHarnessSyntheticToolResult.v1",
                "tool": call.tool_name,
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
        if call.tool_name == "synthetic.lookup":
            key = cast(str, call.arguments["key"])
            values = {
                "gateway-mode": "loopback-synthetic",
                "project-status": "development-contour",
            }
            return {
                "schema_version": "AgenticSecurityHarnessSyntheticToolResult.v1",
                "tool": call.tool_name,
                "key": key,
                "value": values[key],
            }
        raise GatewayContractError("policy allowed a tool without a synthetic executor")


class GatewayHTTPServer(ThreadingHTTPServer):
    """Typed server carrying its immutable config and engine."""

    daemon_threads = True
    allow_reuse_address = False

    config: GatewayConfigV1
    engine: GatewayEngine

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            self.engine.audit.close()


def create_gateway_server(
    config: GatewayConfigV1,
    *,
    audit: GatewayAuditLedger | None = None,
) -> GatewayHTTPServer:
    """Construct, but do not start, the loopback server."""

    ledger = audit or GatewayAuditLedger(config.audit_dir)
    try:
        server = GatewayHTTPServer((config.host, config.port), _GatewayRequestHandler)
    except Exception:
        if audit is None:
            ledger.close()
        raise
    server.config = config
    server.engine = GatewayEngine(ledger)
    return server


def serve_gateway(config: GatewayConfigV1) -> None:
    """Serve until interrupted inside the closed local/synthetic listener contract."""

    with GatewayAuditLedger(config.audit_dir) as audit:
        server = create_gateway_server(config, audit=audit)
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            server.server_close()


class _GatewayRequestHandler(BaseHTTPRequestHandler):
    server: GatewayHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # Raw request paths, clients, and headers are intentionally not logged.
        return

    def do_GET(self) -> None:  # noqa: N802
        request_id = _request_id()
        if not self._headers_safe():
            self._json_error(HTTPStatus.BAD_REQUEST, "credential_headers_forbidden", request_id)
            return
        if self.path == "/healthz":
            self._write_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "mode": "loopback-synthetic",
                    "request_id": request_id,
                },
            )
            return
        if self.path == "/readyz":
            snapshot = self.server.engine.audit.snapshot()
            self._write_json(
                HTTPStatus.OK,
                {
                    "status": "ready",
                    "policy_sha256": self.server.engine.policy.sha256(),
                    "audit_head_sha256": snapshot.head_sha256,
                    "request_id": request_id,
                },
            )
            return
        if self.path == "/v1/gateway/audit":
            self._write_json(
                HTTPStatus.OK,
                self.server.engine.audit.snapshot().model_dump(mode="json"),
            )
            return
        if self.path == "/v1/gateway/policy":
            self._write_json(
                HTTPStatus.OK,
                self.server.engine.policy_snapshot().model_dump(mode="json"),
            )
            return
        if self.path == "/dashboard" and self.server.config.dashboard_enabled:
            snapshot = self.server.engine.audit.snapshot()
            body = _dashboard_html(snapshot, self.server.engine.policy_snapshot())
            self._write_bytes(HTTPStatus.OK, body, "text/html; charset=utf-8")
            return
        if self.path == "/mcp":
            self._mcp_error(
                None,
                -32600,
                "post_required",
                request_id,
                HTTPStatus.METHOD_NOT_ALLOWED,
            )
            return
        self._json_error(HTTPStatus.NOT_FOUND, "route_not_found", request_id)

    def do_POST(self) -> None:  # noqa: N802
        request_id = _request_id()
        if not self._headers_safe():
            self._json_error(HTTPStatus.BAD_REQUEST, "credential_headers_forbidden", request_id)
            return
        if self.path == "/mcp" and not self._mcp_origin_safe():
            self._mcp_error(
                None, -32600, "origin_forbidden", request_id, HTTPStatus.FORBIDDEN
            )
            return
        try:
            payload = self._read_json_body()
        except GatewayContractError as exc:
            self._json_error(HTTPStatus.BAD_REQUEST, str(exc), request_id)
            return
        if self.path == "/v1/chat/completions":
            self._handle_chat(payload, request_id)
            return
        if self.path == "/mcp":
            self._handle_mcp(payload, request_id)
            return
        self._json_error(HTTPStatus.NOT_FOUND, "route_not_found", request_id)

    def _headers_safe(self) -> bool:
        forbidden = {"authorization", "cookie", "proxy-authorization"}
        return not any(name.casefold() in forbidden for name in self.headers)

    def _mcp_origin_safe(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        allowed = {
            f"http://127.0.0.1:{self.server.server_port}",
            f"http://localhost:{self.server.server_port}",
        }
        return origin in allowed

    def _read_json_body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise GatewayContractError("transfer_encoding_forbidden")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise GatewayContractError("application_json_required")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isascii() or not raw_length.isdigit():
            raise GatewayContractError("valid_content_length_required")
        length = int(raw_length)
        if length < 0 or length > self.server.config.max_body_bytes:
            raise GatewayContractError("request_body_limit_exceeded")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise GatewayContractError("incomplete_request_body")
        return _strict_json_object(raw)

    def _handle_chat(self, payload: dict[str, Any], request_id: str) -> None:
        allowed = {"model", "messages", "tools", "tool_choice", "temperature", "stream"}
        if set(payload) - allowed or not isinstance(payload.get("model"), str):
            self._json_error(HTTPStatus.BAD_REQUEST, "chat_contract_violation", request_id)
            return
        if payload.get("stream", False) is not False:
            self._json_error(HTTPStatus.BAD_REQUEST, "streaming_not_supported", request_id)
            return
        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages:
            self._json_error(HTTPStatus.BAD_REQUEST, "messages_required", request_id)
            return
        try:
            _validate_json_value(messages, depth=0)
        except ValueError:
            self._json_error(HTTPStatus.BAD_REQUEST, "messages_contract_violation", request_id)
            return
        model = cast(str, payload["model"])
        if model == "ash-fake-safe":
            self.server.engine.record_operation(
                request_id=request_id,
                protocol="openai_compatible",
                operation="chat_completion",
                subject=model,
                payload=payload,
                reason_code="synthetic_response_allowed",
            )
            self._write_json(
                HTTPStatus.OK,
                _chat_response(request_id, model, "Synthetic response."),
            )
            return
        tool_by_model = {
            "ash-fake-tool-allow": ("synthetic.lookup", {"key": "project-status"}),
            "ash-fake-tool-deny": ("system.shell", {"command": "not-executed"}),
            "ash-fake-tool-approval": ("external.send", {"destination": "not-executed"}),
        }
        selected = tool_by_model.get(model)
        if selected is None:
            self._json_error(HTTPStatus.BAD_REQUEST, "unknown_synthetic_model", request_id)
            return
        call = GatewayToolCallV1(
            call_id=f"call:{uuid.uuid4().hex}",
            protocol="openai_compatible",
            tool_name=selected[0],
            arguments=selected[1],
        )
        decision, result = self.server.engine.call_tool(call, request_id=request_id)
        if decision.disposition == "deny":
            self._json_error(HTTPStatus.FORBIDDEN, decision.reason_code, request_id)
            return
        if decision.disposition == "require_approval":
            approval = decision.approval_request()
            self._json_error(
                HTTPStatus.CONFLICT,
                decision.reason_code,
                request_id,
                data={
                    "approval_request_sha256": approval.sha256(),
                    "approval_status": approval.status,
                },
            )
            return
        self._write_json(
            HTTPStatus.OK,
            _chat_response(request_id, model, json.dumps(result, sort_keys=True)),
        )

    def _handle_mcp(self, payload: dict[str, Any], request_id: str) -> None:
        if set(payload) - {"jsonrpc", "id", "method", "params"}:
            self._mcp_error(
                None, -32600, "invalid_request", request_id, HTTPStatus.BAD_REQUEST
            )
            return
        rpc_id = payload.get("id")
        if (
            payload.get("jsonrpc") != "2.0"
            or not isinstance(payload.get("method"), str)
            or not _valid_rpc_id(rpc_id)
        ):
            self._mcp_error(
                None, -32600, "invalid_request", request_id, HTTPStatus.BAD_REQUEST
            )
            return
        method = cast(str, payload["method"])
        params = payload.get("params", {})
        if not isinstance(params, dict):
            self._mcp_error(
                rpc_id, -32602, "invalid_params", request_id, HTTPStatus.BAD_REQUEST
            )
            return
        transport_error = self._validate_mcp_transport(method, params)
        if transport_error is not None:
            code, message, data = transport_error
            self._mcp_error(
                rpc_id,
                code,
                message,
                request_id,
                HTTPStatus.BAD_REQUEST,
                data=data,
            )
            return
        method_params = dict(params)
        method_params.pop("_meta")
        if method == "server/discover":
            if method_params:
                self._mcp_error(
                    rpc_id, -32602, "invalid_params", request_id, HTTPStatus.BAD_REQUEST
                )
                return
            self.server.engine.record_operation(
                request_id=request_id,
                protocol="mcp",
                operation="mcp_discover",
                subject="server/discover",
                payload=params,
                reason_code="synthetic_server_discovered",
            )
            self._mcp_result(
                rpc_id,
                {
                    "resultType": "complete",
                    "supportedVersions": [MCP_PROTOCOL_VERSION],
                    "capabilities": {"tools": {"listChanged": False}},
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "ash-runtime-gateway",
                            "version": "1.1.0-dev",
                        }
                    },
                    "instructions": "Two deterministic synthetic tools; no external effects.",
                    "ttlMs": 300_000,
                    "cacheScope": "public",
                },
            )
            return
        if method == "tools/list":
            if method_params:
                self._mcp_error(
                    rpc_id, -32602, "invalid_params", request_id, HTTPStatus.BAD_REQUEST
                )
                return
            self.server.engine.record_operation(
                request_id=request_id,
                protocol="mcp",
                operation="mcp_tools_list",
                subject="tools/list",
                payload=params,
                reason_code="synthetic_tools_listed",
            )
            self._mcp_result(
                rpc_id,
                {
                    "resultType": "complete",
                    "tools": _mcp_tool_catalog(),
                    "ttlMs": 300_000,
                    "cacheScope": "public",
                },
            )
            return
        if method == "tools/call":
            if set(method_params) != {"name", "arguments"}:
                self._mcp_error(
                    rpc_id, -32602, "invalid_params", request_id, HTTPStatus.BAD_REQUEST
                )
                return
            try:
                call = GatewayToolCallV1(
                    call_id=f"call:{uuid.uuid4().hex}",
                    protocol="mcp",
                    tool_name=method_params["name"],
                    arguments=method_params["arguments"],
                )
            except ValueError:
                self._mcp_error(
                    rpc_id, -32602, "invalid_params", request_id, HTTPStatus.BAD_REQUEST
                )
                return
            decision, result = self.server.engine.call_tool(call, request_id=request_id)
            if decision.disposition != "allow":
                data = {"gatewayReason": decision.reason_code}
                if decision.disposition == "require_approval":
                    approval = decision.approval_request()
                    data.update(
                        {
                            "approvalRequestSha256": approval.sha256(),
                            "approvalStatus": approval.status,
                        }
                    )
                self._mcp_error(
                    rpc_id,
                    -32602,
                    "tool_call_denied",
                    request_id,
                    HTTPStatus.BAD_REQUEST,
                    data=data,
                )
                return
            self._mcp_result(
                rpc_id,
                {
                    "resultType": "complete",
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, sort_keys=True, separators=(",", ":")),
                        }
                    ],
                    "isError": False,
                },
            )
            return
        self._mcp_error(
            rpc_id, -32601, "method_not_found", request_id, HTTPStatus.NOT_FOUND
        )

    def _validate_mcp_transport(
        self, method: str, params: dict[str, Any]
    ) -> tuple[int, str, dict[str, Any] | None] | None:
        accept = {
            item.split(";", 1)[0].strip().lower()
            for item in self.headers.get("Accept", "").split(",")
        }
        if not {"application/json", "text/event-stream"}.issubset(accept):
            return -32020, "header_mismatch", None
        header_version = self.headers.get("MCP-Protocol-Version")
        header_method = self.headers.get("Mcp-Method")
        header_name = self.headers.get("Mcp-Name")
        meta = params.get("_meta")
        if not isinstance(meta, dict) or set(meta) != MCP_REQUIRED_META_KEYS:
            return -32602, "invalid_request_metadata", None
        body_version = meta.get(MCP_META_PROTOCOL_VERSION)
        if not isinstance(body_version, str):
            return -32602, "invalid_request_metadata", None
        if header_version != body_version or header_method != method:
            return -32020, "header_mismatch", None
        if body_version != MCP_PROTOCOL_VERSION:
            return (
                -32022,
                "unsupported_protocol_version",
                {"supportedVersions": [MCP_PROTOCOL_VERSION], "requestedVersion": body_version},
            )
        client_info = meta.get(MCP_META_CLIENT_INFO)
        if (
            not isinstance(client_info, dict)
            or set(client_info) != {"name", "version"}
            or not all(_safe_mcp_identity(value) for value in client_info.values())
        ):
            return -32602, "invalid_request_metadata", None
        if meta.get(MCP_META_CLIENT_CAPABILITIES) != {}:
            return -32602, "unsupported_client_capabilities", None
        expected_name = params.get("name") if method == "tools/call" else None
        if expected_name is None:
            if header_name is not None:
                return -32020, "header_mismatch", None
        elif not isinstance(expected_name, str) or header_name != expected_name:
            return -32020, "header_mismatch", None
        return None

    def _mcp_result(self, rpc_id: Any, result: dict[str, Any]) -> None:
        self._write_json(HTTPStatus.OK, {"jsonrpc": "2.0", "id": rpc_id, "result": result})

    def _mcp_error(
        self,
        rpc_id: Any,
        code: int,
        message: str,
        request_id: str,
        status: HTTPStatus = HTTPStatus.OK,
        *,
        data: dict[str, Any] | None = None,
    ) -> None:
        error: dict[str, Any] = {
            "code": code,
            "message": message,
            "data": {"requestId": request_id},
        }
        if data:
            error["data"].update(data)
        self._write_json(
            status,
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": error,
            },
        )

    def _json_error(
        self,
        status: HTTPStatus,
        code: str,
        request_id: str,
        *,
        data: dict[str, Any] | None = None,
    ) -> None:
        error: dict[str, Any] = {
            "code": code,
            "message": "request rejected",
            "request_id": request_id,
        }
        if data:
            error.update(data)
        self._write_json(
            status,
            {"error": error},
        )

    def _write_json(self, status: HTTPStatus, payload: Mapping[str, Any]) -> None:
        self._write_bytes(status, _canonical_json_bytes(dict(payload)), "application/json")

    def _write_bytes(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def _validate_builtin_arguments(call: GatewayToolCallV1) -> str | None:
    if call.tool_name == "synthetic.sha256":
        if set(call.arguments) != {"text"}:
            return "tool_arguments_denied"
        value = call.arguments.get("text")
        if not isinstance(value, str) or len(value.encode("utf-8")) > 4_096:
            return "tool_arguments_denied"
        return None
    if call.tool_name == "synthetic.lookup":
        if set(call.arguments) != {"key"}:
            return "tool_arguments_denied"
        if call.arguments.get("key") not in {"gateway-mode", "project-status"}:
            return "tool_arguments_denied"
        return None
    return None


def _valid_rpc_id(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -(2**63) <= value < 2**63
    return isinstance(value, str) and 0 < len(value) <= 128


def _safe_mcp_identity(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 128:
        return False
    return all(0x20 <= ord(character) <= 0x7E for character in value)


def _mcp_tool_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": "synthetic.lookup",
            "description": "Return one fixed public gateway metadata value.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["key"],
                "properties": {
                    "key": {"type": "string", "enum": ["gateway-mode", "project-status"]}
                },
            },
        },
        {
            "name": "synthetic.sha256",
            "description": "Return SHA-256 of a bounded in-memory synthetic string.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["text"],
                "properties": {"text": {"type": "string", "maxLength": 4096}},
            },
        },
    ]


def _chat_response(request_id: str, model: str, content: str) -> dict[str, Any]:
    return {
        "id": request_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _dashboard_html(
    snapshot: GatewayAuditSnapshotV1,
    policy: GatewayPolicySnapshotV1,
) -> bytes:
    values = {
        "records": str(snapshot.records),
        "allow": str(snapshot.allow),
        "deny": str(snapshot.deny),
        "approval": str(snapshot.require_approval),
        "head": html.escape(snapshot.head_sha256),
        "policy": html.escape(policy.policy_sha256),
    }
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>ASH Runtime Gateway</title>"
        "<style>body{font:16px system-ui;max-width:800px;margin:3rem auto;padding:0 1rem}"
        "table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.5rem}"
        "code{overflow-wrap:anywhere}</style></head><body>"
        "<h1>ASH Runtime Gateway</h1>"
        "<p>Loopback synthetic development contour. No provider or production authority.</p>"
        "<table><tr><th>Records</th><th>Allowed</th><th>Denied</th>"
        "<th>Approval required</th></tr>"
        f"<tr><td>{values['records']}</td><td>{values['allow']}</td>"
        f"<td>{values['deny']}</td><td>{values['approval']}</td></tr></table>"
        f"<p>Verified audit head: <code>{values['head']}</code></p>"
        f"<p>Active policy: <code>{values['policy']}</code></p>"
        "<p>Approval requests are pending and non-executable; no grant endpoint is "
        "available in this contour.</p>"
        "</body></html>"
    ).encode()


def _validate_json_value(value: Any, *, depth: int) -> None:
    if depth > 12:
        raise ValueError("JSON nesting exceeds the gateway limit")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value.encode("utf-8")) > 16_384:
            raise ValueError("JSON string exceeds the gateway limit")
        if isinstance(value, int) and not (-2**63 <= value < 2**63):
            raise ValueError("JSON integer exceeds the gateway limit")
        return
    if isinstance(value, float):
        if not (-1e308 < value < 1e308):
            raise ValueError("non-finite JSON numbers are forbidden")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("JSON array exceeds the gateway limit")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 128:
            raise ValueError("JSON object exceeds the gateway limit")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("JSON object keys must be bounded non-empty strings")
            _validate_json_value(item, depth=depth + 1)
        return
    raise ValueError("unsupported JSON value")


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise GatewayContractError("duplicate_json_field")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise GatewayContractError("non_finite_json_number")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayContractError("invalid_json") from exc
    if not isinstance(value, dict):
        raise GatewayContractError("json_object_required")
    _validate_json_value(value, depth=0)
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _sha256_domain(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical_json_bytes(value)).hexdigest()


def _request_id() -> str:
    return f"gw_{uuid.uuid4().hex}"


def _prepare_private_directory(root: Path) -> None:
    _require_safe_existing_ancestors(root)
    if root.exists():
        if is_link_or_reparse(root) or not root.is_dir():
            raise GatewayContractError("gateway audit root must be a real directory")
    else:
        missing: list[Path] = []
        candidate = root
        while not candidate.exists():
            missing.append(candidate)
            if candidate.parent == candidate:
                raise GatewayContractError("gateway audit root has no existing ancestor")
            candidate = candidate.parent
        _require_safe_existing_ancestors(candidate)
        for directory in reversed(missing):
            directory.mkdir(mode=0o700, parents=False)
            if is_link_or_reparse(directory) or not directory.is_dir():
                raise GatewayContractError("gateway audit root creation was redirected")
    _require_safe_existing_ancestors(root)


def _require_safe_existing_ancestors(path: Path) -> None:
    for candidate in (path, *path.parents):
        if not candidate.exists():
            continue
        if is_link_or_reparse(candidate):
            raise GatewayContractError("gateway path must not traverse a link or reparse point")
        if candidate != path and not candidate.is_dir():
            raise GatewayContractError("gateway parent path must be a directory")


def _require_safe_existing_file(path: Path, *, label: str) -> None:
    _require_safe_existing_ancestors(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise GatewayContractError(f"{label} is unavailable") from exc
    if is_link_or_reparse(path) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise GatewayContractError(f"{label} must be a regular single-link file")


def _read_safe_existing_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    """Read one bounded stable file through a descriptor, rejecting aliases and swaps."""

    _require_safe_existing_file(path, label=label)
    before = path.lstat()
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise GatewayContractError(f"{label} could not be opened safely") from exc
    try:
        opened_before = os.fstat(fd)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or _file_reference(before) != _file_reference(opened_before)
        ):
            raise GatewayContractError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise GatewayContractError(f"{label} exceeds its byte limit")
        opened_after = os.fstat(fd)
    finally:
        os.close(fd)
    _require_safe_existing_file(path, label=label)
    after = path.lstat()
    if not (
        _stat_identity(before)
        == _stat_identity(opened_before)
        == _stat_identity(opened_after)
        == _stat_identity(after)
    ):
        raise GatewayContractError(f"{label} changed while it was read")
    return raw


def _open_safe_existing_rw_file(path: Path, *, label: str) -> Any:
    """Open one existing regular file without accepting link/path substitution."""

    _require_safe_existing_file(path, label=label)
    before = path.lstat()
    flags = os.O_RDWR
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        _require_safe_existing_file(path, label=label)
        after = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not (
                _file_reference(before)
                == _file_reference(opened)
                == _file_reference(after)
            )
        ):
            raise GatewayContractError(f"{label} changed while it was opened")
        return os.fdopen(fd, "r+b", buffering=0)
    except Exception:
        if "fd" in locals():
            os.close(fd)
        raise


def _file_reference(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _lock_file_nonblocking(handle: Any) -> None:
    handle.seek(0)
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_file(handle: Any) -> None:
    try:
        handle.seek(0)
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl: Any = importlib.import_module("fcntl")
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        return


def unused_loopback_port() -> int:
    """Return a currently unused loopback port for bounded synthetic tests only."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return cast(int, sock.getsockname()[1])


def send_http_json_for_test(
    host: str,
    port: int,
    path: str,
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    """Minimal local test client; never used by the operator CLI."""

    body = _canonical_json_bytes(payload)
    request = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    head, response_body = raw.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    return status, cast(dict[str, Any], json.loads(response_body))
