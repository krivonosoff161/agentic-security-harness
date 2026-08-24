"""Controlled loopback-only provider/tool-host adapter V1.

The adapter deliberately exposes a very small transport surface: one literal loopback
address, one configured TCP port, plain HTTP, and ``/v1/responses``.  It never consults
DNS or proxy environment variables, follows redirects, accepts credentials or caller
headers, discovers tools, or dispatches anything outside the Runtime Gateway's closed
synthetic policy.

Raw input and provider response bytes are transient.  The durable receipt contract
contains only domain-separated digests, bounded counters, fixed reason codes, gateway
decisions, and an explicit lack of provider authentication or operational authority.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import threading
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.provider_tool_adapters import (
    ProviderToolAdapterError,
    ProviderToolExecutionV1,
    execute_provider_tool_payload_v1,
    normalize_provider_tool_calls_v1,
)
from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    ZERO_SHA256,
    GatewayDecisionV1,
    GatewayEngine,
)

LOCAL_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,127}$"
MAX_LOCAL_REPLAY_IDENTITIES = 4_096
LOCAL_RESPONSE_PATH: Literal["/v1/responses"] = "/v1/responses"

LocalAdapterStatus = Literal["completed", "error", "cancelled"]
LocalAdapterReason = Literal[
    "completed_without_tool_calls",
    "completed_with_tool_calls",
    "cancelled_before_request",
    "cancelled_after_response",
    "local_connect_error",
    "local_timeout",
    "local_protocol_error",
    "redirect_forbidden",
    "response_http_status_invalid",
    "response_content_type_invalid",
    "response_content_length_missing",
    "response_content_length_invalid",
    "response_content_length_duplicate",
    "response_transfer_encoding_forbidden",
    "response_content_encoding_forbidden",
    "response_body_truncated",
    "response_body_oversized",
    "response_json_invalid",
    "response_json_noncanonical",
    "response_tool_payload_invalid",
    "tool_call_identity_duplicate",
    "tool_call_replay_denied",
    "replay_capacity_exhausted",
]


class ControlledLocalAdapterContractError(ValueError):
    """Raised when local adapter input violates its closed pre-network contract."""


class ControlledLocalAdapterConfigV1(BaseModel):
    """Immutable transport limits for one operator-selected local endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessControlledLocalAdapterConfig.v1"] = (
        "AgenticSecurityHarnessControlledLocalAdapterConfig.v1"
    )
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: int = Field(ge=1, le=65_535)
    path: Literal["/v1/responses"] = LOCAL_RESPONSE_PATH
    timeout_milliseconds: int = Field(default=2_000, ge=50, le=30_000)
    max_request_bytes: int = Field(default=65_536, ge=1_024, le=65_536)
    max_response_bytes: int = Field(default=65_536, ge=1_024, le=65_536)
    max_retries: int = Field(default=0, ge=0, le=2)

    def sha256(self) -> str:
        return _domain_sha256(
            "ash-controlled-local-adapter-config-v1", self.model_dump(mode="json")
        )

    def endpoint_sha256(self) -> str:
        return _domain_sha256(
            "ash-controlled-local-adapter-endpoint-v1",
            {
                "scheme": "http",
                "host": self.host,
                "port": self.port,
                "path": self.path,
            },
        )


class ControlledLocalToolReceiptV1(BaseModel):
    """Digest-only record of one gateway policy decision and synthetic dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessControlledLocalToolReceipt.v1"] = (
        "AgenticSecurityHarnessControlledLocalToolReceipt.v1"
    )
    sequence: int = Field(ge=1, le=8)
    correlation_sha256: str = Field(pattern=SHA256_PATTERN)
    call_id_sha256: str = Field(pattern=SHA256_PATTERN)
    tool_name_sha256: str = Field(pattern=SHA256_PATTERN)
    arguments_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition: Literal["allow", "deny", "require_approval"]
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    effect: Literal["pure", "external", "process", "unknown"]
    execution_permitted: bool
    result_observed: bool
    result_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _coherent(self) -> ControlledLocalToolReceiptV1:
        if self.execution_permitted != (self.disposition == "allow"):
            raise ValueError("only allow may record execution permission")
        if self.result_observed != self.execution_permitted:
            raise ValueError("only an executed synthetic tool may have a result")
        if self.result_observed == (self.result_sha256 == ZERO_SHA256):
            raise ValueError("tool result presence and digest disagree")
        return self


class ControlledLocalInvocationReceiptV1(BaseModel):
    """Closed privacy-minimized receipt for one bounded local invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessControlledLocalInvocationReceipt.v1"] = (
        "AgenticSecurityHarnessControlledLocalInvocationReceipt.v1"
    )
    request_id_sha256: str = Field(pattern=SHA256_PATTERN)
    endpoint_sha256: str = Field(pattern=SHA256_PATTERN)
    config_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    model_sha256: str = Field(pattern=SHA256_PATTERN)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_observed: bool
    response_sha256: str = Field(pattern=SHA256_PATTERN)
    network_attempts: int = Field(ge=0, le=3)
    status: LocalAdapterStatus
    reason_code: LocalAdapterReason
    http_status: int | None = Field(default=None, ge=100, le=599)
    tools: tuple[ControlledLocalToolReceiptV1, ...] = Field(max_length=8)
    audit_records_before: int = Field(ge=0)
    audit_records_after: int = Field(ge=0)
    audit_head_before_sha256: str = Field(pattern=SHA256_PATTERN)
    audit_head_after_sha256: str = Field(pattern=SHA256_PATTERN)
    network_scope: Literal["literal_loopback_http"] = "literal_loopback_http"
    provider_authenticated: Literal[False] = False
    operational_authority: Literal["none"] = "none"
    receipt_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _coherent(self) -> ControlledLocalInvocationReceiptV1:
        if self.response_observed == (self.response_sha256 == ZERO_SHA256):
            raise ValueError("response presence and digest disagree")
        if self.audit_records_after < self.audit_records_before:
            raise ValueError("gateway audit record count regressed")
        if self.status == "completed" and self.http_status != 200:
            raise ValueError("completed invocation requires HTTP 200")
        if self.status != "completed" and self.tools:
            raise ValueError("failed or cancelled invocation cannot contain tool receipts")
        if self.reason_code == "completed_without_tool_calls" and self.tools:
            raise ValueError("no-tool completion cannot contain tool receipts")
        if self.reason_code == "completed_with_tool_calls" and not self.tools:
            raise ValueError("tool completion requires tool receipts")
        expected = _domain_sha256(
            "ash-controlled-local-invocation-receipt-v1", self.unsigned_payload()
        )
        if self.receipt_sha256 != expected:
            raise ValueError("controlled local invocation receipt digest mismatch")
        return self

    def unsigned_payload(self) -> dict[str, Any]:
        value = self.model_dump(mode="json")
        value.pop("receipt_sha256")
        return value


@dataclass(frozen=True)
class ControlledLocalAdapterOutcomeV1:
    """One receipt plus transient provider-shaped synthetic tool results."""

    receipt: ControlledLocalInvocationReceiptV1
    tool_executions: tuple[ProviderToolExecutionV1, ...] = ()


@dataclass(frozen=True)
class _HTTPResult:
    body: bytes | None
    attempts: int
    reason_code: LocalAdapterReason | None
    http_status: int | None


class _LiteralLoopbackHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose connect path never invokes name resolution."""

    def connect(self) -> None:
        family = socket.AF_INET if self.host == "127.0.0.1" else socket.AF_INET6
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            address: tuple[Any, ...]
            if family == socket.AF_INET:
                address = (self.host, self.port)
            else:
                address = (self.host, self.port, 0, 0)
            sock.connect(address)
        except Exception:
            sock.close()
            raise
        self.sock = sock


class ControlledLocalAdapterV1:
    """Stateful replay-bounded bridge to one operator-started local model endpoint."""

    def __init__(self, config: ControlledLocalAdapterConfigV1, engine: GatewayEngine) -> None:
        if type(config) is not ControlledLocalAdapterConfigV1:
            raise ControlledLocalAdapterContractError("adapter config must be the exact V1 type")
        try:
            checked_config = ControlledLocalAdapterConfigV1.model_validate(
                config.model_dump(mode="python")
            )
        except ValueError as exc:
            raise ControlledLocalAdapterContractError(
                "adapter config violates the closed V1 runtime boundary"
            ) from exc
        if type(engine) is not GatewayEngine:
            raise ControlledLocalAdapterContractError(
                "adapter engine must be the closed Runtime Gateway engine"
            )
        self.config = checked_config
        self.engine = engine
        self._seen_tool_calls: set[str] = set()
        self._replay_lock = threading.Lock()
        self._invoke_lock = threading.Lock()

    def invoke(
        self,
        *,
        model_id: str,
        input_text: str,
        request_id: str,
        cancel_event: threading.Event | None = None,
    ) -> ControlledLocalAdapterOutcomeV1:
        """Perform one bounded request and dispatch only policy-allowed synthetic tools."""

        with self._invoke_lock:
            return self._invoke_serialized(
                model_id=model_id,
                input_text=input_text,
                request_id=request_id,
                cancel_event=cancel_event,
            )

    def _invoke_serialized(
        self,
        *,
        model_id: str,
        input_text: str,
        request_id: str,
        cancel_event: threading.Event | None,
    ) -> ControlledLocalAdapterOutcomeV1:
        """Own one adapter-local audit interval from snapshot through receipt."""

        model_sha = _model_sha256(model_id)
        request_id_sha = _request_id_sha256(request_id)
        request = _build_request(model_id, input_text)
        request_bytes = _canonical_json_bytes(request)
        if len(request_bytes) > self.config.max_request_bytes:
            raise ControlledLocalAdapterContractError("local request exceeds configured limit")
        request_sha = _domain_sha256("ash-controlled-local-request-v1", request)
        before = self.engine.audit.snapshot()

        if cancel_event is not None and cancel_event.is_set():
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=None,
                attempts=0,
                status="cancelled",
                reason="cancelled_before_request",
                http_status=None,
            )

        transport = _request_local(self.config, request_bytes)
        if transport.reason_code is not None:
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=transport.body,
                attempts=transport.attempts,
                status="error",
                reason=transport.reason_code,
                http_status=transport.http_status,
            )
        body = transport.body
        if body is None:
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=None,
                attempts=transport.attempts,
                status="error",
                reason="local_protocol_error",
                http_status=transport.http_status,
            )

        if cancel_event is not None and cancel_event.is_set():
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="cancelled",
                reason="cancelled_after_response",
                http_status=transport.http_status,
            )

        try:
            response = _decode_canonical_response(body)
        except _ResponseFailure as exc:
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="error",
                reason=exc.reason_code,
                http_status=transport.http_status,
            )

        try:
            calls = normalize_provider_tool_calls_v1("openai_responses", body)
        except ProviderToolAdapterError:
            if _is_completed_response_without_tool_calls(response):
                self.engine.record_operation(
                    request_id=request_id,
                    protocol="openai_responses",
                    operation="chat_completion",
                    subject=model_id,
                    payload=response,
                    reason_code="controlled_local_response_received",
                )
                return self._outcome(
                    request_id_sha=request_id_sha,
                    model_sha=model_sha,
                    request_sha=request_sha,
                    before=before,
                    body=body,
                    attempts=transport.attempts,
                    status="completed",
                    reason="completed_without_tool_calls",
                    http_status=transport.http_status,
                )
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="error",
                reason="response_tool_payload_invalid",
                http_status=transport.http_status,
            )

        identities = tuple(call.correlation_sha256() for call in calls)
        if len(set(identities)) != len(identities):
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="error",
                reason="tool_call_identity_duplicate",
                http_status=transport.http_status,
            )
        replay_reason = self._reserve_tool_calls(identities)
        if replay_reason is not None:
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="error",
                reason=replay_reason,
                http_status=transport.http_status,
            )

        if cancel_event is not None and cancel_event.is_set():
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="cancelled",
                reason="cancelled_after_response",
                http_status=transport.http_status,
            )

        self.engine.record_operation(
            request_id=request_id,
            protocol="openai_responses",
            operation="chat_completion",
            subject=model_id,
            payload=response,
            reason_code="controlled_local_response_received",
        )
        try:
            executions = execute_provider_tool_payload_v1(
                self.engine,
                "openai_responses",
                body,
                request_id=request_id,
            )
        except ProviderToolAdapterError:
            # The immutable bytes were already normalized.  Keep this fail-closed guard
            # for future adapter changes without reflecting parser internals.
            return self._outcome(
                request_id_sha=request_id_sha,
                model_sha=model_sha,
                request_sha=request_sha,
                before=before,
                body=body,
                attempts=transport.attempts,
                status="error",
                reason="response_tool_payload_invalid",
                http_status=transport.http_status,
            )
        tool_receipts = tuple(
            _tool_receipt(index, execution)
            for index, execution in enumerate(executions, start=1)
        )
        return self._outcome(
            request_id_sha=request_id_sha,
            model_sha=model_sha,
            request_sha=request_sha,
            before=before,
            body=body,
            attempts=transport.attempts,
            status="completed",
            reason="completed_with_tool_calls",
            http_status=transport.http_status,
            tools=tool_receipts,
            executions=executions,
        )

    def _reserve_tool_calls(
        self, identities: tuple[str, ...]
    ) -> Literal["tool_call_replay_denied", "replay_capacity_exhausted"] | None:
        with self._replay_lock:
            if any(identity in self._seen_tool_calls for identity in identities):
                return "tool_call_replay_denied"
            if len(self._seen_tool_calls) + len(identities) > MAX_LOCAL_REPLAY_IDENTITIES:
                return "replay_capacity_exhausted"
            self._seen_tool_calls.update(identities)
        return None

    def _outcome(
        self,
        *,
        request_id_sha: str,
        model_sha: str,
        request_sha: str,
        before: Any,
        body: bytes | None,
        attempts: int,
        status: LocalAdapterStatus,
        reason: LocalAdapterReason,
        http_status: int | None,
        tools: tuple[ControlledLocalToolReceiptV1, ...] = (),
        executions: tuple[ProviderToolExecutionV1, ...] = (),
    ) -> ControlledLocalAdapterOutcomeV1:
        after = self.engine.audit.snapshot()
        payload: dict[str, Any] = {
            "schema_version": "AgenticSecurityHarnessControlledLocalInvocationReceipt.v1",
            "request_id_sha256": request_id_sha,
            "endpoint_sha256": self.config.endpoint_sha256(),
            "config_sha256": self.config.sha256(),
            "policy_sha256": self.engine.policy.sha256(),
            "model_sha256": model_sha,
            "request_sha256": request_sha,
            "response_observed": body is not None,
            "response_sha256": (
                _domain_sha256_bytes("ash-controlled-local-response-v1", body)
                if body is not None
                else ZERO_SHA256
            ),
            "network_attempts": attempts,
            "status": status,
            "reason_code": reason,
            "http_status": http_status,
            "tools": [item.model_dump(mode="json") for item in tools],
            "audit_records_before": before.records,
            "audit_records_after": after.records,
            "audit_head_before_sha256": before.head_sha256,
            "audit_head_after_sha256": after.head_sha256,
            "network_scope": "literal_loopback_http",
            "provider_authenticated": False,
            "operational_authority": "none",
        }
        payload["receipt_sha256"] = _domain_sha256(
            "ash-controlled-local-invocation-receipt-v1", payload
        )
        receipt = ControlledLocalInvocationReceiptV1.model_validate(payload)
        return ControlledLocalAdapterOutcomeV1(receipt=receipt, tool_executions=executions)


class _ResponseFailure(Exception):
    def __init__(self, reason_code: LocalAdapterReason) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _request_local(config: ControlledLocalAdapterConfigV1, body: bytes) -> _HTTPResult:
    attempts = 0
    for attempt in range(config.max_retries + 1):
        attempts = attempt + 1
        connection = _LiteralLoopbackHTTPConnection(
            config.host,
            config.port,
            timeout=config.timeout_milliseconds / 1_000,
        )
        try:
            connection.request(
                "POST",
                config.path,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Connection": "close",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            headers = response.getheaders()
            status = response.status
            if 300 <= status <= 399:
                return _HTTPResult(None, attempts, "redirect_forbidden", status)
            if status != 200:
                return _HTTPResult(None, attempts, "response_http_status_invalid", status)
            content_types = [
                value for name, value in headers if name.casefold() == "content-type"
            ]
            if len(content_types) != 1 or content_types[0].casefold() != "application/json":
                return _HTTPResult(None, attempts, "response_content_type_invalid", status)
            if any(name.casefold() == "transfer-encoding" for name, _ in headers):
                return _HTTPResult(
                    None, attempts, "response_transfer_encoding_forbidden", status
                )
            if any(name.casefold() == "content-encoding" for name, _ in headers):
                return _HTTPResult(
                    None, attempts, "response_content_encoding_forbidden", status
                )
            lengths = [value for name, value in headers if name.casefold() == "content-length"]
            if not lengths:
                return _HTTPResult(None, attempts, "response_content_length_missing", status)
            if len(lengths) != 1:
                return _HTTPResult(None, attempts, "response_content_length_duplicate", status)
            encoded_length = lengths[0]
            if (
                not encoded_length.isascii()
                or not encoded_length.isdecimal()
                or (len(encoded_length) > 1 and encoded_length.startswith("0"))
            ):
                return _HTTPResult(None, attempts, "response_content_length_invalid", status)
            length = int(encoded_length, 10)
            if length < 1:
                return _HTTPResult(None, attempts, "response_content_length_invalid", status)
            if length > config.max_response_bytes:
                return _HTTPResult(None, attempts, "response_body_oversized", status)
            try:
                payload = response.read(length + 1)
            except http.client.IncompleteRead as exc:
                partial = bytes(exc.partial)
                retained = partial if 0 < len(partial) <= config.max_response_bytes else None
                return _HTTPResult(retained, attempts, "response_body_truncated", status)
            if len(payload) != length:
                return _HTTPResult(
                    payload or None, attempts, "response_body_truncated", status
                )
            if len(payload) > config.max_response_bytes:
                return _HTTPResult(None, attempts, "response_body_oversized", status)
            return _HTTPResult(payload, attempts, None, status)
        except TimeoutError:
            if attempt == config.max_retries:
                return _HTTPResult(None, attempts, "local_timeout", None)
        except (ConnectionRefusedError, ConnectionResetError, http.client.RemoteDisconnected):
            if attempt == config.max_retries:
                return _HTTPResult(None, attempts, "local_connect_error", None)
        except (http.client.HTTPException, OSError):
            if attempt == config.max_retries:
                return _HTTPResult(None, attempts, "local_protocol_error", None)
        finally:
            connection.close()
    raise AssertionError("bounded retry loop did not terminate")


def _decode_canonical_response(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _ResponseFailure("response_json_invalid") from exc
    if type(value) is not dict:
        raise _ResponseFailure("response_json_invalid")
    try:
        _validate_json_value(value, depth=0)
        canonical = _canonical_json_bytes(value)
    except ControlledLocalAdapterContractError as exc:
        raise _ResponseFailure("response_json_invalid") from exc
    if canonical != body:
        raise _ResponseFailure("response_json_noncanonical")
    return value


def _is_completed_response_without_tool_calls(value: dict[str, Any]) -> bool:
    if value.get("object") != "response" or value.get("status") != "completed":
        return False
    output = value.get("output")
    return isinstance(output, list) and not any(
        isinstance(item, dict) and item.get("type") == "function_call" for item in output
    )


def _tool_receipt(
    sequence: int, execution: ProviderToolExecutionV1
) -> ControlledLocalToolReceiptV1:
    decision = execution.decision
    safe_result = execution.provider_response
    result = _extract_synthetic_result(safe_result, decision)
    return ControlledLocalToolReceiptV1(
        sequence=sequence,
        correlation_sha256=execution.correlation_sha256,
        call_id_sha256=decision.call_id_sha256,
        tool_name_sha256=decision.tool_name_sha256,
        arguments_sha256=decision.arguments_sha256,
        policy_sha256=decision.policy_sha256,
        disposition=decision.disposition,
        reason_code=decision.reason_code,
        effect=decision.effect,
        execution_permitted=decision.execution_permitted,
        result_observed=result is not None,
        result_sha256=(
            _domain_sha256("ash-controlled-local-tool-result-v1", result)
            if result is not None
            else ZERO_SHA256
        ),
    )


def _extract_synthetic_result(
    provider_response: dict[str, Any], decision: GatewayDecisionV1
) -> dict[str, Any] | None:
    output = provider_response.get("output")
    if not isinstance(output, str):
        raise ControlledLocalAdapterContractError("provider tool result shape drifted")
    try:
        safe = json.loads(output, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ControlledLocalAdapterContractError("provider tool result is invalid") from exc
    if not isinstance(safe, dict) or set(safe) != {
        "approval_request_sha256",
        "disposition",
        "reason_code",
        "result",
        "schema_version",
    }:
        raise ControlledLocalAdapterContractError("provider tool result shape drifted")
    expected_approval = (
        decision.approval_request().sha256()
        if decision.disposition == "require_approval"
        else None
    )
    if (
        safe["schema_version"] != "AgenticSecurityHarnessGatewayProviderResult.v1"
        or safe["disposition"] != decision.disposition
        or safe["reason_code"] != decision.reason_code
        or safe["approval_request_sha256"] != expected_approval
        or _canonical_json_bytes(safe).decode("utf-8") != output
    ):
        raise ControlledLocalAdapterContractError("provider tool result decision drifted")
    result = safe["result"]
    if result is not None and not isinstance(result, dict):
        raise ControlledLocalAdapterContractError("synthetic tool result shape drifted")
    return result


def _build_request(model_id: str, input_text: str) -> dict[str, Any]:
    _model_sha256(model_id)
    if not isinstance(input_text, str):
        raise ControlledLocalAdapterContractError("local model input must be text")
    if "\x00" in input_text:
        raise ControlledLocalAdapterContractError("local model input contains NUL")
    return {
        "input": input_text,
        "model": model_id,
        "tool_choice": "auto",
        "tools": [
            {
                "description": "Return one fixed synthetic project or gateway status value.",
                "name": "synthetic.lookup",
                "parameters": {
                    "additionalProperties": False,
                    "properties": {
                        "key": {
                            "enum": ["gateway-mode", "project-status"],
                            "type": "string",
                        }
                    },
                    "required": ["key"],
                    "type": "object",
                },
                "strict": True,
                "type": "function",
            },
            {
                "description": "Return SHA-256 of bounded synthetic text.",
                "name": "synthetic.sha256",
                "parameters": {
                    "additionalProperties": False,
                    "properties": {"text": {"maxLength": 16384, "type": "string"}},
                    "required": ["text"],
                    "type": "object",
                },
                "strict": True,
                "type": "function",
            },
        ],
    }


def _model_sha256(value: str) -> str:
    if not isinstance(value, str):
        raise ControlledLocalAdapterContractError("local model id must be text")
    import re

    if re.fullmatch(LOCAL_MODEL_ID_PATTERN, value) is None:
        raise ControlledLocalAdapterContractError(
            "local model id violates the opaque-token contract"
        )
    return _domain_sha256("ash-controlled-local-model-id-v1", value)


def _request_id_sha256(value: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
        raise ControlledLocalAdapterContractError("local request id is empty or oversized")
    return _domain_sha256("ash-controlled-local-request-id-v1", value)


def encode_controlled_local_invocation_receipt_v1(
    receipt: ControlledLocalInvocationReceiptV1,
) -> bytes:
    return _canonical_json_bytes(receipt.model_dump(mode="json"))


def decode_controlled_local_invocation_receipt_v1(
    payload: bytes,
) -> ControlledLocalInvocationReceiptV1:
    if not payload or len(payload) > 65_536:
        raise ControlledLocalAdapterContractError("controlled local receipt is empty or oversized")
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ControlledLocalAdapterContractError(
            "controlled local receipt is invalid JSON"
        ) from exc
    if type(value) is not dict or _canonical_json_bytes(value) != payload:
        raise ControlledLocalAdapterContractError("controlled local receipt is not canonical JSON")
    try:
        return ControlledLocalInvocationReceiptV1.model_validate(value)
    except ValueError as exc:
        raise ControlledLocalAdapterContractError(
            "controlled local receipt violates the closed contract"
        ) from exc


def controlled_local_adapter_v1_json_schemas() -> dict[str, dict[str, Any]]:
    models: tuple[tuple[str, type[BaseModel]], ...] = (
        ("controlled-local-adapter-config.v1.schema.json", ControlledLocalAdapterConfigV1),
        ("controlled-local-tool-receipt.v1.schema.json", ControlledLocalToolReceiptV1),
        (
            "controlled-local-invocation-receipt.v1.schema.json",
            ControlledLocalInvocationReceiptV1,
        ),
    )
    schemas: dict[str, dict[str, Any]] = {}
    for name, model in models:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = (
            "https://github.com/krivonosoff161/agentic-security-harness/blob/main/schemas/"
            + name
        )
        schema["additionalProperties"] = False
        schemas[name] = schema
    return schemas


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_value(value: Any, *, depth: int) -> None:
    if depth > 12:
        raise ControlledLocalAdapterContractError("JSON nesting exceeds the adapter limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ControlledLocalAdapterContractError("JSON contains a non-finite number")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise ControlledLocalAdapterContractError("JSON array exceeds the adapter limit")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 256 or any(not isinstance(key, str) for key in value):
            raise ControlledLocalAdapterContractError("JSON object exceeds the adapter limit")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise ControlledLocalAdapterContractError("JSON contains an unsupported value")


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ControlledLocalAdapterContractError("value is not canonical JSON") from exc


def _domain_sha256(domain: str, value: Any) -> str:
    return _domain_sha256_bytes(domain, _canonical_json_bytes(value))


def _domain_sha256_bytes(domain: str, value: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + value).hexdigest()


__all__ = [
    "ControlledLocalAdapterConfigV1",
    "ControlledLocalAdapterContractError",
    "ControlledLocalAdapterOutcomeV1",
    "ControlledLocalAdapterV1",
    "ControlledLocalInvocationReceiptV1",
    "ControlledLocalToolReceiptV1",
    "LOCAL_RESPONSE_PATH",
    "MAX_LOCAL_REPLAY_IDENTITIES",
    "controlled_local_adapter_v1_json_schemas",
    "decode_controlled_local_invocation_receipt_v1",
    "encode_controlled_local_invocation_receipt_v1",
]
