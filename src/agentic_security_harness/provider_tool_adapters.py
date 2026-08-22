"""Credential-free provider tool-call normalization for the Runtime Gateway.

This module does not import a provider SDK, open a socket, read environment variables,
or execute arbitrary tools. It accepts already-retained synthetic response payloads,
normalizes supported tool calls into the closed Runtime Gateway contract, and formats
provider-shaped synthetic results after policy evaluation.

The provider-shaped result is transient interoperability data, not an evidence receipt or
an authenticated statement from a provider.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.runtime_gateway import (
    MCP_META_CLIENT_CAPABILITIES,
    MCP_META_CLIENT_INFO,
    MCP_META_PROTOCOL_VERSION,
    MCP_PROTOCOL_VERSION,
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayContractError,
    GatewayDecisionV1,
    GatewayEngine,
    GatewayProtocol,
    GatewayToolCallV1,
)

ProviderFamily = Literal[
    "openai_responses",
    "anthropic_messages",
    "google_interactions",
    "mcp",
]

MAX_PROVIDER_PAYLOAD_BYTES = 65_536
MAX_PROVIDER_TOOL_CALLS = 8
MAX_PROVIDER_ITEMS = 64
MAX_PROVIDER_CORRELATION_BYTES = 256


class ProviderToolAdapterError(GatewayContractError):
    """Raised before gateway dispatch when a provider envelope is invalid."""


class ProviderToolCallV1(BaseModel):
    """One transient provider call normalized without retaining message text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessProviderToolCall.v1"] = (
        "AgenticSecurityHarnessProviderToolCall.v1"
    )
    provider: ProviderFamily
    correlation_id: str | int = Field(repr=False)
    tool_name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    arguments: dict[str, Any] = Field(default_factory=dict, repr=False)

    @model_validator(mode="after")
    def _bounded(self) -> ProviderToolCallV1:
        if isinstance(self.correlation_id, bool):
            raise ValueError("provider correlation id must not be boolean")
        correlation = str(self.correlation_id)
        if not correlation or len(correlation.encode("utf-8")) > MAX_PROVIDER_CORRELATION_BYTES:
            raise ValueError("provider correlation id is empty or oversized")
        _validate_json_value(self.arguments, depth=0)
        if len(_canonical_json_bytes(self.arguments)) > 16_384:
            raise ValueError("provider tool arguments exceed the gateway limit")
        return self

    def correlation_sha256(self) -> str:
        return _domain_sha256(
            "ash-provider-correlation-v1",
            {"provider": self.provider, "value": self.correlation_id},
        )

    def to_gateway_call(self) -> GatewayToolCallV1:
        protocol: GatewayProtocol = self.provider
        return GatewayToolCallV1(
            call_id=f"provider:{self.correlation_sha256()}",
            protocol=protocol,
            tool_name=self.tool_name,
            arguments=self.arguments,
        )


class ProviderToolExecutionV1(BaseModel):
    """Transient result of one normalized call; not a persisted evidence artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessProviderToolExecution.v1"] = (
        "AgenticSecurityHarnessProviderToolExecution.v1"
    )
    provider: ProviderFamily
    correlation_sha256: str = Field(pattern=SHA256_PATTERN)
    tool_name_sha256: str = Field(pattern=SHA256_PATTERN)
    decision: GatewayDecisionV1
    provider_response: dict[str, Any] = Field(repr=False)

    @model_validator(mode="after")
    def _bounded_response(self) -> ProviderToolExecutionV1:
        _validate_json_value(self.provider_response, depth=0)
        if len(_canonical_json_bytes(self.provider_response)) > 32_768:
            raise ValueError("provider response exceeds the adapter limit")
        return self


def normalize_provider_tool_calls_v1(
    provider: ProviderFamily,
    payload: bytes | dict[str, Any],
) -> tuple[ProviderToolCallV1, ...]:
    """Parse one closed, non-streaming provider response or MCP request.

    Unrelated text/content blocks are ignored and never copied into the normalized call.
    A payload with no supported tool call fails closed rather than being interpreted as a
    successful no-op.
    """

    root = _decode_payload(payload)
    if provider == "openai_responses":
        calls = _normalize_openai_responses(root)
    elif provider == "anthropic_messages":
        calls = _normalize_anthropic_messages(root)
    elif provider == "google_interactions":
        calls = _normalize_google_interactions(root)
    elif provider == "mcp":
        calls = _normalize_mcp(root)
    else:  # pragma: no cover - Literal plus runtime guard for untyped callers
        raise ProviderToolAdapterError("unsupported provider adapter")
    if not calls:
        raise ProviderToolAdapterError("provider payload contains no supported tool call")
    if len(calls) > MAX_PROVIDER_TOOL_CALLS:
        raise ProviderToolAdapterError("provider payload exceeds the tool-call limit")
    return tuple(calls)


def execute_provider_tool_payload_v1(
    engine: GatewayEngine,
    provider: ProviderFamily,
    payload: bytes | dict[str, Any],
    *,
    request_id: str,
) -> tuple[ProviderToolExecutionV1, ...]:
    """Normalize, policy-check, and dispatch only the gateway's synthetic tools."""

    calls = normalize_provider_tool_calls_v1(provider, payload)
    executions: list[ProviderToolExecutionV1] = []
    for index, call in enumerate(calls):
        decision, result = engine.call_tool(
            call.to_gateway_call(),
            request_id=f"{request_id}:{index}",
        )
        response = _format_provider_response(call, decision, result)
        executions.append(
            ProviderToolExecutionV1(
                provider=provider,
                correlation_sha256=call.correlation_sha256(),
                tool_name_sha256=_domain_sha256(
                    "ash-provider-tool-name-v1", call.tool_name
                ),
                decision=decision,
                provider_response=response,
            )
        )
    return tuple(executions)


def _normalize_openai_responses(root: dict[str, Any]) -> list[ProviderToolCallV1]:
    if root.get("object") != "response" or root.get("status") != "completed":
        raise ProviderToolAdapterError("OpenAI Responses payload is not completed")
    items = _bounded_list(root.get("output"), label="OpenAI output")
    calls: list[ProviderToolCallV1] = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "function_call":
            continue
        _require_keys(
            item,
            required={"type", "call_id", "name", "arguments", "status"},
            allowed={"type", "id", "call_id", "name", "arguments", "status"},
            label="OpenAI function call",
        )
        if item["status"] != "completed":
            raise ProviderToolAdapterError("OpenAI function call is incomplete")
        calls.append(
            _call(
                "openai_responses",
                item["call_id"],
                item["name"],
                _decode_arguments_json(item["arguments"], label="OpenAI arguments"),
            )
        )
    return calls


def _normalize_anthropic_messages(root: dict[str, Any]) -> list[ProviderToolCallV1]:
    if (
        root.get("type") != "message"
        or root.get("role") != "assistant"
        or root.get("stop_reason") != "tool_use"
    ):
        raise ProviderToolAdapterError("Anthropic Messages payload is not a tool-use turn")
    items = _bounded_list(root.get("content"), label="Anthropic content")
    calls: list[ProviderToolCallV1] = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "tool_use":
            continue
        _require_keys(
            item,
            required={"type", "id", "name", "input"},
            allowed={"type", "id", "name", "input"},
            label="Anthropic tool_use block",
        )
        calls.append(
            _call("anthropic_messages", item["id"], item["name"], item["input"])
        )
    return calls


def _normalize_google_interactions(root: dict[str, Any]) -> list[ProviderToolCallV1]:
    if root.get("status") != "completed":
        raise ProviderToolAdapterError("Google interaction is not completed")
    items = _bounded_list(root.get("steps"), label="Google interaction steps")
    calls: list[ProviderToolCallV1] = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "function_call":
            continue
        _require_keys(
            item,
            required={"type", "id", "name", "arguments"},
            allowed={"type", "id", "name", "arguments", "status"},
            label="Google function_call step",
        )
        if item.get("status", "completed") != "completed":
            raise ProviderToolAdapterError("Google function call is incomplete")
        calls.append(
            _call(
                "google_interactions",
                item["id"],
                item["name"],
                item["arguments"],
            )
        )
    return calls


def _normalize_mcp(root: dict[str, Any]) -> list[ProviderToolCallV1]:
    _require_keys(
        root,
        required={"jsonrpc", "id", "method", "params"},
        allowed={"jsonrpc", "id", "method", "params"},
        label="MCP request",
    )
    if root["jsonrpc"] != "2.0" or root["method"] != "tools/call":
        raise ProviderToolAdapterError("MCP adapter accepts only tools/call")
    params = _require_dict(root["params"], label="MCP params")
    _require_keys(
        params,
        required={"name", "arguments", "_meta"},
        allowed={"name", "arguments", "_meta"},
        label="MCP tools/call params",
    )
    meta = _require_dict(params["_meta"], label="MCP _meta")
    required_meta = {
        MCP_META_PROTOCOL_VERSION,
        MCP_META_CLIENT_INFO,
        MCP_META_CLIENT_CAPABILITIES,
    }
    if set(meta) != required_meta or meta[MCP_META_PROTOCOL_VERSION] != MCP_PROTOCOL_VERSION:
        raise ProviderToolAdapterError("MCP metadata violates the 2026-07-28 contract")
    _require_dict(meta[MCP_META_CLIENT_INFO], label="MCP clientInfo")
    _require_dict(meta[MCP_META_CLIENT_CAPABILITIES], label="MCP clientCapabilities")
    return [_call("mcp", root["id"], params["name"], params["arguments"])]


def _call(
    provider: ProviderFamily,
    correlation_id: Any,
    tool_name: Any,
    arguments: Any,
) -> ProviderToolCallV1:
    if not isinstance(correlation_id, (str, int)) or isinstance(correlation_id, bool):
        raise ProviderToolAdapterError("provider correlation id has the wrong type")
    if provider != "mcp" and not isinstance(correlation_id, str):
        raise ProviderToolAdapterError("provider correlation id must be a string")
    if not isinstance(tool_name, str):
        raise ProviderToolAdapterError("provider tool name has the wrong type")
    if not isinstance(arguments, dict):
        raise ProviderToolAdapterError("provider tool arguments must be an object")
    try:
        return ProviderToolCallV1(
            provider=provider,
            correlation_id=correlation_id,
            tool_name=tool_name,
            arguments=arguments,
        )
    except ValueError as exc:
        raise ProviderToolAdapterError("provider tool call violates the closed contract") from exc


def _format_provider_response(
    call: ProviderToolCallV1,
    decision: GatewayDecisionV1,
    result: dict[str, Any] | None,
) -> dict[str, Any]:
    safe_result = {
        "schema_version": "AgenticSecurityHarnessGatewayProviderResult.v1",
        "disposition": decision.disposition,
        "reason_code": decision.reason_code,
        "result": result,
    }
    text = _canonical_json_bytes(safe_result).decode("utf-8")
    is_error = not decision.execution_permitted
    if call.provider == "openai_responses":
        return {
            "type": "function_call_output",
            "call_id": call.correlation_id,
            "output": text,
        }
    if call.provider == "anthropic_messages":
        return {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": call.correlation_id,
                    "content": text,
                    "is_error": is_error,
                }
            ],
        }
    if call.provider == "google_interactions":
        return {
            "type": "function_result",
            "name": call.tool_name,
            "call_id": call.correlation_id,
            "result": [{"type": "text", "text": text}],
        }
    return {
        "jsonrpc": "2.0",
        "id": call.correlation_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "structuredContent": safe_result,
            "isError": is_error,
        },
    }


def _decode_payload(payload: bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, bytes):
        if not payload or len(payload) > MAX_PROVIDER_PAYLOAD_BYTES:
            raise ProviderToolAdapterError("provider payload is empty or oversized")
        try:
            value = json.loads(payload, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProviderToolAdapterError("provider payload is not unique-key JSON") from exc
    elif type(payload) is dict:
        value = payload
    else:
        raise ProviderToolAdapterError("provider payload must be bytes or an exact dict")
    if not isinstance(value, dict):
        raise ProviderToolAdapterError("provider payload root must be an object")
    _validate_json_value(value, depth=0)
    if len(_canonical_json_bytes(value)) > MAX_PROVIDER_PAYLOAD_BYTES:
        raise ProviderToolAdapterError("provider payload exceeds the canonical byte limit")
    return value


def _decode_arguments_json(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 16_384:
        raise ProviderToolAdapterError(f"{label} must be bounded JSON text")
    try:
        decoded = json.loads(value, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProviderToolAdapterError(f"{label} is not unique-key JSON") from exc
    return _require_dict(decoded, label=label)


def _bounded_list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > MAX_PROVIDER_ITEMS:
        raise ProviderToolAdapterError(f"{label} must be a bounded array")
    return value


def _require_dict(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderToolAdapterError(f"{label} must be an object")
    return value


def _require_keys(
    value: dict[str, Any],
    *,
    required: set[str],
    allowed: set[str],
    label: str,
) -> None:
    keys = set(value)
    if not required <= keys or not keys <= allowed:
        raise ProviderToolAdapterError(f"{label} has missing or unknown fields")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_value(value: Any, *, depth: int) -> None:
    if depth > 12:
        raise ProviderToolAdapterError("provider payload nesting exceeds the limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ProviderToolAdapterError("provider payload contains a non-finite number")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise ProviderToolAdapterError("provider payload array exceeds the limit")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 256 or any(not isinstance(key, str) for key in value):
            raise ProviderToolAdapterError("provider payload object exceeds the limit")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise ProviderToolAdapterError("provider payload contains an unsupported JSON value")


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProviderToolAdapterError("provider payload is not canonical JSON") from exc


def _domain_sha256(domain: str, value: Any) -> str:
    payload = domain.encode("ascii") + b"\0" + _canonical_json_bytes(value)
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "MAX_PROVIDER_PAYLOAD_BYTES",
    "MAX_PROVIDER_TOOL_CALLS",
    "ProviderFamily",
    "ProviderToolAdapterError",
    "ProviderToolCallV1",
    "ProviderToolExecutionV1",
    "execute_provider_tool_payload_v1",
    "normalize_provider_tool_calls_v1",
]
