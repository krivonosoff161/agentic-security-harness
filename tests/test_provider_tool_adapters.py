"""Adversarial tests for credential-free provider tool-call normalization."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_security_harness.provider_tool_adapters import (
    MAX_PROVIDER_TOOL_CALLS,
    ProviderFamily,
    ProviderToolAdapterError,
    ProviderToolCallV1,
    execute_provider_tool_payload_v1,
    normalize_provider_tool_calls_v1,
)
from agentic_security_harness.runtime_gateway import GatewayAuditLedger, GatewayEngine

FIXTURES = Path(__file__).parents[1] / "examples" / "provider-tool-adapters"


def _meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "ash-synthetic-fixture",
            "version": "1.0.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _payload(
    provider: ProviderFamily,
    *,
    tool_name: str = "synthetic.lookup",
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    values = arguments or {"key": "project-status"}
    if provider == "openai_responses":
        return {
            "id": "resp_synthetic",
            "object": "response",
            "status": "completed",
            "output": [
                {"type": "output_text", "text": "ignored private-like message"},
                {
                    "type": "function_call",
                    "id": "fc_synthetic",
                    "call_id": "call_synthetic",
                    "name": tool_name,
                    "arguments": json.dumps(values, separators=(",", ":")),
                    "status": "completed",
                },
            ],
        }
    if provider == "anthropic_messages":
        return {
            "id": "msg_synthetic",
            "type": "message",
            "role": "assistant",
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "ignored private-like message"},
                {
                    "type": "tool_use",
                    "id": "toolu_synthetic",
                    "name": tool_name,
                    "input": values,
                },
            ],
        }
    if provider == "google_interactions":
        return {
            "id": "interaction_synthetic",
            "status": "completed",
            "steps": [
                {"type": "text", "text": "ignored private-like message"},
                {
                    "type": "function_call",
                    "id": "gcall_synthetic",
                    "name": tool_name,
                    "arguments": values,
                    "status": "completed",
                },
            ],
        }
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": values, "_meta": _meta()},
    }


@pytest.mark.parametrize(
    "provider",
    ("openai_responses", "anthropic_messages", "google_interactions", "mcp"),
)
def test_all_provider_fixtures_reach_the_same_closed_gateway_policy(
    tmp_path: Path,
    provider: ProviderFamily,
) -> None:
    with GatewayAuditLedger(tmp_path / provider) as audit:
        engine = GatewayEngine(audit)
        executions = execute_provider_tool_payload_v1(
            engine,
            provider,
            _payload(provider),
            request_id=f"request:{provider}",
        )

        assert len(executions) == 1
        execution = executions[0]
        assert execution.provider == provider
        assert execution.decision.disposition == "allow"
        assert execution.decision.execution_permitted is True
        assert engine.execution_count == 1
        assert "development-contour" in json.dumps(execution.provider_response)
        assert audit.read_records()[0].protocol == provider


def test_denied_and_approval_calls_never_reach_a_tool_executor(tmp_path: Path) -> None:
    payload = _payload(
        "openai_responses",
        tool_name="system.shell",
        arguments={"command": "must-not-run"},
    )
    payload["output"].append(
        {
            "type": "function_call",
            "id": "fc_external",
            "call_id": "call_external",
            "name": "external.send",
            "arguments": '{"destination":"must-not-send"}',
            "status": "completed",
        }
    )
    with GatewayAuditLedger(tmp_path / "audit") as audit:
        engine = GatewayEngine(audit)
        executions = execute_provider_tool_payload_v1(
            engine,
            "openai_responses",
            payload,
            request_id="request:denied",
        )

        assert [item.decision.disposition for item in executions] == [
            "deny",
            "require_approval",
        ]
        assert engine.execution_count == 0
        assert all("must-not" not in json.dumps(item.provider_response) for item in executions)
        assert [item.disposition for item in audit.read_records()] == [
            "deny",
            "require_approval",
        ]


def test_adapter_never_retains_message_text_or_raw_arguments(tmp_path: Path) -> None:
    secret_like = "synthetic-private-marker-never-retained"
    payload = _payload("anthropic_messages")
    payload["content"][0]["text"] = secret_like
    payload["content"][1]["input"] = {"key": "project-status"}

    with GatewayAuditLedger(tmp_path / "audit") as audit:
        result = execute_provider_tool_payload_v1(
            GatewayEngine(audit),
            "anthropic_messages",
            payload,
            request_id=secret_like,
        )
        assert secret_like not in json.dumps(result[0].provider_response)

    public_audit = (tmp_path / "audit" / "gateway-audit.jsonl").read_text(
        encoding="utf-8"
    )
    assert secret_like not in public_audit
    assert "project-status" not in public_audit
    assert "toolu_synthetic" not in public_audit


def test_duplicate_json_incomplete_turn_and_unknown_call_fields_fail_closed() -> None:
    duplicate = (
        b'{"object":"response","status":"completed","status":"completed",'
        b'"output":[]}'
    )
    with pytest.raises(ProviderToolAdapterError, match="unique-key"):
        normalize_provider_tool_calls_v1("openai_responses", duplicate)

    incomplete = _payload("openai_responses")
    incomplete["status"] = "in_progress"
    with pytest.raises(ProviderToolAdapterError, match="not completed"):
        normalize_provider_tool_calls_v1("openai_responses", incomplete)

    unknown = _payload("anthropic_messages")
    unknown["content"][1]["authorization"] = "not-trusted"
    with pytest.raises(ProviderToolAdapterError, match="unknown fields"):
        normalize_provider_tool_calls_v1("anthropic_messages", unknown)


def test_tool_call_count_and_payload_size_are_bounded() -> None:
    payload = _payload("google_interactions")
    call = payload["steps"][1]
    payload["steps"] = [dict(call, id=f"gcall_{index}") for index in range(9)]
    assert len(payload["steps"]) == MAX_PROVIDER_TOOL_CALLS + 1
    with pytest.raises(ProviderToolAdapterError, match="tool-call limit"):
        normalize_provider_tool_calls_v1("google_interactions", payload)

    with pytest.raises(ProviderToolAdapterError, match="oversized"):
        normalize_provider_tool_calls_v1("mcp", b"{" + b"x" * 70_000 + b"}")


def test_mcp_metadata_and_numeric_correlation_are_preserved_only_in_response(
    tmp_path: Path,
) -> None:
    payload = _payload("mcp")
    calls = normalize_provider_tool_calls_v1("mcp", payload)
    assert calls[0].correlation_id == 7
    assert calls[0].to_gateway_call().call_id.startswith("provider:")

    broken = _payload("mcp")
    broken["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2025-06-18"
    with pytest.raises(ProviderToolAdapterError, match="2026-07-28"):
        normalize_provider_tool_calls_v1("mcp", broken)

    with GatewayAuditLedger(tmp_path / "audit") as audit:
        response = execute_provider_tool_payload_v1(
            GatewayEngine(audit), "mcp", payload, request_id="request:mcp"
        )[0].provider_response
        assert response["id"] == 7


def test_provider_contract_models_are_closed() -> None:
    with pytest.raises(ValidationError):
        ProviderToolCallV1.model_validate(
            {
                "provider": "openai_responses",
                "correlation_id": "call_1",
                "tool_name": "synthetic.lookup",
                "arguments": {"key": "project-status"},
                "credential": "forbidden",
            }
        )
    with pytest.raises(ProviderToolAdapterError, match="bytes or an exact dict"):
        normalize_provider_tool_calls_v1("openai_responses", ["not", "an", "object"])  # type: ignore[arg-type]


def test_adapter_source_has_no_network_sdk_or_environment_capability() -> None:
    import agentic_security_harness.provider_tool_adapters as module

    source = inspect.getsource(module)
    forbidden = (
        "import requests",
        "import httpx",
        "import socket",
        "import urllib",
        "import openai",
        "import anthropic",
        "from google",
        "os.environ",
        "subprocess",
    )
    assert all(value not in source for value in forbidden)


@pytest.mark.parametrize(
    ("provider", "filename"),
    (
        ("openai_responses", "openai-responses.json"),
        ("anthropic_messages", "anthropic-messages.json"),
        ("google_interactions", "google-interactions.json"),
        ("mcp", "mcp-tools-call.json"),
    ),
)
def test_committed_offline_fixtures_normalize_without_provider_access(
    provider: ProviderFamily,
    filename: str,
) -> None:
    payload = (FIXTURES / filename).read_bytes()
    calls = normalize_provider_tool_calls_v1(provider, payload)
    assert len(calls) == 1
    assert calls[0].provider == provider
    assert calls[0].tool_name == "synthetic.lookup"
