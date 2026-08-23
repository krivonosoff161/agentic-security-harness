"""Adversarial coverage for the loopback Runtime Gateway contour."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_security_harness import cli
from agentic_security_harness.runtime_gateway import (
    GatewayAuditLedger,
    GatewayConfigV1,
    GatewayContractError,
    GatewayEngine,
    GatewayToolCallV1,
    create_gateway_server,
    default_gateway_policy_v1,
    evaluate_gateway_tool_call,
    load_gateway_config_v1,
    unused_loopback_port,
)
from agentic_security_harness.version import __version__


def _config(tmp_path: Path, port: int | None = None) -> GatewayConfigV1:
    return GatewayConfigV1(
        audit_dir=(tmp_path / "audit").resolve(),
        port=port or unused_loopback_port(),
    )


def _post(
    port: int,
    path: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("POST", path, body=body, headers=request_headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        return response.status, result
    finally:
        connection.close()


def _mcp_meta(*, version: str = "2026-07-28") -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {
            "name": "ash-test-client",
            "version": "1.0.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _mcp_post(
    port: int,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    rpc_id: Any = 1,
    headers: dict[str, str] | None = None,
    version: str = "2026-07-28",
) -> tuple[int, dict[str, Any]]:
    request_params = dict(params or {})
    request_params["_meta"] = _mcp_meta(version=version)
    request_headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }
    name = request_params.get("name")
    if method == "tools/call" and isinstance(name, str):
        request_headers["Mcp-Name"] = name
    request_headers.update(headers or {})
    return _post(
        port,
        "/mcp",
        {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": request_params},
        headers=request_headers,
    )


def _get(port: int, path: str) -> tuple[int, bytes, dict[str, str]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def test_closed_policy_allows_only_two_synthetic_tools() -> None:
    policy = default_gateway_policy_v1()
    assert policy.sha256() == default_gateway_policy_v1().sha256()

    allowed = GatewayToolCallV1(
        call_id="call:1",
        protocol="mcp",
        tool_name="synthetic.lookup",
        arguments={"key": "project-status"},
    )
    denied = GatewayToolCallV1(
        call_id="call:2",
        protocol="mcp",
        tool_name="system.shell",
        arguments={"command": "not-executed"},
    )
    unknown = GatewayToolCallV1(
        call_id="call:3",
        protocol="mcp",
        tool_name="custom.plugin",
        arguments={},
    )

    assert evaluate_gateway_tool_call(allowed).disposition == "allow"
    assert evaluate_gateway_tool_call(denied).disposition == "deny"
    assert evaluate_gateway_tool_call(unknown).reason_code == "unknown_tool_denied"


def test_allowed_tool_arguments_are_closed_and_bounded() -> None:
    invalid = GatewayToolCallV1(
        call_id="call:1",
        protocol="mcp",
        tool_name="synthetic.lookup",
        arguments={"key": "private-value"},
    )
    decision = evaluate_gateway_tool_call(invalid)
    assert decision.disposition == "deny"
    assert decision.reason_code == "tool_arguments_denied"

    with pytest.raises(ValidationError, match="gateway limit"):
        GatewayToolCallV1(
            call_id="call:2",
            protocol="mcp",
            tool_name="synthetic.sha256",
            arguments={"text": "x" * 17_000},
        )


def test_denied_and_approval_calls_never_execute(tmp_path: Path) -> None:
    with GatewayAuditLedger(tmp_path / "audit") as audit:
        engine = GatewayEngine(audit)
        for name in ("system.shell", "external.send", "unknown.tool"):
            decision, result = engine.call_tool(
                GatewayToolCallV1(
                    call_id=f"call:{name}",
                    protocol="mcp",
                    tool_name=name,
                    arguments={},
                ),
                request_id=f"request:{name}",
            )
            assert decision.execution_permitted is False
            assert result is None
        assert engine.execution_count == 0


def test_approval_request_is_stable_privacy_minimized_and_non_executable() -> None:
    call = GatewayToolCallV1(
        call_id="call:approval-private",
        protocol="mcp",
        tool_name="external.send",
        arguments={"destination": "synthetic-private-destination"},
    )
    decision = evaluate_gateway_tool_call(call)
    request = decision.approval_request()

    assert request.status == "pending_non_executable"
    assert request.execution_permitted is False
    assert request.grant_endpoint_available is False
    assert request.sha256() == decision.approval_request().sha256()
    encoded = json.dumps(request.model_dump(mode="json"), sort_keys=True)
    assert "approval-private" not in encoded
    assert "external.send" not in encoded
    assert "synthetic-private-destination" not in encoded

    allowed = evaluate_gateway_tool_call(
        GatewayToolCallV1(
            call_id="call:allowed",
            protocol="mcp",
            tool_name="synthetic.lookup",
            arguments={"key": "project-status"},
        )
    )
    with pytest.raises(GatewayContractError, match="approval-required"):
        allowed.approval_request()


def test_audit_chain_is_privacy_minimized_and_tamper_evident(tmp_path: Path) -> None:
    secret_shaped_input = "synthetic-private-value-never-write"
    root = tmp_path / "audit"
    with GatewayAuditLedger(root) as audit:
        engine = GatewayEngine(audit)
        decision, result = engine.call_tool(
            GatewayToolCallV1(
                call_id="call:private",
                protocol="mcp",
                tool_name="synthetic.sha256",
                arguments={"text": secret_shaped_input},
            ),
            request_id="request:private",
        )
        assert decision.disposition == "allow"
        assert result == {
            "schema_version": "AgenticSecurityHarnessSyntheticToolResult.v1",
            "tool": "synthetic.sha256",
            "sha256": hashlib.sha256(secret_shaped_input.encode()).hexdigest(),
        }
        assert audit.snapshot().records == 1

    ledger_path = root / "gateway-audit.jsonl"
    retained = ledger_path.read_text(encoding="utf-8")
    assert secret_shaped_input not in retained
    assert "synthetic.sha256" not in retained
    assert "request:private" not in retained

    line = bytearray(ledger_path.read_bytes())
    line[line.index(b'"allow"')] = ord("x")
    ledger_path.write_bytes(line)
    with pytest.raises(GatewayContractError):
        GatewayAuditLedger(root)


def test_audit_payload_commitments_are_keyed_per_ledger(tmp_path: Path) -> None:
    commitments: list[str] = []
    for name in ("one", "two"):
        with GatewayAuditLedger(tmp_path / name) as audit:
            record = audit.append(
                request_id="same-request",
                protocol="mcp",
                operation="mcp_tools_list",
                subject="same-subject",
                payload={"short": "guessable"},
                policy_sha256=default_gateway_policy_v1().sha256(),
                disposition="allow",
                reason_code="synthetic_tools_listed",
            )
            commitments.append(record.payload_commitment)
        key = (tmp_path / name / "gateway-audit.key").read_bytes()
        ledger = (tmp_path / name / "gateway-audit.jsonl").read_bytes()
        assert len(key) == 32
        assert key not in ledger
    assert commitments[0] != commitments[1]

    key_path = tmp_path / "one" / "gateway-audit.key"
    key_path.write_bytes(b"x" * 32)
    with pytest.raises(GatewayContractError, match="key identity mismatch"):
        GatewayAuditLedger(tmp_path / "one")


def test_audit_refuses_concurrent_writer(tmp_path: Path) -> None:
    first = GatewayAuditLedger(tmp_path / "audit")
    try:
        with pytest.raises(GatewayContractError, match="another gateway process"):
            GatewayAuditLedger(tmp_path / "audit")
    finally:
        first.close()


def test_config_is_closed_and_resolves_relative_audit_root(tmp_path: Path) -> None:
    config_path = tmp_path / "gateway.toml"
    config_path.write_text(
        '\n'.join(
            [
                'schema_version = "AgenticSecurityHarnessGatewayConfig.v1"',
                'host = "127.0.0.1"',
                "port = 8787",
                'audit_dir = "./runtime-data"',
                "max_body_bytes = 65536",
                "dashboard_enabled = true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    config = load_gateway_config_v1(config_path)
    assert config.audit_dir == (tmp_path / "runtime-data").resolve()

    config_path.write_text(config_path.read_text() + "unknown = true\n", encoding="utf-8")
    with pytest.raises(GatewayContractError, match="closed V1"):
        load_gateway_config_v1(config_path)

    with pytest.raises(ValidationError, match="synthetic_container_mode"):
        GatewayConfigV1(
            host="0.0.0.0",
            audit_dir=(tmp_path / "container-audit").resolve(),
        )


def test_gateway_check_is_read_only_and_path_private(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "gateway.toml"
    audit_dir = tmp_path / "private-audit-location"
    config_path.write_text(
        '\n'.join(
            [
                'schema_version = "AgenticSecurityHarnessGatewayConfig.v1"',
                'host = "127.0.0.1"',
                "port = 8787",
                f'audit_dir = "{audit_dir.as_posix()}"',
                "max_body_bytes = 65536",
                "dashboard_enabled = true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert cli.main(["gateway-check", "--config", str(config_path)]) == 0
    output = capsys.readouterr().out
    assert "valid V1" in output
    assert str(audit_dir) not in output
    assert not audit_dir.exists()


def test_gateway_fixture_cli_runs_offline_without_printing_payload(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "gateway.toml"
    assert cli.main(["gateway-init", "--out", str(config_path)]) == 0
    capsys.readouterr()
    fixture = (
        Path(__file__).parents[1]
        / "examples"
        / "provider-tool-adapters"
        / "openai-responses.json"
    )

    assert (
        cli.main(
            [
                "gateway-fixture",
                "--config",
                str(config_path),
                "--provider",
                "openai_responses",
                "--input",
                str(fixture),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "evaluated offline" in output
    assert "allow=1 deny=0 require_approval=0" in output
    assert "Provider/network/credentials: off" in output
    assert "project-status" not in output
    assert "call_synthetic" not in output
    ledger = tmp_path / ".internal" / "runtime-gateway" / "gateway-audit.jsonl"
    retained = ledger.read_text(encoding="utf-8")
    assert "project-status" not in retained
    assert "call_synthetic" not in retained


def test_gateway_init_creates_once_and_generated_config_validates(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "gateway.toml"
    assert cli.main(["gateway-init", "--out", str(config_path)]) == 0
    capsys.readouterr()
    config = load_gateway_config_v1(config_path)
    assert config.host == "127.0.0.1"
    assert config.audit_dir == (tmp_path / ".internal" / "runtime-gateway").resolve()

    original = config_path.read_bytes()
    assert cli.main(["gateway-init", "--out", str(config_path)]) == 1
    assert config_path.read_bytes() == original


@pytest.fixture
def running_gateway(tmp_path: Path) -> Iterator[tuple[int, GatewayEngine]]:
    config = _config(tmp_path)
    audit = GatewayAuditLedger(config.audit_dir)
    server = create_gateway_server(config, audit=audit)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield config.port, server.engine
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        audit.close()


def test_openai_compatible_safe_and_tool_decision_paths(
    running_gateway: tuple[int, GatewayEngine],
) -> None:
    port, engine = running_gateway
    base = {"messages": [{"role": "user", "content": "untrusted raw text"}]}

    status, safe = _post(port, "/v1/chat/completions", {**base, "model": "ash-fake-safe"})
    assert status == 200
    assert safe["choices"][0]["message"]["content"] == "Synthetic response."

    status, allowed = _post(
        port,
        "/v1/chat/completions",
        {**base, "model": "ash-fake-tool-allow"},
    )
    assert status == 200
    assert "development-contour" in allowed["choices"][0]["message"]["content"]
    assert engine.execution_count == 1

    status, denied = _post(
        port,
        "/v1/chat/completions",
        {**base, "model": "ash-fake-tool-deny"},
    )
    assert status == 403
    assert denied["error"]["code"] == "process_execution_denied"
    assert engine.execution_count == 1

    status, approval = _post(
        port,
        "/v1/chat/completions",
        {**base, "model": "ash-fake-tool-approval"},
    )
    assert status == 409
    assert approval["error"]["code"] == "owner_approval_required"
    assert approval["error"]["approval_status"] == "pending_non_executable"
    assert len(approval["error"]["approval_request_sha256"]) == 64
    assert "not-executed" not in json.dumps(approval)
    assert engine.execution_count == 1


def test_policy_endpoint_exposes_closed_non_authorizing_snapshot(
    running_gateway: tuple[int, GatewayEngine],
) -> None:
    port, engine = running_gateway
    status, body, headers = _get(port, "/v1/gateway/policy")
    payload = json.loads(body)

    assert status == 200
    assert payload == engine.policy_snapshot().model_dump(mode="json")
    assert payload["policy_sha256"] == engine.policy.sha256()
    assert payload["approval_grant_available"] is False
    assert [rule["tool_name"] for rule in payload["rules"]] == [
        "external.send",
        "synthetic.lookup",
        "synthetic.sha256",
        "system.shell",
    ]
    assert headers["Cache-Control"] == "no-store"


def test_mcp_lists_only_executable_synthetic_tools_and_blocks_unknown(
    running_gateway: tuple[int, GatewayEngine],
) -> None:
    port, engine = running_gateway
    status, discovered = _mcp_post(port, "server/discover")
    assert status == 200
    assert discovered["result"]["supportedVersions"] == ["2026-07-28"]
    assert discovered["result"]["resultType"] == "complete"
    assert discovered["result"]["_meta"]["io.modelcontextprotocol/serverInfo"] == {
        "name": "ash-runtime-gateway",
        "version": __version__,
    }

    status, listed = _mcp_post(port, "tools/list")
    assert status == 200
    assert listed["result"]["resultType"] == "complete"
    assert [item["name"] for item in listed["result"]["tools"]] == [
        "synthetic.lookup",
        "synthetic.sha256",
    ]

    status, result = _mcp_post(
        port,
        "tools/call",
        {"name": "synthetic.sha256", "arguments": {"text": "fixture"}},
        rpc_id=2,
    )
    assert status == 200
    assert result["result"]["resultType"] == "complete"
    assert result["result"]["isError"] is False
    assert engine.execution_count == 1

    status, invalid_id = _mcp_post(port, "tools/list", rpc_id={"reflected": "object"})
    assert status == 400
    assert invalid_id["id"] is None
    assert invalid_id["error"]["message"] == "invalid_request"

    status, blocked = _mcp_post(
        port,
        "tools/call",
        {"name": "custom.exec", "arguments": {}},
        rpc_id=3,
    )
    assert status == 400
    assert blocked["error"]["message"] == "tool_call_denied"
    assert blocked["error"]["data"]["gatewayReason"] == "unknown_tool_denied"
    assert engine.execution_count == 1

    status, approval = _mcp_post(
        port,
        "tools/call",
        {"name": "external.send", "arguments": {"destination": "not-executed"}},
        rpc_id=4,
    )
    assert status == 400
    assert approval["error"]["data"]["gatewayReason"] == "owner_approval_required"
    assert approval["error"]["data"]["approvalStatus"] == "pending_non_executable"
    assert len(approval["error"]["data"]["approvalRequestSha256"]) == 64
    assert "not-executed" not in json.dumps(approval)
    assert engine.execution_count == 1


def test_mcp_2026_transport_headers_metadata_and_origin_are_fail_closed(
    running_gateway: tuple[int, GatewayEngine],
) -> None:
    port, _engine = running_gateway

    status, legacy = _mcp_post(port, "initialize")
    assert status == 404
    assert legacy["error"]["code"] == -32601

    status, mismatched = _mcp_post(
        port,
        "tools/list",
        headers={"Mcp-Method": "tools/call"},
    )
    assert status == 400
    assert mismatched["error"]["code"] == -32020

    status, name_mismatch = _mcp_post(
        port,
        "tools/call",
        {"name": "synthetic.lookup", "arguments": {"key": "project-status"}},
        headers={"Mcp-Name": "synthetic.sha256"},
    )
    assert status == 400
    assert name_mismatch["error"]["code"] == -32020

    status, missing_meta = _post(
        port,
        "/mcp",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/list",
        },
    )
    assert status == 400
    assert missing_meta["error"]["message"] == "invalid_request_metadata"

    status, missing_accept = _post(
        port,
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": _mcp_meta()},
        },
        headers={
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/list",
        },
    )
    assert status == 400
    assert missing_accept["error"]["code"] == -32020

    status, unsupported = _mcp_post(port, "tools/list", version="2099-01-01")
    assert status == 400
    assert unsupported["error"]["code"] == -32022
    assert unsupported["error"]["data"]["supportedVersions"] == ["2026-07-28"]

    status, origin = _mcp_post(
        port,
        "tools/list",
        headers={"Origin": "https://attacker.example"},
    )
    assert status == 403
    assert origin["error"]["message"] == "origin_forbidden"

    status, accepted = _mcp_post(
        port,
        "tools/list",
        headers={"Origin": f"http://127.0.0.1:{port}"},
    )
    assert status == 200
    assert accepted["result"]["resultType"] == "complete"

    get_status, get_body, _headers = _get(port, "/mcp")
    assert get_status == 405
    assert json.loads(get_body)["error"]["message"] == "post_required"


def test_http_boundary_rejects_credentials_duplicates_and_oversized_bodies(
    running_gateway: tuple[int, GatewayEngine],
) -> None:
    port, _engine = running_gateway
    status, payload = _mcp_post(
        port,
        "tools/list",
        headers={"Authorization": "Bearer synthetic-do-not-log"},
    )
    assert status == 400
    assert payload["error"]["code"] == "credential_headers_forbidden"

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        duplicate = b'{"model":"ash-fake-safe","model":"other","messages":[]}'
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=duplicate,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 400
        assert json.loads(response.read())["error"]["code"] == "duplicate_json_field"
    finally:
        connection.close()

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/mcp",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "999999"},
        )
        response = connection.getresponse()
        assert response.status == 400
        assert json.loads(response.read())["error"]["code"] == "request_body_limit_exceeded"
    finally:
        connection.close()


def test_dashboard_exposes_only_aggregate_safe_state(
    running_gateway: tuple[int, GatewayEngine],
) -> None:
    port, _engine = running_gateway
    _mcp_post(port, "tools/list")
    status, body, headers = _get(port, "/dashboard")
    assert status == 200
    assert b"Loopback synthetic development contour" in body
    assert b"Approval requests are pending and non-executable" in body
    assert _engine.policy.sha256().encode() in body
    assert b"tools/list" not in body
    assert headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in headers["Content-Security-Policy"]


@pytest.mark.skipif(not hasattr(os, "link"), reason="hardlinks unavailable")
def test_audit_refuses_hardlinked_ledger(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    with GatewayAuditLedger(root) as audit:
        audit.append(
            request_id="request:1",
            protocol="mcp",
            operation="mcp_tools_list",
            subject="tools/list",
            payload={},
            policy_sha256=default_gateway_policy_v1().sha256(),
            disposition="allow",
            reason_code="synthetic_tools_listed",
        )
    link = tmp_path / "ledger-link"
    os.link(root / "gateway-audit.jsonl", link)
    try:
        with pytest.raises(GatewayContractError, match="single-link"):
            GatewayAuditLedger(root)
    finally:
        link.unlink()
