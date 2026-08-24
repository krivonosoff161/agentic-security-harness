from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import agentic_security_harness as ash
from agentic_security_harness.controlled_local_adapter import (
    ControlledLocalAdapterConfigV1,
    ControlledLocalAdapterContractError,
    ControlledLocalAdapterV1,
    controlled_local_adapter_v1_json_schemas,
    decode_controlled_local_invocation_receipt_v1,
    encode_controlled_local_invocation_receipt_v1,
)
from agentic_security_harness.runtime_gateway import GatewayAuditLedger, GatewayEngine


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _response(*calls: dict[str, Any]) -> bytes:
    return _canonical({"object": "response", "output": list(calls), "status": "completed"})


def _call(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "arguments": _canonical(arguments).decode("utf-8"),
        "call_id": call_id,
        "name": name,
        "status": "completed",
        "type": "function_call",
    }


@dataclass
class _Reply:
    body: bytes = field(default_factory=lambda: _response())
    status: int = 200
    content_type: str | None = "application/json"
    content_length: str | None = None
    omit_content_length: bool = False
    duplicate_content_length: bool = False
    transfer_encoding: str | None = None
    content_encoding: str | None = None
    location: str | None = None
    truncate_by: int = 0
    delay_seconds: float = 0.0
    disconnect: bool = False
    signal_event: threading.Event | None = None


@dataclass
class _Plan:
    replies: list[_Reply]
    requests: list[tuple[str, dict[str, str], bytes]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def next_reply(self) -> _Reply:
        with self.lock:
            if not self.replies:
                raise AssertionError("unexpected local adapter request")
            return self.replies.pop(0)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    plan: _Plan


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.plan.requests.append(  # type: ignore[attr-defined]
            (self.path, {key: value for key, value in self.headers.items()}, body)
        )
        reply = self.server.plan.next_reply()  # type: ignore[attr-defined]
        if reply.disconnect:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if reply.delay_seconds:
            time.sleep(reply.delay_seconds)
        try:
            self.send_response(reply.status)
            if reply.content_type is not None:
                self.send_header("Content-Type", reply.content_type)
            if reply.transfer_encoding is not None:
                self.send_header("Transfer-Encoding", reply.transfer_encoding)
            if reply.content_encoding is not None:
                self.send_header("Content-Encoding", reply.content_encoding)
            if reply.location is not None:
                self.send_header("Location", reply.location)
            content_length = reply.content_length
            if (
                content_length is None
                and reply.transfer_encoding is None
                and not reply.omit_content_length
            ):
                content_length = str(len(reply.body) + reply.truncate_by)
            if content_length is not None:
                self.send_header("Content-Length", content_length)
                if reply.duplicate_content_length:
                    self.send_header("Content-Length", content_length)
            self.send_header("Connection", "close")
            self.end_headers()
            if reply.signal_event is not None:
                reply.signal_event.set()
            if reply.transfer_encoding == "chunked":
                self.wfile.write(f"{len(reply.body):x}\r\n".encode("ascii"))
                self.wfile.write(reply.body + b"\r\n0\r\n\r\n")
            else:
                self.wfile.write(reply.body)
        except (BrokenPipeError, ConnectionResetError):
            return
        self.close_connection = True


@contextmanager
def _serve(*replies: _Reply) -> Iterator[tuple[int, _Plan]]:
    plan = _Plan(list(replies))
    server = _Server(("127.0.0.1", 0), _Handler)
    server.plan = plan
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server.server_port, plan
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@contextmanager
def _adapter(
    tmp_path: Path,
    port: int,
    **config_overrides: Any,
) -> Iterator[tuple[ControlledLocalAdapterV1, GatewayEngine]]:
    config = ControlledLocalAdapterConfigV1(port=port, **config_overrides)
    with GatewayAuditLedger(tmp_path / "audit") as audit:
        engine = GatewayEngine(audit)
        yield ControlledLocalAdapterV1(config, engine), engine


def test_config_is_literal_loopback_and_model_ids_are_opaque(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ControlledLocalAdapterConfigV1(host="localhost", port=8080)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ControlledLocalAdapterConfigV1(host="127.0.0.2", port=8080)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ControlledLocalAdapterConfigV1(port=8080, path="/other")  # type: ignore[arg-type]

    bypassed = ControlledLocalAdapterConfigV1.model_construct(
        host="192.0.2.10", port=8080, path="/v1/responses"
    )
    with GatewayAuditLedger(tmp_path / "bypassed-audit") as audit:
        with pytest.raises(ControlledLocalAdapterContractError, match="runtime boundary"):
            ControlledLocalAdapterV1(bypassed, GatewayEngine(audit))

    class _UnsafeEngine(GatewayEngine):
        pass

    with GatewayAuditLedger(tmp_path / "subclass-audit") as audit:
        with pytest.raises(ControlledLocalAdapterContractError, match="closed Runtime"):
            ControlledLocalAdapterV1(
                ControlledLocalAdapterConfigV1(port=8080), _UnsafeEngine(audit)
            )

    with _serve(_Reply(body=_response()), _Reply(body=_response())) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, _engine):
            qwen = adapter.invoke(
                model_id="Qwen/Qwen3-32B",
                input_text="synthetic input",
                request_id="request:qwen",
            )
            deepseek = adapter.invoke(
                model_id="deepseek-ai/DeepSeek-R1",
                input_text="synthetic input",
                request_id="request:deepseek",
            )
    assert qwen.receipt.status == deepseek.receipt.status == "completed"
    assert qwen.receipt.model_sha256 != deepseek.receipt.model_sha256
    assert qwen.receipt.provider_authenticated is False
    assert qwen.receipt.operational_authority == "none"


def test_allowed_call_uses_fixed_transport_and_digest_only_receipt(tmp_path: Path) -> None:
    private_input = "synthetic-private-input-never-retained"
    raw_call_id = "call_private_identifier"
    raw_model = "Qwen/Qwen3-8B"
    body = _response(_call(raw_call_id, "synthetic.lookup", {"key": "project-status"}))
    with _serve(_Reply(body=body)) as (port, plan):
        with _adapter(tmp_path, port) as (adapter, engine):
            outcome = adapter.invoke(
                model_id=raw_model,
                input_text=private_input,
                request_id="request:private",
            )
            assert engine.execution_count == 1
            assert outcome.tool_executions[0].decision.disposition == "allow"
            assert outcome.receipt.audit_records_after == outcome.receipt.audit_records_before + 2

    assert len(plan.requests) == 1
    path, headers, request_body = plan.requests[0]
    assert path == "/v1/responses"
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert headers["Connection"] == "close"
    assert "Authorization" not in headers
    request = json.loads(request_body)
    assert request["model"] == raw_model
    assert [tool["name"] for tool in request["tools"]] == [
        "synthetic.lookup",
        "synthetic.sha256",
    ]
    assert request_body == _canonical(request)

    encoded = encode_controlled_local_invocation_receipt_v1(outcome.receipt)
    assert decode_controlled_local_invocation_receipt_v1(encoded) == outcome.receipt
    for raw in (private_input, raw_call_id, raw_model, "project-status", "synthetic.lookup"):
        assert raw.encode("utf-8") not in encoded
    retained = (tmp_path / "audit" / "gateway-audit.jsonl").read_bytes()
    assert private_input.encode() not in retained
    assert raw_call_id.encode() not in retained
    assert raw_model.encode() not in retained


def test_denied_and_approval_tool_calls_never_dispatch(tmp_path: Path) -> None:
    body = _response(
        _call("deny_1", "system.shell", {"command": "not-executed"}),
        _call("approval_1", "external.send", {"destination": "not-executed"}),
    )
    with _serve(_Reply(body=body)) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, engine):
            outcome = adapter.invoke(
                model_id="local-model",
                input_text="synthetic request",
                request_id="request:blocked",
            )
            assert engine.execution_count == 0
    assert [item.disposition for item in outcome.receipt.tools] == [
        "deny",
        "require_approval",
    ]
    assert all(not item.execution_permitted for item in outcome.receipt.tools)
    assert all(not item.result_observed for item in outcome.receipt.tools)
    encoded = encode_controlled_local_invocation_receipt_v1(outcome.receipt)
    assert b"not-executed" not in encoded
    assert outcome.receipt.operational_authority == "none"


def test_replayed_or_duplicate_tool_identity_is_denied_before_dispatch(tmp_path: Path) -> None:
    call = _call("same_call", "synthetic.lookup", {"key": "gateway-mode"})
    with _serve(
        _Reply(body=_response(call)),
        _Reply(body=_response(call)),
    ) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, engine):
            first = adapter.invoke(
                model_id="local-model", input_text="one", request_id="request:one"
            )
            replay = adapter.invoke(
                model_id="local-model", input_text="two", request_id="request:two"
            )
            assert engine.execution_count == 1
    assert first.receipt.status == "completed"
    assert replay.receipt.status == "error"
    assert replay.receipt.reason_code == "tool_call_replay_denied"
    assert replay.receipt.tools == ()

    with _serve(_Reply(body=_response(call, call))) as (port, _plan):
        with _adapter(tmp_path / "duplicate", port) as (adapter, engine):
            duplicate = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:duplicate"
            )
            assert engine.execution_count == 0
    assert duplicate.receipt.reason_code == "tool_call_identity_duplicate"


def test_concurrent_replay_dispatches_exactly_once(tmp_path: Path) -> None:
    call = _call("concurrent_call", "synthetic.lookup", {"key": "gateway-mode"})
    outcomes: list[Any] = []
    with _serve(_Reply(body=_response(call)), _Reply(body=_response(call))) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, engine):
            threads = [
                threading.Thread(
                    target=lambda index=index: outcomes.append(
                        adapter.invoke(
                            model_id="local-model",
                            input_text=f"input-{index}",
                            request_id=f"request:concurrent:{index}",
                        )
                    )
                )
                for index in range(2)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            assert engine.execution_count == 1
    assert len(outcomes) == 2
    assert sorted(item.receipt.reason_code for item in outcomes) == [
        "completed_with_tool_calls",
        "tool_call_replay_denied",
    ]


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (_Reply(status=302, location="http://127.0.0.1:1/other"), "redirect_forbidden"),
        (_Reply(status=401), "response_http_status_invalid"),
        (_Reply(content_type="text/plain"), "response_content_type_invalid"),
        (_Reply(content_type=None), "response_content_type_invalid"),
        (_Reply(omit_content_length=True), "response_content_length_missing"),
        (_Reply(transfer_encoding="chunked"), "response_transfer_encoding_forbidden"),
        (_Reply(content_encoding="gzip"), "response_content_encoding_forbidden"),
        (_Reply(content_length="invalid"), "response_content_length_invalid"),
        (_Reply(content_length="+2"), "response_content_length_invalid"),
        (_Reply(content_length="02"), "response_content_length_invalid"),
        (
            _Reply(content_length="2", duplicate_content_length=True),
            "response_content_length_duplicate",
        ),
        (_Reply(body=b"{}", content_length="70000"), "response_body_oversized"),
        (_Reply(body=b"{}", truncate_by=4), "response_body_truncated"),
    ],
)
def test_response_boundary_fails_closed(
    tmp_path: Path, reply: _Reply, reason: str
) -> None:
    with _serve(reply) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, engine):
            outcome = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:boundary"
            )
            assert engine.execution_count == 0
    assert outcome.receipt.status == "error"
    assert outcome.receipt.reason_code == reason
    assert outcome.receipt.tools == ()


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b'{"object":"response","object":"response","output":[],"status":"completed"}',
         "response_json_invalid"),
        (b'{"object": "response", "output": [], "status": "completed"}',
         "response_json_noncanonical"),
        (b"not-json", "response_json_invalid"),
        (
            (b'{"object":"response","output":' + b"[" * 20 + b"]" * 20
             + b',"status":"completed"}'),
            "response_json_invalid",
        ),
        (_canonical({"object": "response", "output": {}, "status": "completed"}),
         "response_tool_payload_invalid"),
        (_canonical({"object": "response", "output": [], "status": "failed"}),
         "response_tool_payload_invalid"),
    ],
)
def test_malformed_provider_responses_do_not_reach_gateway(
    tmp_path: Path, body: bytes, reason: str
) -> None:
    with _serve(_Reply(body=body)) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, engine):
            outcome = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:malformed"
            )
            assert engine.execution_count == 0
    assert outcome.receipt.reason_code == reason


def test_transport_ignores_proxy_environment_and_never_resolves_dns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://192.0.2.1:9")

    def forbidden_resolution(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("DNS resolution must not be called")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_resolution)
    with _serve(_Reply(body=_response())) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, _engine):
            outcome = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:no-proxy"
            )
    assert outcome.receipt.status == "completed"
    assert outcome.receipt.network_scope == "literal_loopback_http"


def test_retry_is_bounded_and_only_pre_dispatch(tmp_path: Path) -> None:
    body = _response(_call("retry_call", "synthetic.lookup", {"key": "project-status"}))
    with _serve(_Reply(disconnect=True), _Reply(body=body)) as (port, plan):
        with _adapter(tmp_path, port, max_retries=1) as (adapter, engine):
            outcome = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:retry"
            )
            assert engine.execution_count == 1
    assert len(plan.requests) == 2
    assert outcome.receipt.network_attempts == 2
    assert outcome.receipt.status == "completed"


def test_timeout_cancellation_and_request_limit_are_closed(tmp_path: Path) -> None:
    with _serve(_Reply(body=_response(), delay_seconds=0.2)) as (port, _plan):
        with _adapter(tmp_path, port, timeout_milliseconds=50) as (adapter, engine):
            timeout = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:timeout"
            )
            assert engine.execution_count == 0
    assert timeout.receipt.reason_code == "local_timeout"

    cancelled_event = threading.Event()
    cancelled_event.set()
    with _serve() as (port, plan):
        with _adapter(tmp_path / "cancel", port) as (adapter, engine):
            cancelled = adapter.invoke(
                model_id="local-model",
                input_text="input",
                request_id="request:cancelled",
                cancel_event=cancelled_event,
            )
            assert engine.execution_count == 0
    assert plan.requests == []
    assert cancelled.receipt.status == "cancelled"
    assert cancelled.receipt.reason_code == "cancelled_before_request"
    assert cancelled.receipt.network_attempts == 0

    after_response_event = threading.Event()
    with _serve(_Reply(body=_response(), signal_event=after_response_event)) as (port, _plan):
        with _adapter(tmp_path / "cancel-after", port) as (adapter, engine):
            cancelled_after = adapter.invoke(
                model_id="local-model",
                input_text="input",
                request_id="request:cancelled-after",
                cancel_event=after_response_event,
            )
            assert engine.execution_count == 0
    assert cancelled_after.receipt.status == "cancelled"
    assert cancelled_after.receipt.reason_code == "cancelled_after_response"
    assert cancelled_after.receipt.response_observed is True

    with _serve() as (port, plan):
        with _adapter(tmp_path / "oversize", port, max_request_bytes=1024) as (adapter, _engine):
            with pytest.raises(ControlledLocalAdapterContractError, match="configured limit"):
                adapter.invoke(
                    model_id="local-model",
                    input_text="x" * 2_000,
                    request_id="request:oversized",
                )
    assert plan.requests == []


def test_receipt_codec_rejects_tampering_unknown_fields_and_noncanonical_bytes(
    tmp_path: Path,
) -> None:
    with _serve(_Reply(body=_response())) as (port, _plan):
        with _adapter(tmp_path, port) as (adapter, _engine):
            outcome = adapter.invoke(
                model_id="local-model", input_text="input", request_id="request:receipt"
            )
    encoded = encode_controlled_local_invocation_receipt_v1(outcome.receipt)
    payload = json.loads(encoded)
    payload["network_attempts"] = 2
    with pytest.raises(ControlledLocalAdapterContractError, match="closed contract"):
        decode_controlled_local_invocation_receipt_v1(_canonical(payload))
    payload = json.loads(encoded)
    payload["unknown"] = True
    with pytest.raises(ControlledLocalAdapterContractError, match="closed contract"):
        decode_controlled_local_invocation_receipt_v1(_canonical(payload))
    with pytest.raises(ControlledLocalAdapterContractError, match="not canonical"):
        decode_controlled_local_invocation_receipt_v1(encoded + b"\n")


def test_generated_schemas_are_closed() -> None:
    schemas = controlled_local_adapter_v1_json_schemas()
    assert set(schemas) == {
        "controlled-local-adapter-config.v1.schema.json",
        "controlled-local-invocation-receipt.v1.schema.json",
        "controlled-local-tool-receipt.v1.schema.json",
    }
    assert all(schema["additionalProperties"] is False for schema in schemas.values())


def test_controlled_adapter_is_exported_from_installed_package_surface() -> None:
    assert ash.ControlledLocalAdapterV1 is ControlledLocalAdapterV1
    assert ash.ControlledLocalAdapterConfigV1 is ControlledLocalAdapterConfigV1
