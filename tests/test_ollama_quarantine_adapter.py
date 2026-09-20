"""Public fixtures and owned loopback servers only; no installed model is contacted."""

from __future__ import annotations

import hashlib
import json
import socketserver
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from pydantic import ValidationError

import agentic_security_harness.ollama_quarantine_adapter as adapter
from agentic_security_harness.quarantine_connector import (
    ProviderAdapterProfileRegistryV1,
    ProviderAdapterProfileV1,
    QuarantineCapabilityBindingV1,
)
from agentic_security_harness.runtime_gateway import GatewayEngine, default_gateway_policy_v1

MODEL = "public-toy:latest"


def _registry() -> ProviderAdapterProfileRegistryV1:
    return ProviderAdapterProfileRegistryV1(
        profiles=(
            ProviderAdapterProfileV1(
                profile_id="fixture.ollama",
                profile_version="v1",
                capabilities=(
                    QuarantineCapabilityBindingV1(
                        capability_id="bounded.lookup",
                        gateway_protocol="mcp",
                        gateway_tool_name="synthetic.lookup",
                        allowed_argument_keys=("key",),
                        required_argument_keys=("key",),
                    ),
                ),
            ),
        )
    )


def _arguments() -> dict[str, Any]:
    return {
        "model_id": MODEL,
        "request_id": "request:fixture",
        "registry": _registry(),
        "selected_profile_id": "fixture.ollama",
        "selected_profile_version": "v1",
        "gateway_policy": default_gateway_policy_v1(),
    }


def _proposal(key: Any = "project-status", capability: str = "bounded.lookup") -> dict[str, Any]:
    return {"capability_id": capability, "arguments": {"key": key}}


def _body(proposal: Any = None, **changes: Any) -> bytes:
    value = {
        "model": MODEL,
        "done": True,
        "done_reason": "stop",
        "response": json.dumps(_proposal() if proposal is None else proposal),
        "created_at": "2026-09-20T00:00:00Z",
        "context": [1, 2, 3],
        "prompt_eval_count": 10,
        "eval_count": 12,
    }
    value.update(changes)
    return json.dumps(value).encode()


def _evaluate(body: bytes, **changes: Any) -> adapter.OllamaQuarantineOutcomeV1:
    return adapter.evaluate_ollama_generate_response_v1(body, **(_arguments() | changes))


def _unexpected(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("no executor/network effect expected")


@pytest.fixture(autouse=True)
def _no_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(GatewayEngine, "call_tool", _unexpected)


@pytest.mark.parametrize(
    ("proposal", "disposition", "decision"),
    [
        (_proposal(), "admit", "allow"),
        (_proposal("gateway-mode"), "admit", "allow"),
        (_proposal("unknown-public-key"), "admit", "deny"),
        (_proposal({"authority": "admin"}), "reject", None),
        (_proposal(capability="unregistered.capability"), "reject", None),
        ({"no_request": True}, "admit", None),
    ],
)
def test_native_proposal_reaches_unchanged_policy(
    proposal: Any,
    disposition: str,
    decision: str | None,
) -> None:
    result = _evaluate(_body(proposal))
    assert result.reason_code == "evaluated"
    assert result.composition is not None
    assert result.composition.connector_disposition == disposition
    value = result.composition.gateway_decision
    assert (value.disposition if value else None) == decision
    assert result.composition.gateway_evaluated == (decision is not None)
    assert result.operational_authority == "none" and result.dispatch_performed is False
    assert result.transport_attempts == 0


def test_whitespace_is_normalized_but_semantic_values_are_not_repaired() -> None:
    plain = _evaluate(_body())
    spaced = _evaluate(
        _body(
            response='\n { "arguments" : {"key":"project-status"}, '
            '"capability_id" : "bounded.lookup" } \n'
        )
    )
    assert plain.composition == spaced.composition
    assert plain.proposal_sha256 == spaced.proposal_sha256
    assert plain.response_sha256 != spaced.response_sha256
    changed = _evaluate(_body(_proposal("PROJECT-STATUS")))
    assert changed.composition is not None and changed.composition.gateway_decision is not None
    assert changed.composition.gateway_decision.disposition == "deny"
    assert changed.proposal_sha256 != plain.proposal_sha256


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        None,
        True,
        {"no_request": False},
        {"no_request": 1},
        {"no_request": True, "allow": True},
        {"capability_id": "bounded.lookup"},
        {"capability_id": True, "arguments": {}},
        {"capability_id": "bounded.lookup", "arguments": []},
        _proposal() | {"profile_id": "other"},
        _proposal() | {"request_id": "chosen-by-model"},
        _proposal() | {"allow": True},
        _proposal() | {"policy": "bypass"},
        _proposal() | {"endpoint": "public-toy-only"},
    ],
)
def test_proposal_does_not_override_application_fields(value: Any) -> None:
    result = _evaluate(_body(response=json.dumps(value)))
    assert result.reason_code in {"proposal_shape_invalid", "proposal_json_invalid"}
    assert result.composition is None


@pytest.mark.parametrize(
    "text",
    [
        '{"capability_id":"bounded.lookup","capability_id":"other","arguments":{}}',
        '{"capability_id":"bounded.lookup","arguments":{"key":"project-status","key":"x"}}',
        '{"capability_id":"bounded.lookup","arguments":{"key":NaN}}',
        '{"capability_id":"bounded.lookup","arguments":{"key":1e999}}',
        '{"capability_id":"bounded.lookup","arguments":{"key":"\\ud800"}}',
        "```json\n{}\n```",
        "{",
        "[]",
        "null",
        '{"x":' + "[" * 14 + "0" + "]" * 14 + "}",
        '{"x":"' + "a" * 16384 + '"}',
    ],
    ids=[
        "duplicate-capability",
        "duplicate-key",
        "nan",
        "infinity",
        "surrogate",
        "markdown",
        "truncated",
        "array",
        "null",
        "depth",
        "oversized",
    ],
)
def test_malformed_proposal_is_never_silently_no_request(text: str) -> None:
    result = _evaluate(_body(response=text))
    assert result.reason_code == "proposal_json_invalid"
    assert result.composition is None


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"model": "different"}, "model_mismatch"),
        ({"done": False}, "generation_incomplete"),
        ({"done": 1}, "generation_incomplete"),
        ({"done_reason": "length"}, "generation_incomplete"),
        ({"tool_calls": []}, "outer_contract_invalid"),
        ({"response": {}}, "outer_contract_invalid"),
        ({"thinking": "public synthetic hidden channel"}, "outer_contract_invalid"),
        ({"context": [True]}, "outer_contract_invalid"),
        ({"context": {"role": "admin"}}, "outer_contract_invalid"),
        ({"prompt_eval_count": True}, "outer_contract_invalid"),
        ({"eval_count": -1}, "outer_contract_invalid"),
        ({"created_at": []}, "outer_contract_invalid"),
    ],
)
def test_outer_contract_is_explicit(changes: dict[str, Any], reason: str) -> None:
    assert _evaluate(_body(**changes)).reason_code == reason


@pytest.mark.parametrize("raw", [b"{", b"[]", b'{"model":1,"model":2}', b"\xff"])
def test_invalid_outer_json(raw: bytes) -> None:
    assert _evaluate(raw).reason_code == "outer_json_invalid"


def test_missing_or_oversized_outer() -> None:
    assert _evaluate(b"{}").reason_code == "outer_contract_invalid"
    result = _evaluate(b"x" * (adapter.MAX_RESPONSE_BYTES + 1))
    assert result.reason_code == "response_too_large" and result.response_sha256 is None


def test_no_request_contract_cannot_be_changed_to_a_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "compose_quarantine_gateway_v1", _unexpected)
    assert _evaluate(_body(), require_no_request=True).reason_code == "proposal_shape_invalid"


def test_receipt_has_no_raw_content() -> None:
    canary = "PUBLIC_SYNTHETIC_CANARY_NOT_PRIVATE"
    result = _evaluate(_body(_proposal(canary)))
    text = result.model_dump_json()
    for value in (canary, MODEL, "bounded.lookup", "fixture.ollama", "request:fixture"):
        # Composition has safe profile id/version by its existing public contract.
        if value != "fixture.ollama":
            assert value not in text
    assert (
        result.proposal_sha256 == hashlib.sha256(adapter._canonical(_proposal(canary))).hexdigest()
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "localhost"},
        {"host": "192.0.2.1"},
        {"port": True},
        {"port": 0},
        {"timeout_seconds": 0.0},
        {"timeout_seconds": float("inf")},
        {"path": "/other"},
        {"headers": {}},
        {"max_response_bytes": 65537},
    ],
)
def test_config_has_no_remote_or_credential_surface(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        adapter.OllamaQuarantineConfigV1(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"model_id": "bad model"},
        {"model_id": "public-toy:cloud"},
        {"model_id": "public-toy:CLOUD"},
        {"request_id": "bad request"},
        {"selected_profile_id": "missing"},
        {"selected_profile_version": "missing"},
    ],
)
def test_invalid_binding_fails_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    monkeypatch.setattr(adapter, "_post", _unexpected)
    with pytest.raises(ValueError):
        adapter.invoke_ollama_quarantine_v1(
            adapter.OllamaQuarantineConfigV1(), prompt="public", **(_arguments() | changes)
        )


def test_constructed_remote_config_cannot_bypass_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "_post", _unexpected)
    config = adapter.OllamaQuarantineConfigV1.model_construct(host="192.0.2.1")
    with pytest.raises(ValueError):
        adapter.invoke_ollama_quarantine_v1(config, prompt="public", **_arguments())


def test_schema_does_not_choose_capability_or_argument_values() -> None:
    schema = adapter.ollama_proposal_schema_v1()
    assert schema["properties"]["capability_id"] == {"type": "string"}
    assert schema["properties"]["arguments"] == {"type": "object"}
    assert "profile_id" not in json.dumps(schema)
    assert "no_request" not in json.dumps(schema)
    assert adapter.ollama_proposal_schema_v1(no_request=True)["required"] == ["no_request"]


@contextmanager
def _server(
    wire: bytes, *, delay: float = 0, trickle: float = 0
) -> Iterator[tuple[int, list[Any]]]:
    captured: list[Any] = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            request_line = self.rfile.readline()
            headers: dict[bytes, bytes] = {}
            while True:
                line = self.rfile.readline()
                if line in (b"\r\n", b""):
                    break
                key, value = line.split(b":", 1)
                headers[key.lower()] = value.strip()
            data = self.rfile.read(int(headers[b"content-length"]))
            captured.append((request_line, headers, json.loads(data)))
            time.sleep(delay)
            try:
                if trickle:
                    for byte in wire:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(trickle)
                else:
                    self.wfile.write(wire)
            except OSError:
                pass

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            yield server.server_address[1], captured
        finally:
            server.shutdown()
            thread.join(timeout=2)


def _wire(body: bytes | None = None, headers: bytes | None = None, status: int = 200) -> bytes:
    body = _body() if body is None else body
    headers = (
        (
            b"Content-Type: application/json; charset=utf-8\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n"
        )
        if headers is None
        else headers
    )
    return f"HTTP/1.1 {status} Test\r\n".encode() + headers + b"\r\n" + body


def test_real_http_framing_host_owned_metadata_and_zero_dispatch() -> None:
    with _server(_wire()) as (port, captured):
        result = adapter.invoke_ollama_quarantine_v1(
            adapter.OllamaQuarantineConfigV1(port=port), prompt="public input", **_arguments()
        )
    assert result.reason_code == "evaluated" and result.transport_attempts == 1
    assert result.composition is not None and result.composition.gateway_decision is not None
    assert result.composition.gateway_decision.disposition == "allow"
    line, headers, request = captured[0]
    assert line == b"POST /api/generate HTTP/1.1\r\n"
    assert b"authorization" not in headers
    assert request["model"] == MODEL and request["stream"] is False
    assert "request:fixture" not in json.dumps(request)
    assert "fixture.ollama" not in json.dumps(request)
    assert request["prompt"] == "public input"
    assert len(captured) == 1


def test_chunked_native_reply() -> None:
    body = _body()
    chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    headers = b"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
    with _server(_wire(chunked, headers)) as (port, _):
        result = adapter.invoke_ollama_quarantine_v1(
            adapter.OllamaQuarantineConfigV1(port=port), prompt="public", **_arguments()
        )
    assert result.reason_code == "evaluated"


@pytest.mark.parametrize(
    ("wire", "reason"),
    [
        (_wire(status=302), "http_rejected"),
        (_wire(headers=b"Content-Type: text/plain\r\n"), "http_rejected"),
        (
            _wire(headers=b"Content-Type: application/json\r\nContent-Encoding: gzip\r\n"),
            "http_rejected",
        ),
        (
            _wire(
                headers=b"Content-Type: application/json\r\nContent-Length: 1\r\n"
                b"Content-Length: 2\r\n"
            ),
            "http_rejected",
        ),
        (
            _wire(
                headers=b"Content-Type: application/json\r\nContent-Length: 2\r\n"
                b"Transfer-Encoding: chunked\r\n"
            ),
            "http_rejected",
        ),
        (
            _wire(headers=b"Content-Type: application/json\r\nContent-Length: -1\r\n"),
            "http_rejected",
        ),
        (
            _wire(headers=b"Content-Type: application/json\r\nContent-Length: 65537\r\n"),
            "response_too_large",
        ),
        (
            _wire(headers=b"Content-Type: application/json\r\nContent-Length: 10000\r\n"),
            "http_rejected",
        ),
        (_wire(b"x" * 66000, headers=b"Content-Type: application/json\r\n"), "response_too_large"),
    ],
    ids=[
        "redirect",
        "type",
        "encoding",
        "duplicate-length",
        "ambiguous-framing",
        "negative-length",
        "declared-oversize",
        "truncated",
        "body-oversize",
    ],
)
def test_http_failures_are_typed_and_not_retried(wire: bytes, reason: str) -> None:
    with _server(wire) as (port, captured):
        result = adapter.invoke_ollama_quarantine_v1(
            adapter.OllamaQuarantineConfigV1(port=port), prompt="public", **_arguments()
        )
    assert result.reason_code == reason
    assert result.composition is None and result.transport_attempts == 1
    assert len(captured) == 1


@pytest.mark.parametrize("mode", ["delay", "trickle"])
def test_deadline_is_absolute_not_reset_by_trickle(mode: str) -> None:
    options = {"delay": 0.3} if mode == "delay" else {"trickle": 0.02}
    with _server(_wire(), **options) as (port, captured):
        started = time.monotonic()
        result = adapter.invoke_ollama_quarantine_v1(
            adapter.OllamaQuarantineConfigV1(port=port, timeout_seconds=0.1),
            prompt="public",
            **_arguments(),
        )
        elapsed = time.monotonic() - started
    assert result.reason_code == "transport_timeout" and elapsed < 1.0
    assert len(captured) == 1


def test_live_no_request_contract_rejects_unexpected_proposal() -> None:
    with _server(_wire()) as (port, _):
        result = adapter.invoke_ollama_quarantine_v1(
            adapter.OllamaQuarantineConfigV1(port=port),
            prompt="public",
            no_request=True,
            **_arguments(),
        )
    assert result.reason_code == "proposal_shape_invalid" and result.composition is None
