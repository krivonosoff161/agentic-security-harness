"""Early POST denial remains authoritative while connection cleanup is bounded."""
from __future__ import annotations

import http.client
import io
import json
import threading
import time
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentic_security_harness import runtime_gateway as gateway


def _handler(data: bytes, length: str = "999999") -> Any:
    handler: Any = object.__new__(gateway._GatewayRequestHandler)
    handler.server = SimpleNamespace(config=SimpleNamespace(max_body_bytes=65_536))
    handler.headers = Message()
    handler.headers["Content-Length"] = length
    handler.rfile = io.BytesIO(data)
    handler.wfile = io.BytesIO()
    handler.command = "POST"
    handler.connection = SimpleNamespace(gettimeout=lambda: None, settimeout=lambda value: None)
    handler.send_response = lambda status: None
    handler.send_header = lambda name, value: None
    handler.end_headers = lambda: None
    return handler


@pytest.mark.parametrize("length", ["999999", "not-a-number", "9" * 100, ""])
def test_rejected_suffix_cleanup_has_a_hard_byte_cap(length: str) -> None:
    handler = _handler(b"x" * 100_000, length)
    handler._write_bytes(HTTPStatus.BAD_REQUEST, b"denied", "text/plain")
    assert handler.rfile.tell() == 65_536
    assert handler.wfile.getvalue() == b"denied"
    assert handler.close_connection is True


def test_cleanup_is_after_response_and_has_a_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = _handler(b"x" * 50_000)
    deadlines = iter([1.0, 1.01, 1.11])
    monkeypatch.setattr(gateway.time, "monotonic", lambda: next(deadlines))
    timeouts: list[float | None] = []
    handler.connection.settimeout = timeouts.append
    original = handler.rfile

    class CheckedRead:
        def read1(self, count: int) -> bytes:
            assert handler.wfile.getvalue() == b"denied"
            return original.read1(count)

    handler.rfile = CheckedRead()
    handler._write_bytes(HTTPStatus.BAD_REQUEST, b"denied", "text/plain")
    assert original.tell() == 8192
    assert timeouts[0] is not None
    assert 0 < timeouts[0] < 0.1
    assert timeouts[-1] is None


@pytest.mark.parametrize("header,value,expected", [
    ("Authorization", "Bearer synthetic-do-not-log", b"credential_headers_forbidden"),
    ("Origin", "https://attacker.example", b"origin_forbidden"),
])
def test_denial_never_parses_or_dispatches_rejected_body(
    header: str, value: str, expected: bytes,
) -> None:
    handler = _handler(b"untrusted-not-json", "18")
    handler.path = "/mcp"
    handler.server.server_port = 12345
    handler.headers[header] = value
    handler._read_json_body = lambda: pytest.fail("denied input must not be parsed")
    handler._handle_mcp = lambda *args: pytest.fail("denied input must not dispatch")
    handler.do_POST()
    assert expected in handler.wfile.getvalue()
    assert handler.rfile.tell() == len(b"untrusted-not-json")


def test_consumed_body_does_not_trigger_extra_read() -> None:
    handler = _handler(b"unrelated remaining bytes")
    handler._request_body_consumed = True
    handler._write_bytes(HTTPStatus.BAD_REQUEST, b"denied", "text/plain")
    assert handler.rfile.tell() == 0


def test_cleanup_error_retains_denial_without_second_response() -> None:
    handler = _handler(b"", "5")

    class FailedRead:
        def read1(self, count: int) -> bytes:
            raise TimeoutError("synthetic cleanup timeout")

    handler.rfile = FailedRead()
    handler._write_bytes(HTTPStatus.BAD_REQUEST, b"denied", "text/plain")
    assert handler.wfile.getvalue() == b"denied"
    assert handler.close_connection is True


@pytest.mark.parametrize("extra_headers,expected_status", [
    ({"Authorization": "Bearer synthetic-do-not-log"}, 400),
    ({"Origin": "https://attacker.example"}, 403),
    ({"Content-Length": "999999"}, 400),
])
def test_split_post_header_body_preserves_early_denial(
    tmp_path: Path, extra_headers: dict[str, str], expected_status: int,
) -> None:
    config = gateway.GatewayConfigV1(
        audit_dir=(tmp_path / "audit").resolve(), port=gateway.unused_loopback_port(),
    )
    server = gateway.create_gateway_server(config)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        # Five distinct requests, not retries of a failed request. The delayed
        # body exercises the previously timing-dependent early-close path.
        for _ in range(5):
            connection = http.client.HTTPConnection("127.0.0.1", config.port, timeout=2)
            try:
                connection.putrequest("POST", "/mcp")
                headers = {"Content-Type": "application/json", "Content-Length": "2"}
                headers.update(extra_headers)
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.endheaders()
                time.sleep(0.01)
                connection.send(b"{}")
                response = connection.getresponse()
                assert response.status == expected_status
                assert "error" in json.loads(response.read())
            finally:
                connection.close()
        assert server.engine.execution_count == 0
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
