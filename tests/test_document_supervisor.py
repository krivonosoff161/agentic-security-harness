"""Fixed-child document supervisor and its post-exit fence validation."""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import _workspace_files
from agentic_security_harness import document_supervisor as supervisor
from agentic_security_harness import document_workflow as workflow


class _ScriptedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *, stall: bool = False) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.stall = stall
        self.posts = 0
        self.seen = threading.Event()
        self.release = threading.Event()


class _Handler(BaseHTTPRequestHandler):
    server: _ScriptedServer

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        request = json.loads(self.rfile.read(length))
        assert self.path == "/api/generate"
        assert request["model"] == "scripted:local"
        self.server.posts += 1
        self.server.seen.set()
        if self.server.stall:
            self.server.release.wait(10)
        raw = json.dumps({"model": "scripted:local", "response": "# Result\n\nSafe text.\n",
                          "done": True, "done_reason": "stop"}).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass


@contextmanager
def _server(*, stall: bool = False) -> Iterator[_ScriptedServer]:
    server = _ScriptedServer(stall=stall)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _fixture(tmp_path: Path, port: int) -> tuple[workflow.DocumentConfig, Path]:
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    source = tmp_path / "source.txt"
    source.write_text("Public synthetic facts.\n", encoding="utf-8")
    return workflow.DocumentConfig(jobs, "scripted:local", port=port), source


def test_preview_uses_no_child_or_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source = _fixture(tmp_path, 11434)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("preview launched worker")

    monkeypatch.setattr(supervisor.multiprocessing, "get_context", forbidden)
    result = supervisor.run_supervised_job(config, source, "Write a short note", "first",
                                           timeout_seconds=1.0)
    assert result["state"] == "preview"
    assert not (config.jobs_dir / "first").exists()


def test_successful_worker_has_no_fence(tmp_path: Path) -> None:
    with _server() as server:
        config, source = _fixture(tmp_path, server.server_port)
        result = supervisor.run_supervised_job(config, source, "Write a short note", "first",
                                               timeout_seconds=10.0, execute=True)
        assert result["state"] == "saved"
        assert server.posts == 1
        job = config.jobs_dir / "first"
        assert (job / "document.md").read_bytes() == b"# Result\n\nSafe text.\n"
        assert (job / "session-closed.json").is_file()
        assert not (job / "supervisor-fence.json").exists()
        started = json.loads((job / "started.json").read_text())
        assert len(started["supervisor_nonce"]) == 32


def test_timeout_terminates_owned_worker_without_effect_or_false_fence(tmp_path: Path) -> None:
    with _server(stall=True) as server:
        config, source = _fixture(tmp_path, server.server_port)
        result = supervisor.run_supervised_job(config, source, "Write a short note", "first",
                                               timeout_seconds=2.5, execute=True)
        assert result["state"] == "needs_inspection"
        assert result["reason"] == "supervised_timeout"
        assert result["writer_terminated"] is True
        assert result["supervisor_fence_written"] is False
        job = config.jobs_dir / "first"
        assert not (job / "document.md").exists()
        assert not (job / "supervisor-fence.json").exists()
        assert server.posts <= 1


def _authorized_intent_without_closure(
    config: workflow.DocumentConfig, source: Path, monkeypatch: pytest.MonkeyPatch,
    nonce: str,
) -> Path:
    # Private fixture only: force a BaseException immediately after the durable
    # intent, leaving the same kind of pre-effect records as an interrupted job.
    original = _workspace_files.WorkspaceFiles.write_once

    def stop_after_intent(self: Any, alias: str, content: bytes) -> Any:
        result = original(self, alias, content)
        if alias == "intent1":
            raise SystemExit(19)
        return result

    def scripted(args: Any, policy: Any, *, source: bytes, document_content: bool,
                 generation_json: bool) -> tuple[bytes | None, dict[str, Any]]:
        if args.execute:
            return b"# Result\n\nSafe text.\n", {"transport_attempts": 1}
        return None, {"input_sha256": workflow._sha(source), "transport_attempts": 0}

    monkeypatch.setattr(_workspace_files.WorkspaceFiles, "write_once", stop_after_intent)
    monkeypatch.setattr(workflow, "_generate", scripted)
    with pytest.raises(SystemExit):
        workflow.run_job(config, source, "Write a short note", "first", execute=True,
                         supervisor_nonce=nonce)
    job = config.jobs_dir / "first"
    assert (job / "started.json").is_file()
    assert len(list(job.glob("*-intent.json"))) == 1
    assert not (job / "document.md").exists()
    assert not (job / "session-closed.json").exists()
    return job


def test_fence_requires_exact_nonce_config_intent_and_is_create_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source = _fixture(tmp_path, 11434)
    nonce = uuid.uuid4().hex
    job = _authorized_intent_without_closure(config, source, monkeypatch, nonce)
    assert supervisor._write_fence(config, "first", uuid.uuid4().hex, 123, 1, True) is False
    wrong_config = workflow.DocumentConfig(config.jobs_dir, "other:local", port=11434)
    assert supervisor._write_fence(wrong_config, "first", nonce, 123, 1, True) is False
    intent_path = next(job.glob("*-intent.json"))
    original = intent_path.read_bytes()
    intent = json.loads(original)
    intent["write_authorized"] = False
    intent_path.write_text(json.dumps(intent), encoding="utf-8")
    assert supervisor._write_fence(config, "first", nonce, 123, 1, True) is False
    intent_path.write_bytes(original)
    assert supervisor._write_fence(config, "first", nonce, 123, 1, True) is True
    fence_path = job / "supervisor-fence.json"
    fence = json.loads(fence_path.read_text())
    assert set(fence) == {
        "schema_version", "supervisor_nonce", "job_id", "configuration_sha256",
        "policy_sha256", "session_id", "started_sha256", "intent_sha256",
        "worker_pid", "exitcode", "terminated", "writer_terminated", "replay_allowed",
    }
    assert fence["replay_allowed"] is False
    assert fence["writer_terminated"] is True
    first = fence_path.read_bytes()
    assert supervisor._write_fence(config, "first", nonce, 123, 1, True) is False
    assert fence_path.read_bytes() == first
