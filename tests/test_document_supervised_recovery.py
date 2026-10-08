"""Owned spawned workers really exit at deterministic file-effect windows.

The test-only worker instruments local synthetic writes, not a public injection
point. Process interruption is not a simulated power cut or filesystem crash.
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import document_recovery as recovery
from agentic_security_harness import document_supervisor as supervisor
from agentic_security_harness import document_workflow as workflow

_CONTENT = b"# Recovered note\n\nPublic synthetic facts.\n"


def _exit_before_reservation(
    send: Connection, config: workflow.DocumentConfig, source_path: Path | None,
    task: str, job_id: str, nonce: str, kwargs: dict[str, Any],
) -> None:
    # Spawned test child exits before run_job can reserve a job or write intent.
    os._exit(41)


def _crash_worker(
    send: Connection, config: workflow.DocumentConfig, source_path: Path | None,
    task: str, job_id: str, nonce: str, kwargs: dict[str, Any],
) -> None:
    # Top-level importable spawn target in the TEST module only. The production
    # entrypoint never accepts this callback or arbitrary commands from callers.
    original = workflow.WorkspaceFiles.write_once

    def write_then_crash(self: Any, alias: str, content: bytes) -> Any:
        if alias == "document" and job_id == "before-create":
            os._exit(41)
        if alias == "document" and job_id == "partial-create":
            original(self, alias, content[: len(content) // 2])
            os._exit(41)
        result = original(self, alias, content)
        if ((alias == "document" and job_id == "after-create")
                or (alias == "result1" and job_id == "after-result")
                or (alias == "record" and self._targets[alias] == "summary.json"
                    and job_id == "after-summary")):
            os._exit(41)
        return result

    def generate(args: Any, policy: Any, *, source: bytes, document_content: bool,
                 generation_json: bool) -> tuple[bytes | None, dict[str, Any]]:
        if args.execute:
            return _CONTENT, {"transport_attempts": 1}
        return None, {"input_sha256": workflow._sha(source), "transport_attempts": 0}

    with pytest.MonkeyPatch.context() as patches:
        patches.setattr(workflow.WorkspaceFiles, "write_once", write_then_crash)
        patches.setattr(workflow, "_generate", generate)
        supervisor._worker_main(send, config, source_path, task, job_id, nonce, kwargs)


def _interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str,
) -> tuple[workflow.DocumentConfig, Path, Path]:
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    source = tmp_path / "source.txt"
    source.write_bytes(b"Public source.\n")
    config = workflow.DocumentConfig(jobs, "scripted:local")
    monkeypatch.setattr(supervisor, "_worker_main", _crash_worker)
    result = supervisor.run_supervised_job(
        config, source, "Write a short note", stage, timeout_seconds=15, execute=True,
    )
    assert result["state"] == "needs_inspection", result
    assert result["writer_terminated"] is True
    assert result["supervisor_fence_written"] is True
    job = jobs / stage
    assert not (job / "session-closed.json").exists()
    fence = json.loads((job / "supervisor-fence.json").read_bytes())
    assert fence["exitcode"] == 41 and fence["terminated"] is False
    return config, source, job


def test_owned_child_exit_before_reservation_has_no_fence_or_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    source = tmp_path / "source.txt"
    source.write_bytes(b"Public source.\n")
    config = workflow.DocumentConfig(jobs, "scripted:local")
    monkeypatch.setattr(supervisor, "_worker_main", _exit_before_reservation)
    result = supervisor.run_supervised_job(
        config, source, "Write a short note", "before-reservation",
        timeout_seconds=15, execute=True,
    )
    assert result["state"] == "needs_inspection"
    assert result["reason"] == "supervised_worker_exit"
    assert result["writer_terminated"] is True
    assert result["supervisor_fence_written"] is False
    assert not list(jobs.iterdir())
    assert workflow.inspect_job(config, "before-reservation")["state"] == "not_found"
    recovered = recovery.inspect_recovery(config, "before-reservation")
    assert recovered["state"] == "needs_inspection"
    assert recovered["replay_allowed"] is False


def test_concurrent_restarts_of_interrupted_id_never_generate_or_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, job = _interrupted(tmp_path, monkeypatch, "after-create")
    old_files = {path.name: path.read_bytes() for path in job.iterdir()}
    old_recovery = recovery.inspect_recovery(config, "after-create")
    assert old_recovery["state"] == "recoverable_data"

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("existing job attempted generation or child spawn")

    monkeypatch.setattr(workflow, "_generate", forbidden)
    monkeypatch.setattr(supervisor.multiprocessing, "get_context", forbidden)
    barrier = threading.Barrier(6)

    def retry(_: int) -> dict[str, Any]:
        barrier.wait(timeout=10)
        return supervisor.run_supervised_job(
            config, source, "Write a short note", "after-create",
            timeout_seconds=5, execute=True,
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        attempts = list(pool.map(retry, range(6)))
    assert all(result["state"] == "error" and result["reason"] == "job_already_exists"
               and result["effect"] == "none" for result in attempts)
    assert {path.name: path.read_bytes() for path in job.iterdir()} == old_files
    assert recovery.inspect_recovery(config, "after-create") == old_recovery


@pytest.mark.parametrize("stage,recoverable", [
    ("before-create", False), ("partial-create", False),
    ("after-create", True), ("after-result", True), ("after-summary", True),
])
def test_real_child_exit_can_recover_only_complete_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, recoverable: bool,
) -> None:
    config, source, job = _interrupted(tmp_path, monkeypatch, stage)
    before = {p.name: p.read_bytes() for p in job.iterdir()}
    status = recovery.inspect_recovery(config, stage)
    assert status["state"] == ("recoverable_data" if recoverable else "needs_inspection")
    assert status["original_completion_proven"] is False
    assert status["replay_allowed"] is False
    assert workflow.inspect_job(config, stage)["state"] == "needs_inspection"
    # An existing ID is spent even when exact bytes can be captured as data.
    calls: list[bytes] = []

    def generate(args: Any, policy: Any, *, source: bytes, document_content: bool,
                 generation_json: bool) -> tuple[bytes | None, dict[str, Any]]:
        if args.execute:
            calls.append(source)
            return b"# Continued\n\nReviewed recovered data.\n", {"transport_attempts": 1}
        return None, {"input_sha256": workflow._sha(source), "transport_attempts": 0}

    monkeypatch.setattr(workflow, "_generate", generate)
    retried = workflow.run_job(config, source, "Write a short note", stage, execute=True)
    assert retried["reason"] == "job_already_exists" and calls == []
    if recoverable:
        assert status["fence_kind"] == "owned_supervisor_exit"
        with pytest.raises(workflow.SourceReviewBlocked):
            recovery.read_recovered_document(config, stage, reviewed_source_sha256="0" * 64)
        captured = recovery.read_recovered_document(
            config, stage, reviewed_source_sha256=status["document_sha256"],
        )
        assert captured.content == _CONTENT
        assert captured.record()["authority"] == "none"
        continued = workflow.run_job(
            config, None, "Continue reviewed note", "continued", source_job=stage,
            recover_source=True, reviewed_source_sha256=status["document_sha256"], execute=True,
        )
        assert continued["state"] == "saved"
        assert calls == [_CONTENT]
    assert {p.name: p.read_bytes() for p in job.iterdir()} == before


@pytest.mark.parametrize("key,value", [
    ("supervisor_nonce", "0" * 32), ("started_sha256", "0" * 64),
    ("intent_sha256", "0" * 64), ("configuration_sha256", "0" * 64),
    ("worker_pid", True), ("exitcode", 0), ("exitcode", False),
    ("terminated", "yes"), ("writer_terminated", False), ("replay_allowed", True),
    ("unknown", "authority"),
])
def test_fence_binding_and_closed_schema_reject_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str, value: Any,
) -> None:
    config, _, job = _interrupted(tmp_path, monkeypatch, "after-create")
    path = job / "supervisor-fence.json"
    fence = json.loads(path.read_bytes())
    fence[key] = value
    path.write_text(json.dumps(fence), encoding="utf-8")
    assert recovery.inspect_recovery(config, "after-create")["state"] == "needs_inspection"


def test_supervisor_and_normal_closure_must_not_coexist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, job = _interrupted(tmp_path, monkeypatch, "after-create")
    fence = json.loads((job / "supervisor-fence.json").read_bytes())
    (job / "session-closed.json").write_text(json.dumps({
        "schema_version": "ash.workspace-session-closed.v1", "session_id": fence["session_id"],
        "policy_sha256": fence["policy_sha256"], "attempts": 1, "closed": True,
        "replay_allowed": False,
    }), encoding="utf-8")
    assert recovery.inspect_recovery(config, "after-create")["state"] == "needs_inspection"
