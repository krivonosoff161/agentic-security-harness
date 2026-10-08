"""One trusted-host document worker with a narrow, post-exit fence.

This supervisor owns the child process handle. It does not accept a PID, command,
worker callback, or model-controlled authority. A fence proves only that this
local worker has exited; the original job remains unresolved after interruption.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import re
import uuid
from itertools import islice
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentic_security_harness._fixture_files import _checked_directory
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_restrictions import (
    DocumentSourceRestrictions,
    parse_source_restrictions,
)
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.runtime_guard_foundation import GuardDecision
from agentic_security_harness.workspace_writer import _canonical, _read_file, _sha

if TYPE_CHECKING:
    from agentic_security_harness.document_coverage import DocumentRunPlan
    from agentic_security_harness.document_quality import DocumentRequirements
    from agentic_security_harness.document_workflow import DocumentConfig

_HEX32 = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_INTENT_KEYS = {
    "schema_version", "session_id", "call_id", "policy_sha256", "proposal_sha256",
    "applied", "effect", "reason", "receipt_complete", "artifact", "bytes",
    "content_sha256", "decision", "phase", "write_authorized",
}
_FENCE_VERSION = "ash.document-supervisor-fence.v1"


def _worker_main(send: Connection, config: DocumentConfig, source_path: Path | None, task: str,
                 job_id: str, nonce: str, kwargs: dict[str, Any]) -> None:
    """Fixed spawn target. Pipe carries only fixed status, never source or output."""
    from agentic_security_harness.document_workflow import run_job

    try:
        result = run_job(config, source_path, task, job_id, execute=True,
                         supervisor_nonce=nonce, **kwargs)
        message = {"state": result.get("state"), "reason": result.get("reason"),
                   "effect": result.get("effect")}
        if (message["state"] not in {"saved", "denied", "error", "needs_inspection"}
                or type(message["reason"]) is not str
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", message["reason"])
                or message["effect"] not in {"none", "created", "unknown_inspect_output"}):
            message = {"state": "needs_inspection", "reason": "worker_status_invalid",
                       "effect": "unknown_inspect_output"}
    except BaseException:
        # Exception text could include source or model output; never forward it.
        message = {"state": "needs_inspection", "reason": "worker_interrupted",
                   "effect": "unknown_inspect_output"}
        try:
            send.send_bytes(_canonical(message))
        except (OSError, ValueError):
            pass
        finally:
            send.close()
        os._exit(2)
    try:
        send.send_bytes(_canonical(message))
    except (OSError, ValueError):
        pass
    finally:
        send.close()


def _record(path: Path, limit: int) -> tuple[dict[str, Any], str]:
    raw = _read_file(path, limit)
    value = _json(raw, limit)
    if type(value) is not dict:
        raise ValueError("object record required")
    return value, _sha(raw)


def _fence_record(config: DocumentConfig, job_id: str, nonce: str, worker_pid: int,
                  exitcode: int, terminated: bool) -> dict[str, Any] | None:
    """Construct only from one host-bound started record and authorized intent."""
    from agentic_security_harness import document_workflow as doc

    if (type(nonce) is not str or _HEX32.fullmatch(nonce) is None
            or type(worker_pid) is not int or worker_pid <= 0
            or type(exitcode) is not int or exitcode == 0
            or type(terminated) is not bool):
        return None
    job = config.jobs_dir / doc._job_name(job_id)
    try:
        _checked_directory(job)
        if ((job / "session-closed.json").exists()
                or (job / "session-closed.json").is_symlink()
                or (job / "supervisor-fence.json").exists()
                or (job / "supervisor-fence.json").is_symlink()):
            return None
        started, started_sha = _record(job / "started.json", 65536)
        if (started.get("schema_version") != doc.VERSION
                or started.get("state") != "started"
                or started.get("job_id") != job_id
                or started.get("supervisor_nonce") != nonce
                or started.get("configuration_sha256") != config.sha256
                or started.get("engine") != config.engine):
            return None
        restrictions = None
        if "source_restrictions" in started or "source_restrictions_sha256" in started:
            if "source_restrictions" not in started:
                return None
            restrictions = parse_source_restrictions(started["source_restrictions"])
            if (restrictions.sha256 != started.get("source_restrictions_sha256")
                    or restrictions.record()["content_sha256"] != started.get("input_sha256")
                    or restrictions.data_class != config.data_class):
                return None
        policy = config.policy(
            job,
            source_restrictions_sha256=restrictions.sha256 if restrictions else None,
            source_expires_at=restrictions.expires_at if restrictions else None,
        )
        if started.get("policy_sha256") != policy.sha256:
            return None
        # A second attempt or another session is contradictory, not a candidate
        # to select heuristically. Bound inventory before reading any filename.
        names = [entry.name for entry in islice(job.iterdir(), 11)]
        if len(names) > 10:
            return None
        intents = [name for name in names if name.endswith("-intent.json")]
        if len(intents) != 1:
            return None
        match = re.fullmatch(r"\.ash-([a-f0-9]{32})-01-intent\.json", intents[0])
        if match is None:
            return None
        session_id = match.group(1)
        intent, intent_sha = _record(job / intents[0], 16384)
        decision = GuardDecision.model_validate(intent.get("decision"))
        if (set(intent) != _INTENT_KEYS
                or intent.get("schema_version") != "ash.workspace-write.v1"
                or intent.get("phase") != "intent"
                or intent.get("applied") is not False
                or intent.get("effect") != "none"
                or intent.get("receipt_complete") is not False
                or intent.get("reason") != "guard_rejected"
                or intent.get("write_authorized") is not True
                or intent.get("session_id") != session_id
                or intent.get("call_id") != f"{session_id}:1"
                or intent.get("policy_sha256") != policy.sha256
                or intent.get("artifact") != "document"
                or type(intent.get("proposal_sha256")) is not str
                or _HEX64.fullmatch(intent["proposal_sha256"]) is None
                or type(intent.get("content_sha256")) is not str
                or _HEX64.fullmatch(intent["content_sha256"]) is None
                or type(intent.get("bytes")) is not int
                or not 0 < intent["bytes"] <= policy.max_bytes
                or decision.disposition != "allow"
                or decision.evidence.policy_sha256 != policy.sha256
                or decision.evidence.content_sha256 != intent["content_sha256"]):
            return None
        return {
            "schema_version": _FENCE_VERSION,
            "supervisor_nonce": nonce,
            "job_id": job_id,
            "configuration_sha256": config.sha256,
            "policy_sha256": policy.sha256,
            "session_id": session_id,
            "started_sha256": started_sha,
            "intent_sha256": intent_sha,
            "worker_pid": worker_pid,
            "exitcode": exitcode,
            "terminated": terminated,
            "writer_terminated": True,
            "replay_allowed": False,
        }
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_fence(config: DocumentConfig, job_id: str, nonce: str, worker_pid: int,
                 exitcode: int, terminated: bool) -> bool:
    from agentic_security_harness import document_workflow as doc

    record = _fence_record(config, job_id, nonce, worker_pid, exitcode, terminated)
    if record is None:
        return False
    try:
        doc._save(config.jobs_dir / doc._job_name(job_id) / "supervisor-fence.json", record)
        return True
    except (OSError, ValueError):
        return False


def _interrupted(job_id: str, *, timed_out: bool, fenced: bool) -> dict[str, Any]:
    return {
        "state": "needs_inspection", "job_id": job_id,
        "reason": "supervised_timeout" if timed_out else "supervised_worker_exit",
        "effect": "unknown_inspect_output", "replay_allowed": False,
        "writer_terminated": True, "supervisor_fence_written": fenced,
        "next_step": "inspect_original_then_review_exact_bytes_for_new_job",
    }


def run_supervised_job(
    config: DocumentConfig, source_path: Path | None, task: str, job_id: str, *,
    timeout_seconds: float, execute: bool = False, source_job: str | None = None,
    requirements: DocumentRequirements | None = None,
    reviewed_source_sha256: str | None = None,
    source_restrictions: DocumentSourceRestrictions | DocumentMultiSourceRestrictions | None = None,
    expected_input_sha256: str | None = None,
    run_plan_sha256: str | None = None,
    run_plan_path: Path | None = None,
    run_plan: DocumentRunPlan | None = None,
    recover_source: bool = False,
) -> dict[str, Any]:
    """Run at most one fixed workflow worker; never adopt or kill a caller PID."""
    from agentic_security_harness import document_workflow as doc

    if (type(timeout_seconds) not in {int, float} or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 3600):
        raise ValueError("bounded timeout_seconds required")
    if type(execute) is not bool:
        raise ValueError("execute must be boolean")
    kwargs: dict[str, Any] = {
        "source_job": source_job, "requirements": requirements,
        "reviewed_source_sha256": reviewed_source_sha256,
        "source_restrictions": source_restrictions,
        "expected_input_sha256": expected_input_sha256,
        "run_plan_sha256": run_plan_sha256,
        "run_plan_path": run_plan_path, "run_plan": run_plan,
        "recover_source": recover_source,
    }
    # Preview is the ordinary in-process read-only workflow, not a worker.
    preview = doc.run_job(config, source_path, task, job_id, execute=False, **kwargs)
    if not execute or preview.get("state") != "preview":
        return preview
    if (config.jobs_dir / doc._job_name(job_id)).exists():
        return {"state": "error", "job_id": job_id, "reason": "job_already_exists",
                "effect": "none", "next_step": "inspect_existing_job_do_not_retry"}
    nonce = uuid.uuid4().hex
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    worker = context.Process(target=_worker_main,
                             args=(send, config, source_path, task, job_id, nonce, kwargs))
    try:
        worker.start()
    except BaseException:
        send.close()
        receive.close()
        raise
    send.close()
    try:
        worker.join(timeout_seconds)
        timed_out = worker.is_alive()
        if timed_out:
            worker.terminate()  # Owned Process handle, never a supplied PID.
            worker.join(3.0)
            if worker.is_alive():
                worker.kill()
                worker.join(3.0)
        if worker.is_alive() or worker.exitcode is None or worker.pid is None:
            return {"state": "needs_inspection", "job_id": job_id,
                    "reason": "supervised_worker_not_fenced", "effect": "unknown_inspect_output",
                    "replay_allowed": False, "supervisor_fence_written": False}
        if timed_out or worker.exitcode != 0:
            fenced = _write_fence(config, job_id, nonce, worker.pid, worker.exitcode,
                                  timed_out)
            return _interrupted(job_id, timed_out=timed_out, fenced=fenced)
        # A successful exit needs no supervisor fence. The pipe is advisory;
        # persisted job inspection owns the outcome if status transport is lost.
        if receive.poll(0.1):
            try:
                json.loads(receive.recv_bytes(maxlength=1024))
            except (EOFError, OSError, ValueError):
                pass
        return doc.inspect_job(config, job_id)
    finally:
        receive.close()
        if not worker.is_alive():
            worker.close()
