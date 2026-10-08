"""Read-only capture of bytes left by a closed, ambiguous document job.

Local records are trusted host bookkeeping, not remote attestations. Recovery
does not finish an original job, repair its receipts, or authorize effect replay.
"""

from __future__ import annotations

import re
from itertools import islice
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
    from agentic_security_harness.document_workflow import DocumentConfig, DocumentInput

_HEX32 = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_CLOSURE_KEYS = {
    "schema_version", "session_id", "policy_sha256", "attempts", "closed",
    "replay_allowed",
}
_STARTED_KEYS = {
    "schema_version", "job_id", "configuration_sha256", "policy_sha256",
    "input_sha256", "input_provenance", "reviewed_source_sha256",
    "requirements_sha256", "task_sha256", "engine", "state",
}
_OPTIONAL_STARTED_KEYS = {
    "source_restrictions", "source_restrictions_sha256", "run_plan_sha256", "supervisor_nonce",
}
_KNOWN_FILES = {
    "started.json", "session-closed.json", "document.md", "summary.json",
    "quality.json", "supervisor-fence.json",
}
_FENCE_KEYS = {
    "schema_version", "supervisor_nonce", "job_id", "configuration_sha256",
    "policy_sha256", "session_id", "started_sha256", "intent_sha256",
    "worker_pid", "exitcode", "terminated", "writer_terminated", "replay_allowed",
}
_INTENT_KEYS = {
    "schema_version", "session_id", "call_id", "policy_sha256", "proposal_sha256",
    "applied", "effect", "reason", "receipt_complete", "artifact", "bytes",
    "content_sha256", "decision", "phase", "write_authorized",
}


def _unresolved(job_id: str, reason: str) -> dict[str, Any]:
    return {
        "state": "needs_inspection", "job_id": job_id, "reason": reason,
        "replay_allowed": False, "original_completion_proven": False,
        "writes_performed": False,
    }


def _record(path: Path, limit: int) -> tuple[dict[str, Any], str]:
    raw = _read_file(path, limit)
    value = _json(raw, limit)
    if type(value) is not dict:
        raise ValueError("object record required")
    return value, _sha(raw)


def _source_restrictions(
    initial: dict[str, Any],
) -> DocumentSourceRestrictions | DocumentMultiSourceRestrictions | None:
    if ("source_restrictions" in initial) != ("source_restrictions_sha256" in initial):
        raise ValueError("incomplete source restrictions")
    if "source_restrictions" not in initial:
        return None
    restrictions = parse_source_restrictions(initial["source_restrictions"])
    if (restrictions.sha256 != initial["source_restrictions_sha256"]
            or restrictions.record()["content_sha256"] != initial["input_sha256"]):
        raise ValueError("source restrictions changed")
    return restrictions


def _inventory(job: Path, session_id: str, closure_name: str) -> set[str]:
    entries = list(islice(job.iterdir(), 9))
    if len(entries) > 8:
        raise ValueError("unexpected job inventory")
    names = {entry.name for entry in entries}
    intent = f".ash-{session_id}-01-intent.json"
    result = f".ash-{session_id}-01-result.json"
    if (len(names) != len(entries) or not {"started.json", closure_name,
                                      "document.md", intent} <= names
            or len(names & {"session-closed.json", "supervisor-fence.json"}) != 1
            or names - (_KNOWN_FILES | {intent, result})):
        raise ValueError("unexpected job inventory")
    return names


def inspect_recovery(config: DocumentConfig, job_id: str) -> dict[str, Any]:
    """Inspect one existing job without writing or replaying its effect."""
    from agentic_security_harness import document_workflow as doc

    if type(config) is not doc.DocumentConfig:
        raise ValueError("DocumentConfig required")
    normal = doc.inspect_job(config, job_id)
    if normal["state"] == "saved":
        return {"state": "already_complete", "job_id": job_id,
                "reason": "use_normal_source_handoff", "replay_allowed": False,
                "document_sha256": normal["document_sha256"], "writes_performed": False}
    job = config.jobs_dir / doc._job_name(job_id)
    problem = _unresolved(job_id, "recovery_evidence_incomplete_or_changed")
    try:
        _checked_directory(config.jobs_dir)
        _checked_directory(job)
        initial, initial_sha = _record(job / "started.json", 65536)
        if (not _STARTED_KEYS <= initial.keys()
                or set(initial) - (_STARTED_KEYS | _OPTIONAL_STARTED_KEYS)
                or initial["schema_version"] != doc.VERSION
                or initial["job_id"] != job_id
                or initial["configuration_sha256"] != config.sha256
                or initial["engine"] != config.engine
                or initial["state"] != "started"
                or any(type(initial[key]) is not str or _HEX64.fullmatch(initial[key]) is None
                       for key in ("policy_sha256", "input_sha256", "task_sha256"))
                or (initial["requirements_sha256"] is not None and (
                    type(initial["requirements_sha256"]) is not str
                    or _HEX64.fullmatch(initial["requirements_sha256"]) is None))
                or ("run_plan_sha256" in initial and (
                    type(initial["run_plan_sha256"]) is not str
                    or _HEX64.fullmatch(initial["run_plan_sha256"]) is None))
                or ("supervisor_nonce" in initial and (
                    type(initial["supervisor_nonce"]) is not str
                    or _HEX32.fullmatch(initial["supervisor_nonce"]) is None))):
            return problem
        provenance = initial["input_provenance"]
        if (type(provenance) is not dict
                or set(provenance) != {"kind", "source_job", "content_sha256",
                                       "trust", "authority", "data_class"} | (
                                           {"recovery_evidence_sha256"}
                                           if provenance.get("kind") == "recovered_document"
                                           else set())
                or provenance["kind"] not in {"host_selected_file", "generated_document",
                                               "recovered_document"}
                or (provenance["kind"] == "recovered_document" and (
                    type(provenance.get("recovery_evidence_sha256")) is not str
                    or _HEX64.fullmatch(provenance["recovery_evidence_sha256"]) is None))
                or provenance["content_sha256"] != initial["input_sha256"]
                or provenance["data_class"] != config.data_class
                or provenance["trust"] != "untrusted" or provenance["authority"] != "none"
                or (provenance["kind"] == "host_selected_file"
                    and provenance["source_job"] is not None)
                or (provenance["kind"] != "host_selected_file"
                    and (type(provenance["source_job"]) is not str
                         or doc._job_name(provenance["source_job"]) == job_id))):
            return problem
        reviewed = initial["reviewed_source_sha256"]
        if reviewed is not None and (
            type(reviewed) is not str or reviewed != initial["input_sha256"]
            or provenance["kind"] == "host_selected_file"
        ):
            return problem
        restrictions = _source_restrictions(initial)
        if (restrictions is not None
                and restrictions.data_class != config.data_class):
            return problem
        policy = config.policy(
            job,
            source_restrictions_sha256=(restrictions.sha256 if restrictions else None),
            source_expires_at=(restrictions.expires_at if restrictions else None),
        )
        if initial["policy_sha256"] != policy.sha256:
            return problem
        # Exactly one local host termination record is required. A supervisor
        # fence never fabricates normal completion or permits replay.
        closure_name = ("supervisor-fence.json" if (job / "supervisor-fence.json").exists()
                        else "session-closed.json")
        closure, closure_sha = _record(job / closure_name, 16384)
        session_id = closure.get("session_id")
        if (type(session_id) is not str or _HEX32.fullmatch(session_id) is None
                or closure.get("policy_sha256") != initial["policy_sha256"]
                or closure.get("replay_allowed") is not False):
            return problem
        if closure_name == "session-closed.json":
            if (set(closure) != _CLOSURE_KEYS
                    or closure["schema_version"] != "ash.workspace-session-closed.v1"
                    or type(closure["attempts"]) is not int or closure["attempts"] != 1
                    or closure["closed"] is not True):
                return problem
        elif (set(closure) != _FENCE_KEYS
              or closure["schema_version"] != "ash.document-supervisor-fence.v1"
              or "supervisor_nonce" not in initial
              or closure["supervisor_nonce"] != initial["supervisor_nonce"]
              or closure["job_id"] != job_id
              or closure["configuration_sha256"] != config.sha256
              or closure["started_sha256"] != initial_sha
              or type(closure["worker_pid"]) is not int or closure["worker_pid"] <= 0
              or type(closure["exitcode"]) is not int or closure["exitcode"] == 0
              or type(closure["terminated"]) is not bool
              or closure["writer_terminated"] is not True):
            return problem
        names = _inventory(job, session_id, closure_name)
        intent_name = f".ash-{session_id}-01-intent.json"
        intent, intent_sha = _record(job / intent_name, 16384)
        if closure_name == "supervisor-fence.json" and closure["intent_sha256"] != intent_sha:
            return problem
        decision = GuardDecision.model_validate(intent.get("decision"))
        if (set(intent) != _INTENT_KEYS
                or intent.get("schema_version") != "ash.workspace-write.v1"
                or intent.get("phase") != "intent"
                or intent.get("applied") is not False
                or intent.get("effect") != "none"
                or intent.get("receipt_complete") is not False
                or intent.get("reason") != "guard_rejected"
                or type(intent.get("proposal_sha256")) is not str
                or _HEX64.fullmatch(intent["proposal_sha256"]) is None
                or intent.get("write_authorized") is not True
                or intent.get("session_id") != session_id
                or intent.get("call_id") != f"{session_id}:1"
                or intent.get("policy_sha256") != policy.sha256
                or intent.get("artifact") != "document"
                or type(intent.get("bytes")) is not int
                or not 0 < intent["bytes"] <= policy.max_bytes
                or type(intent.get("content_sha256")) is not str
                or _HEX64.fullmatch(intent["content_sha256"]) is None
                or decision.disposition != "allow"
                or decision.evidence.policy_sha256 != policy.sha256
                or decision.evidence.content_sha256 != intent["content_sha256"]):
            return problem
        raw = _read_file(job / "document.md", policy.max_bytes)
        output_sha = _sha(raw)
        if len(raw) != intent["bytes"] or output_sha != intent["content_sha256"]:
            return problem
        hashes = {"started.json": initial_sha, closure_name: closure_sha,
                  intent_name: intent_sha, "document.md": output_sha}
        result_name = f".ash-{session_id}-01-result.json"
        if result_name in names:
            result, result_sha = _record(job / result_name, 16384)
            hashes[result_name] = result_sha
            if (result.get("session_id") != session_id
                    or result.get("call_id") != f"{session_id}:1"
                    or result.get("policy_sha256") != policy.sha256
                    or result.get("content_sha256") != output_sha
                    or result.get("artifact") != "document"
                    or result.get("decision") != intent["decision"]
                    or result.get("proposal_sha256") != intent.get("proposal_sha256")
                    or result.get("applied") is not True
                    or result.get("effect") != "created"
                    or result.get("reason") != "write_completed"
                    or result.get("output_sha256") != output_sha):
                return _unresolved(job_id, "recovery_contradictory_result")
        summary = None
        if "summary.json" in names:
            summary, summary_sha = _record(job / "summary.json", 65536)
            hashes["summary.json"] = summary_sha
            if (any(summary.get(key) != value for key, value in initial.items()
                    if key != "state")
                    or summary.get("effect") == "none"
                    or summary.get("state") not in {"saved", "needs_inspection"}):
                return _unresolved(job_id, "recovery_contradictory_summary")
        quality = None
        basic_quality = doc.evaluate_document(raw)
        if basic_quality["status"] == "failed":
            return _unresolved(job_id, "recovery_quality_failed")
        if "quality.json" in names:
            quality_record, quality_sha = _record(job / "quality.json", 8192)
            hashes["quality.json"] = quality_sha
            quality = doc._checked_quality(
                quality_record, output_sha, initial["requirements_sha256"]
            )
            if (quality["status"] == "failed"
                    or (initial["requirements_sha256"] is None and quality != basic_quality)):
                return _unresolved(job_id, "recovery_quality_failed")
        else:
            quality = basic_quality
        if summary is not None and summary.get("quality") is not None and (
            "quality.json" not in names or summary["quality"] != quality
        ):
            return _unresolved(job_id, "recovery_contradictory_summary")
        output_restrictions = restrictions.for_output(raw).record() if restrictions else None
        evidence_sha = _sha(b"ash-document-recovery-evidence-v1\0" + _canonical({
            "job_id": job_id, "configuration_sha256": config.sha256,
            "policy_sha256": policy.sha256, "record_hashes": hashes,
        }))
        return {
            "state": "recoverable_data", "job_id": job_id,
            "reason": "fenced_bytes_match_authorized_intent",
            "fence_kind": ("owned_supervisor_exit" if closure_name == "supervisor-fence.json"
                           else "normal_writer_close"),
            "document_sha256": output_sha, "recovery_evidence_sha256": evidence_sha,
            "output_restrictions": output_restrictions, "quality": quality,
            "replay_allowed": False, "original_completion_proven": False,
            "writes_performed": False,
            "next_step": "review_existing_document_then_use_new_job_id_never_replay",
        }
    except (OSError, ValueError, KeyError, TypeError):
        return problem


def read_recovered_document(
    config: DocumentConfig, job_id: str, *, reviewed_source_sha256: str,
) -> DocumentInput:
    """Capture reviewed exact bytes as data; never change the original job."""
    from agentic_security_harness import document_workflow as doc

    status = inspect_recovery(config, job_id)
    if status["state"] != "recoverable_data":
        raise ValueError(status["reason"])
    if (type(reviewed_source_sha256) is not str
            or _HEX64.fullmatch(reviewed_source_sha256) is None
            or reviewed_source_sha256 != status["document_sha256"]):
        raise doc.SourceReviewBlocked(
            "source_review_digest_mismatch", status["document_sha256"]
        )
    raw = _read_file(config.jobs_dir / doc._job_name(job_id) / "document.md", 16384)
    if _sha(raw) != status["document_sha256"]:
        raise ValueError("recovered document changed during capture")
    restrictions = (
        parse_source_restrictions(status["output_restrictions"])
        if status["output_restrictions"] is not None else None
    )
    return doc.DocumentInput(
        raw, job_id, config.data_class, restrictions,
        recovery_sha256=status["recovery_evidence_sha256"],
    )
