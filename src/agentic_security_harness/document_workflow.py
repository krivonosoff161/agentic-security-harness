"""One document per exclusive job, using the existing guarded writer.

Configuration and job IDs belong to the host. No replay, resume, cloud provider,
model-selected paths, or logging of source/model text. Local state is trusted
operator state, not authenticated remote history or power-loss recovery.
"""

from __future__ import annotations

import argparse
import http.client
import importlib.metadata
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_security_harness._fixture_files import _checked_directory, _identity
from agentic_security_harness._workspace_files import WorkspaceFiles, _validate_filename
from agentic_security_harness.document_expectations import DocumentRunPlan, execution_sha256
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_quality import DocumentRequirements, evaluate_document
from agentic_security_harness.document_restrictions import (
    DocumentSourceRestrictions,
    parse_source_restrictions,
)
from agentic_security_harness.ollama_quarantine_adapter import (
    _MODEL_ID,
    OllamaQuarantineConfigV1,
    _json,
)
from agentic_security_harness.workspace_cli import _generate
from agentic_security_harness.workspace_writer import (
    GuardedWorkspace,
    WorkspacePolicy,
    _canonical,
    _read_file,
    _sha,
    verify_workspace_output,
)

VERSION = "ash.document-workflow.v1"
_JOB = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z", re.ASCII)
_STATES = {"saved", "denied", "error", "needs_inspection"}
_REASONS = {
    "write_completed",
    "guard_rejected",
    "proposal_rejected",
    "no_proposal",
    "boundary_interrupted",
    "agent_or_storage_unavailable",
    "model_response_rejected",
    "transport_unavailable",
    "transport_timeout",
    "http_rejected",
    "response_too_large",
    "intent_storage_unavailable",
    "result_storage_unavailable",
    "output_unavailable",
    "target_already_exists",
    "session_unavailable",
    "proposal_budget_exhausted",
    "workspace_identity_changed",
    "source_clock_invalid",
    "source_digest_mismatch",
    "source_class_mismatch",
    "source_storage_forbidden",
    "source_forwarding_forbidden",
    "source_recipient_forbidden",
    "source_purpose_forbidden",
    "source_confirmation_required",
    "source_expired",
}
_RESPONSE_REJECTIONS = {
    "outer_json_invalid", "outer_contract_invalid", "generation_limit_reached",
    "generation_not_completed", "proposal_encoding_invalid", "proposal_size_invalid",
    "proposal_json_invalid",
}
_NEXT = {
    "saved": "read_document_and_review_accuracy",
    "denied": "review_denial_before_new_job",
    "needs_inspection": "inspect_job_do_not_replay",
    "error": "fix_configuration_or_service_then_choose_a_new_job_id",
}


def _job_name(value: str) -> str:
    if type(value) is not str or not _JOB.fullmatch(value):
        raise ValueError("job ID must be 1..48 lowercase letters, digits, hyphens or underscores")
    _validate_filename(value)
    return value


def _new_directory(path: Path) -> None:
    before = _identity(_checked_directory(path.parent))
    os.mkdir(path, 0o700)  # Exclusive reservation, also for concurrent callers.
    if _identity(_checked_directory(path.parent)) != before:
        raise ValueError("parent changed during creation")
    _checked_directory(path)


def _save(path: Path, value: dict[str, Any]) -> None:
    with WorkspaceFiles.open(path.parent, {"record": path.name}, 65536) as files:
        raw = _canonical(value) + b"\n"
        written = files.write_once("record", raw)
        if files.readback_sha("record") != written:
            raise ValueError("record readback failed")


@dataclass(frozen=True)
class DocumentInput:
    """Captured bytes for data use only, never a policy or an executable instruction.

    Construct via ``read_job_document`` to bind an existing job's verified bytes.
    Local configuration/bookkeeping remain trusted host state, not remote attestations.
    """

    content: bytes = field(repr=False)
    source_job: str
    data_class: str
    restrictions: DocumentSourceRestrictions | DocumentMultiSourceRestrictions | None = None
    recovery_sha256: str | None = None

    def record(self) -> dict[str, Any]:
        return {
            "kind": ("recovered_document" if self.recovery_sha256 is not None
                     else "generated_document"),
            "source_job": self.source_job,
            "content_sha256": _sha(self.content),
            "trust": "untrusted",
            "authority": "none",
            "data_class": self.data_class,
            **({"recovery_evidence_sha256": self.recovery_sha256}
               if self.recovery_sha256 is not None else {}),
        }


class SourceReviewBlocked(ValueError):
    """Content-free reason for a source whose exact bytes need host review."""

    def __init__(self, reason: str, source_sha256: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.source_sha256 = source_sha256


class SourceQualityBlocked(ValueError):
    """A verified saved document failed its declared checks; review cannot override it."""


def read_job_document(
    config: DocumentConfig, job_id: str, *, reviewed_source_sha256: str | None = None,
) -> DocumentInput:
    """Read a saved job as data; refuse failed quality, changed or incomplete output.

    The destination job still obtains its permissions exclusively from its host config.
    A host digest acknowledges review of these exact bytes; it grants no authority.
    """
    status = inspect_job(config, job_id)
    if status.get("state") != "saved":
        raise ValueError("source job is not eligible as document data")
    if status.get("quality", {}).get("status") == "failed":
        raise SourceQualityBlocked("source job is not eligible as document data")
    raw = _read_file(config.jobs_dir / _job_name(job_id) / "document.md", 16384)
    # Bind the bytes actually returned, not a path validated before a later read.
    if _sha(raw) != status.get("document_sha256"):
        raise ValueError("source changed during capture")
    digest = _sha(raw)
    if reviewed_source_sha256 is not None and (
        type(reviewed_source_sha256) is not str
        or re.fullmatch(r"[a-f0-9]{64}", reviewed_source_sha256) is None
    ):
        raise SourceReviewBlocked("source_review_digest_invalid", digest)
    if reviewed_source_sha256 is not None and reviewed_source_sha256 != digest:
        raise SourceReviewBlocked("source_review_digest_mismatch", digest)
    if status["quality"]["status"] == "review_required" and reviewed_source_sha256 is None:
        raise SourceReviewBlocked("source_review_required", digest)
    restrictions = (
        parse_source_restrictions(status["output_restrictions"])
        if status.get("output_restrictions") is not None else None
    )
    return DocumentInput(raw, job_id, config.data_class, restrictions)


def _next_step(state: str, quality: dict[str, Any] | None) -> str:
    if state == "saved" and quality is not None and quality["status"] == "failed":
        return "review_failed_document_requirements_do_not_chain"
    if state == "saved" and quality is not None and quality["status"] == "review_required":
        return "review_document_then_supply_exact_sha256_for_chaining"
    return _NEXT[state]


def _checked_quality(value: Any, digest: str, requirements_digest: str | None) -> dict[str, Any]:
    """Validate content-free stored findings without echoing arbitrary stored fields."""
    reasons = {
        "checked": {"declared_json_match", "declared_checklist_match"},
        "review_required": {"human_review_required", "structure_only_review_required"},
        "failed": {
            "document_too_large", "invalid_utf8", "empty_document", "control_character",
            "json_invalid", "json_mismatch", "unclosed_fence",
            "checklist_count_mismatch", "checklist_terms_mismatch",
        },
    }
    if (
        type(value) is not dict
        or set(value) != {
            "status", "reason", "requirements_sha256", "content_sha256",
            "authority", "semantics_verified",
        }
        or type(value["status"]) is not str or value["status"] not in reasons
        or type(value["reason"]) is not str
        or value["reason"] not in reasons[value["status"]]
        or (value["status"] == "checked" and requirements_digest is None)
        or value["authority"] != "none"
        or value["semantics_verified"] is not False
        or value["content_sha256"] != digest
        or value["requirements_sha256"] != requirements_digest
        or (requirements_digest is not None and (
            type(requirements_digest) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", requirements_digest)
        ))
    ):
        raise ValueError("invalid document quality record")
    return dict(value)


@dataclass(frozen=True)
class DocumentConfig:
    jobs_dir: Path
    model: str
    engine: str = "native"
    max_bytes: int = 8192
    data_class: str = "private"
    port: int = 11434
    timeout: float = 90.0

    def __post_init__(self) -> None:
        if not isinstance(self.jobs_dir, Path) or not self.jobs_dir.is_absolute():
            raise ValueError("absolute jobs directory required")
        object.__setattr__(self, "jobs_dir", Path(os.path.abspath(self.jobs_dir)))
        if (
            type(self.model) is not str
            or not _MODEL_ID.fullmatch(self.model)
            or self.model.lower().endswith(":cloud")
        ):
            raise ValueError("explicit local model required")
        if self.engine not in {"native", "pydantic-ai"}:
            raise ValueError("unsupported engine")
        OllamaQuarantineConfigV1(port=self.port, timeout_seconds=self.timeout)
        self.policy(self.jobs_dir)  # Shared limit/classification validation.

    def policy(
        self, root: Path, *, source_restrictions_sha256: str | None = None,
        source_expires_at: datetime | None = None,
    ) -> WorkspacePolicy:
        return WorkspacePolicy(
            root,
            (("document", "document.md"),),
            self.max_bytes,
            max_proposals=1,
            data_class=self.data_class,
            source_restrictions_sha256=source_restrictions_sha256,
            source_expires_at=source_expires_at,
        )

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": VERSION,
            "jobs_dir": str(self.jobs_dir),
            "model": self.model,
            "engine": self.engine,
            "max_bytes": self.max_bytes,
            "data_class": self.data_class,
            "port": self.port,
            "timeout": self.timeout,
        }

    @property
    def sha256(self) -> str:
        return _sha(_canonical(self.record()))

    @classmethod
    def load(cls, path: Path) -> DocumentConfig:
        path = path.absolute()
        value = _json(_read_file(path, 16384), 16384)
        if (
            set(value)
            != {
                "schema_version",
                "jobs_dir",
                "model",
                "engine",
                "max_bytes",
                "data_class",
                "port",
                "timeout",
            }
            or value["schema_version"] != VERSION
            or type(value["jobs_dir"]) is not str
        ):
            raise ValueError("invalid document configuration")
        root = Path(value["jobs_dir"])
        return cls(
            (path.parent / root).absolute(),
            value["model"],
            value["engine"],
            value["max_bytes"],
            value["data_class"],
            value["port"],
            value["timeout"],
        )


def initialize(directory: Path, model: str, engine: str = "native") -> dict[str, Any]:
    """Creates only a new application directory; never adopts an existing one."""
    directory = directory.absolute()
    config = DocumentConfig(directory / "jobs", model, engine)
    _new_directory(directory)
    _new_directory(config.jobs_dir)
    record = {**config.record(), "jobs_dir": "jobs"}
    _save(directory / "document.json", record)
    return {
        "state": "initialized",
        "reason": "configuration_created",
        "configuration": "document.json",
        "engine": engine,
        "next_step": "document-check --config <directory>/document.json --check-model",
    }


def _engine_available(engine: str) -> bool:
    if engine == "native":
        return True
    try:
        return importlib.metadata.version("pydantic-ai-slim") == "1.107.1"
    except importlib.metadata.PackageNotFoundError:
        return False


def model_available(config: DocumentConfig) -> str:
    """Explicit bounded metadata GET; no generation, redirects, proxy or credentials."""
    connection = http.client.HTTPConnection("127.0.0.1", config.port, timeout=2.0)
    try:
        connection.request("GET", "/api/tags")
        response = connection.getresponse()
        if response.status != 200:
            return "service_unavailable"
        value = _json(response.read(65537), 65536)
        models = value.get("models")
        if type(models) is not list or len(models) > 512:
            return "service_unavailable"
        return (
            "available"
            if any(type(row) is dict and row.get("name") == config.model for row in models)
            else "model_not_installed"
        )
    except (OSError, ValueError, http.client.HTTPException):
        return "service_unavailable"
    finally:
        connection.close()


def check(config: DocumentConfig, *, check_model: bool = False) -> dict[str, Any]:
    config.policy(config.jobs_dir).check()
    available = _engine_available(config.engine)
    model = model_available(config) if check_model else "not_checked"
    ready = available and model in {"available", "not_checked"}
    return {
        "state": "ready" if ready else "error",
        "configuration_valid": True,
        "reason": (
            "preflight_ok" if ready else "optional_engine_unavailable" if not available else model
        ),
        "model_availability": model,
        "next_step": (
            "document-run --help"
            if ready
            else "install_document_agent_extra"
            if not available
            else "check_existing_local_ollama_and_exact_model_name"
        ),
        "permission_preview": {
            "operation": "create_new_text_file",
            "artifact": "document",
            "filename": "document.md",
            "overwrite": False,
            "source_byte_limit": 16384,
            "output_byte_limit": config.max_bytes,
            "model_calls_per_job": 1,
        },
        "write_permissions_probed": False,
        "writes_performed": False,
        "network_performed": check_model,
        "configuration_sha256": config.sha256,
    }


def run_job(
    config: DocumentConfig, source_path: Path | None, task: str, job_id: str, *,
    execute: bool = False, source_job: str | None = None,
    requirements: DocumentRequirements | None = None,
    reviewed_source_sha256: str | None = None,
    source_restrictions: DocumentSourceRestrictions | DocumentMultiSourceRestrictions | None = None,
    expected_input_sha256: str | None = None,
    run_plan_sha256: str | None = None,
    run_plan_path: Path | None = None,
    run_plan: DocumentRunPlan | None = None,
    supervisor_nonce: str | None = None,
    recover_source: bool = False,
) -> dict[str, Any]:
    """Preview by default; an explicit execute reserves the job before any model call."""
    started_at = time.perf_counter()
    job = config.jobs_dir / _job_name(job_id)
    preflight = check(config)
    if preflight["state"] != "ready":
        return preflight
    def existing_job() -> dict[str, Any]:
        return {
            "state": "error",
            "job_id": job_id,
            "reason": "job_already_exists",
            "effect": "none",
            "next_step": "inspect_existing_job_do_not_retry",
        }

    if job.exists() or job.is_symlink():
        return existing_job()
    if (source_path is None) == (source_job is None):
        raise ValueError("select exactly one source file or saved source job")
    if reviewed_source_sha256 is not None and source_job is None:
        raise ValueError("reviewed source digest requires a source job")
    if type(recover_source) is not bool or (recover_source and source_job is None):
        raise ValueError("source recovery requires a source job")
    if recover_source and reviewed_source_sha256 is None:
        return {"state": "error", "job_id": job_id, "effect": "none",
                "reason": "source_recovery_review_required",
                "next_step": "inspect_recovery_and_review_exact_bytes_before_new_job"}
    if requirements is not None and type(requirements) is not DocumentRequirements:
        raise ValueError("invalid host document requirements")
    if (source_restrictions is not None
            and type(source_restrictions) not in (
                DocumentSourceRestrictions, DocumentMultiSourceRestrictions)):
        raise ValueError("invalid host source restrictions")
    if source_job is not None and source_restrictions is not None:
        raise ValueError("source job restrictions cannot be overridden")
    for digest in (expected_input_sha256, run_plan_sha256):
        if digest is not None and (
            type(digest) is not str or re.fullmatch(r"[a-f0-9]{64}", digest) is None
        ):
            raise ValueError("invalid host expectation digest")
    if supervisor_nonce is not None and (
        type(supervisor_nonce) is not str or re.fullmatch(r"[a-f0-9]{32}", supervisor_nonce) is None
    ):
        raise ValueError("host supervisor nonce required")
    if run_plan_path is not None and run_plan is not None:
        raise ValueError("select one plan path or admitted plan")
    if (run_plan_path is None and run_plan is None) != (run_plan_sha256 is None):
        raise ValueError("plan and retained digest must be supplied together")
    if run_plan is not None and (
        type(run_plan) is not DocumentRunPlan or run_plan.sha256 != run_plan_sha256
    ):
        raise ValueError("admitted plan differs from retained digest")
    expected_job = None
    plan = run_plan
    if run_plan_path is not None:
        # Lazy import avoids a module cycle; coverage uses this actual workflow.
        from agentic_security_harness.document_coverage import load_plan

        assert run_plan_sha256 is not None
        plan = load_plan(run_plan_path, expected_sha256=run_plan_sha256)
    if plan is not None:
        if plan.configuration_sha256 != config.sha256:
            raise ValueError("plan configuration mismatch")
        expected_job = plan.for_job(job_id)
        if type(task) is not str or _sha(task.encode("utf-8")) != expected_job.task_sha256:
            raise ValueError("task differs from host expectation")
        if source_job != expected_job.source_job:
            raise ValueError("source job differs from host expectation")
        if (expected_input_sha256 is not None
                and expected_input_sha256 != expected_job.input_sha256):
            raise ValueError("input expectation cannot override plan")
        expected_input_sha256 = expected_job.input_sha256
        restriction_digest = source_restrictions.sha256 if source_restrictions is not None else None
        if source_job is None and restriction_digest != expected_job.source_restrictions_sha256:
            raise ValueError("source restrictions differ from host expectation")
    requirements_digest = (
        _sha(_canonical(requirements.record())) if requirements is not None else None
    )
    if (expected_job is not None and expected_job.execution_sha256 is not None
            and execution_sha256(
                requirements_sha256=requirements_digest,
                recover_source=recover_source,
            ) != expected_job.execution_sha256):
        raise ValueError("execution differs from host expectation")
    generation_json = requirements is not None and requirements.mode == "exact_json"
    if source_job is not None:
        try:
            if recover_source:
                from agentic_security_harness.document_recovery import read_recovered_document

                assert reviewed_source_sha256 is not None
                captured = read_recovered_document(
                    config, source_job, reviewed_source_sha256=reviewed_source_sha256,
                )
            else:
                captured = read_job_document(
                    config, source_job, reviewed_source_sha256=reviewed_source_sha256
                )
        except SourceReviewBlocked as exc:
            return {
                "state": "error", "job_id": job_id, "reason": exc.reason,
                "source_sha256": exc.source_sha256, "effect": "none",
                "next_step": "inspect_source_and_review_exact_bytes_before_new_job",
            }
        source, provenance = captured.content, captured.record()
        source_restrictions = captured.restrictions
    else:
        assert source_path is not None
        source = _read_file(source_path, 16384)
        provenance = {
            "kind": "host_selected_file", "source_job": None,
            "content_sha256": _sha(source), "trust": "untrusted",
            "authority": "none", "data_class": config.data_class,
        }

    if expected_input_sha256 is not None and _sha(source) != expected_input_sha256:
        raise ValueError("captured input differs from host expectation")

    def source_reason() -> str | None:
        return source_restrictions.admission_reason(
            source, data_class=config.data_class, now=datetime.now(UTC)
        ) if source_restrictions is not None else None

    reason = source_reason()
    if reason is not None:
        return {
            "state": "error", "job_id": job_id, "reason": reason, "effect": "none",
            "model": {"transport_attempts": 0},
            "next_step": "review_host_source_restrictions_before_new_job",
        }
    restriction_fields = {
        "source_restrictions": source_restrictions.record(),
        "source_restrictions_sha256": source_restrictions.sha256,
    } if source_restrictions is not None else {}
    policy = config.policy(
        job, source_restrictions_sha256=(
            source_restrictions.sha256 if source_restrictions is not None else None
        ),
        source_expires_at=(
            source_restrictions.expires_at if source_restrictions is not None else None
        ),
    )
    args = argparse.Namespace(
        model=config.model,
        artifact="document",
        task=task,
        input=source_path,
        port=config.port,
        timeout=config.timeout,
        execute=False,
    )
    try:
        _, preview = _generate(
            args, policy, source=source, document_content=True, generation_json=generation_json,
        )
    except ValueError as exc:
        # Another caller can reserve and finish this job after our first absence
        # check but before the output-path check in _generate. Translate only
        # that exact collision; malformed inputs still fail before reservation.
        if exc.args == ("selected output already exists",) and (
            job.exists() or job.is_symlink()
        ):
            return existing_job()
        raise
    if not execute:
        return {
            **preflight,
            "state": "preview",
            "job_id": job_id,
            "reason": "preview_only",
            "input_sha256": preview["input_sha256"],
            "input_provenance": provenance,
            "requirements_sha256": requirements_digest,
            "reviewed_source_sha256": reviewed_source_sha256,
            "effect": "none",
            **restriction_fields,
        }
    try:
        _new_directory(job)
    except FileExistsError:
        # Exclusive mkdir is the final reservation boundary. A concurrent
        # winner may have reserved this exact job after both previews passed.
        if job.exists() or job.is_symlink():
            return existing_job()
        raise
    initial = {
        "schema_version": VERSION,
        "job_id": job_id,
        "configuration_sha256": config.sha256,
        "policy_sha256": policy.sha256,
        "input_sha256": _sha(source),
        "input_provenance": provenance,
        "reviewed_source_sha256": reviewed_source_sha256,
        "requirements_sha256": requirements_digest,
        "task_sha256": _sha(task.encode("utf-8")),
        "engine": config.engine,
        "state": "started",
        **restriction_fields,
        **({"run_plan_sha256": run_plan_sha256} if run_plan_sha256 is not None else {}),
        **({"supervisor_nonce": supervisor_nonce} if supervisor_nonce is not None else {}),
    }
    _save(job / "started.json", initial)
    args.execute = True
    metadata: dict[str, Any] = {"transport_attempts": 0}
    result: dict[str, Any] | None = None
    model_ms = 0.0
    submitted = False
    framework_requests = 0
    failure = "no_proposal"
    writer: GuardedWorkspace | None = None

    def generate() -> bytes | None:
        nonlocal model_ms, metadata, failure
        # TTL may have elapsed while reserving/opening the local job. Recheck
        # before sending any bytes, not only at the earlier preview boundary.
        reason = source_reason()
        if reason is not None:
            failure = reason
            return None
        clock = time.perf_counter()
        metadata = {"transport_attempts": 1}
        try:
            proposal, metadata = _generate(
                args, policy, source=source, document_content=True,
                generation_json=generation_json,
            )
            return proposal
        finally:
            model_ms += (time.perf_counter() - clock) * 1000

    try:
        with GuardedWorkspace(policy) as writer:
            write_text = writer.bind_text_tool("document")

            def submit(content: str) -> dict[str, Any]:
                nonlocal submitted, result, failure
                reason = source_reason()
                if reason is not None:
                    failure = reason
                    return {"applied": False, "reason": reason, "effect": "none"}
                submitted = True
                result = write_text(content)
                return result

            if config.engine == "pydantic-ai":
                from agentic_security_harness.workspace_pydantic import (
                    run_local_text_document_agent,
                )

                framework = run_local_text_document_agent(generate, submit)
                framework_requests = framework["framework_requests"]
            else:
                proposal = generate()
                if proposal is not None:
                    submit(proposal.decode("utf-8"))
    except Exception:
        # Raw exceptions may contain source or provider output. Preserve only phase.
        failure = "boundary_interrupted" if submitted else "agent_or_storage_unavailable"
    state = "needs_inspection" if submitted else "error"
    quality: dict[str, Any] | None = None
    output_restrictions = None
    if result is not None:
        if result.get("applied") and result.get("receipt_complete"):
            verified = verify_workspace_output(policy, job / result["receipt"])
            if verified["integrity_ok"]:
                try:
                    raw = _read_file(job / "document.md", policy.max_bytes)
                    if _sha(raw) == verified["sha256"]:
                        quality = evaluate_document(raw, requirements)
                        _save(job / "quality.json", quality)
                        if source_restrictions is not None:
                            output_restrictions = source_restrictions.for_output(raw).record()
                        state = "saved"
                except (OSError, ValueError):
                    pass  # A write may exist; preserve needs_inspection, never retry.
        elif (
            result.get("reason") in {"guard_rejected", "proposal_rejected", "source_expired"}
            and result.get("receipt_complete")
            and result.get("effect") == "none"
        ):
            state = "denied"
    summary = {
        **initial,
        "state": state,
        "reason": result["reason"]
        if result
        else failure
        if failure != "no_proposal"
        else metadata.get("reason", failure),
        "effect": result.get("effect", "unknown_inspect_output")
        if result
        else "unknown_inspect_output"
        if submitted
        else "none",
        "decision": result,
        "model": metadata,
        "framework_requests": framework_requests,
        "timing_ms": {
            "model": model_ms,
            "total": (time.perf_counter() - started_at) * 1000,
            **(result.get("timing_ms", {}) if result else {}),
        },
        "quality": quality,
        "output_trust": "untrusted",
        "output_authority": "none",
        **({"output_restrictions": output_restrictions} if restriction_fields else {}),
        "next_step": (
            "choose_new_job_with_shorter_task_or_smaller_source"
            if state == "error" and metadata.get("response_rejection") == "generation_limit_reached"
            else _next_step(state, quality)
        ),
        "meaning_checked": False,
    }
    try:
        _save(job / "summary.json", summary)
    except (OSError, ValueError):
        summary = {
            **summary,
            "state": "needs_inspection",
            "reason": "summary_storage_unavailable",
            "next_step": "inspect_job_do_not_replay",
        }
    # Persist only after this job has finished all ordinary bookkeeping. A
    # process killed before here has no fence and cannot be assumed stopped.
    # Failure does not invent a fence or repeat an already attempted effect.
    if writer is not None:
        try:
            _save(job / "session-closed.json", writer.closure_record())
        except (OSError, ValueError):
            pass
    return summary


def inspect_job(config: DocumentConfig, job_id: str) -> dict[str, Any]:
    """No execution; only compare trusted local bookkeeping and current output bytes."""
    job = config.jobs_dir / _job_name(job_id)
    problem = {
        "state": "needs_inspection",
        "job_id": job_id,
        "reason": "incomplete_running_or_changed_job",
        "effect": "unknown_inspect_output",
        "next_step": "inspect_job_do_not_replay",
        "writes_performed": False,
    }
    try:
        _checked_directory(config.jobs_dir)
        if not job.exists() and not job.is_symlink():
            return {**problem, "state": "not_found", "reason": "job_not_found", "effect": "none"}
        _checked_directory(job)
        initial = _json(_read_file(job / "started.json", 65536), 65536)
        summary = _json(_read_file(job / "summary.json", 65536), 65536)
        source_restrictions = None
        if "source_restrictions" in initial or "source_restrictions_sha256" in initial:
            source_restrictions = parse_source_restrictions(
                initial["source_restrictions"]
            )
            restriction_record = source_restrictions.record()
            if (
                source_restrictions.sha256 != initial.get("source_restrictions_sha256")
                or restriction_record["content_sha256"] != initial.get("input_sha256")
                or source_restrictions.data_class != config.data_class
            ):
                return problem
        policy = config.policy(
            job, source_restrictions_sha256=(
                source_restrictions.sha256 if source_restrictions is not None else None
            ),
            source_expires_at=(
                source_restrictions.expires_at if source_restrictions is not None else None
            ),
        )
        if (
            initial.get("job_id") != job_id
            or initial.get("configuration_sha256") != config.sha256
            or initial.get("policy_sha256") != policy.sha256
            or initial.get("schema_version") != VERSION
            or summary.get("state") not in _STATES
            or summary.get("reason") not in _REASONS
            or summary.get("effect") not in {"none", "created", "unknown_inspect_output"}
            or any(summary.get(key) != value for key, value in initial.items() if key != "state")
        ):
            return problem
        # A supervisor fence records an interrupted worker, never ordinary
        # completion. Do not allow a saved summary written just before child
        # exit to outrun the post-exit fence.
        if (job / "supervisor-fence.json").exists() or (job / "supervisor-fence.json").is_symlink():
            return problem
        decision = summary.get("decision")
        model = summary.get("model")
        response_rejection = None
        if type(model) is not dict:
            return problem
        if "response_rejection" in model:
            response_rejection = model["response_rejection"]
            if (type(response_rejection) is not str
                    or response_rejection not in _RESPONSE_REJECTIONS
                    or summary["state"] != "error"
                    or summary["reason"] != "model_response_rejected"):
                return problem
        quality = None
        output_digest = None
        output_restrictions = None
        provenance = initial.get("input_provenance")
        reviewed_digest = initial.get("reviewed_source_sha256")
        if ("reviewed_source_sha256" in initial and reviewed_digest is not None and (
            type(reviewed_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", reviewed_digest) is None
            or reviewed_digest != initial.get("input_sha256")
            or type(provenance) is not dict
            or provenance.get("kind") not in {"generated_document", "recovered_document"}
        )):
            return problem
        if provenance is not None and (
            type(provenance) is not dict
            or set(provenance) != {
                "kind", "source_job", "content_sha256", "trust", "authority", "data_class",
            } | ({"recovery_evidence_sha256"} if provenance.get("kind") == "recovered_document"
                 else set())
            or provenance["kind"] not in {
                "host_selected_file", "generated_document", "recovered_document",
            }
            or (provenance["kind"] == "recovered_document" and (
                type(provenance.get("recovery_evidence_sha256")) is not str
                or re.fullmatch(r"[a-f0-9]{64}", provenance["recovery_evidence_sha256"]) is None
            ))
            or provenance["trust"] != "untrusted" or provenance["authority"] != "none"
            or provenance["data_class"] != config.data_class
            or provenance["content_sha256"] != initial.get("input_sha256")
            or (provenance["kind"] == "host_selected_file" and provenance["source_job"] is not None)
            or (provenance["kind"] in {"generated_document", "recovered_document"} and (
                type(provenance["source_job"]) is not str
                or _job_name(provenance["source_job"]) == job_id
            ))
        ):
            return problem
        if type(decision) is dict:
            receipt = decision.get("receipt")
            if summary["state"] in {"saved", "denied"}:
                if type(receipt) is not str or not re.fullmatch(
                    r"\.ash-[a-f0-9]{32}-01-result\.json", receipt
                ):
                    return problem
                observed = _json(_read_file(job / receipt, 16384), 16384)
                if observed != {
                    key: value for key, value in decision.items() if key != "timing_ms"
                }:
                    return problem
                intent_name = receipt.replace("-result.json", "-intent.json")
                intent = _json(_read_file(job / intent_name, 16384), 16384)
                if (
                    intent.get("phase") != "intent"
                    or observed.get("receipt_complete") is not True
                    or any(
                        intent.get(key) != observed.get(key)
                        for key in ("call_id", "policy_sha256", "proposal_sha256", "decision")
                    )
                ):
                    return problem
        if summary["state"] == "saved":
            if type(decision) is not dict or type(decision.get("receipt")) is not str:
                return problem
            # Never read arbitrary paths from even a locally changed summary.
            receipt = decision["receipt"]
            if not re.fullmatch(r"\.ash-[a-f0-9]{32}-[0-9]{2}-result\.json", receipt):
                return problem
            if "supervisor_nonce" in initial:
                nonce = initial["supervisor_nonce"]
                session = re.fullmatch(r"\.ash-([a-f0-9]{32})-01-result\.json", receipt)
                if (type(nonce) is not str
                        or re.fullmatch(r"[a-f0-9]{32}", nonce) is None
                        or session is None):
                    return problem
                closure = _json(_read_file(job / "session-closed.json", 16384), 16384)
                if (type(closure) is not dict
                        or set(closure) != {"schema_version", "session_id", "policy_sha256",
                                            "attempts", "closed", "replay_allowed"}
                        or closure["schema_version"] != "ash.workspace-session-closed.v1"
                        or closure["session_id"] != session.group(1)
                        or closure["policy_sha256"] != policy.sha256
                        or type(closure["attempts"]) is not int
                        or closure["attempts"] != 1
                        or closure["closed"] is not True
                        or closure["replay_allowed"] is not False):
                    return problem
            verified = verify_workspace_output(policy, job / receipt)
            if not verified["integrity_ok"]:
                return problem
            output_digest = verified["sha256"]
            raw = _read_file(job / "document.md", policy.max_bytes)
            if _sha(raw) != output_digest:
                return problem
            if source_restrictions is not None:
                output_restrictions = source_restrictions.for_output(raw).record()
            if summary.get("output_restrictions") != output_restrictions:
                return problem
            basic_quality = evaluate_document(raw)
            if "quality" in summary:
                quality = _checked_quality(
                    summary["quality"], output_digest, initial.get("requirements_sha256")
                )
                if _json(_read_file(job / "quality.json", 8192), 8192) != quality:
                    return problem
                if initial.get("requirements_sha256") is None and quality != basic_quality:
                    return problem
                if basic_quality["status"] == "failed" and quality["status"] != "failed":
                    return problem
            else:
                if provenance is not None or initial.get("requirements_sha256") is not None:
                    return problem
                quality = basic_quality  # Legacy local jobs were never semantic approvals.
        elif summary["state"] in {"error", "denied"}:
            if (job / "document.md").exists() or (job / "document.md").is_symlink():
                return problem
            if summary.get("effect") != "none":
                return problem
            if summary["state"] == "denied" and (
                type(decision) is not dict
                or decision.get("reason") not in {
                    "proposal_rejected", "guard_rejected", "source_expired",
                }
                or decision.get("applied") is not False
            ):
                return problem
        # Do not echo arbitrary additional persisted fields on status inspection.
        return {
            **{
                key: summary[key]
                for key in ("schema_version", "job_id", "state", "reason", "effect")
            },
            "document_sha256": output_digest,
            "quality": quality,
            "output_trust": "untrusted",
            "output_authority": "none",
            **({"output_restrictions": output_restrictions}
               if source_restrictions is not None else {}),
            **({"response_rejection": response_rejection}
               if response_rejection is not None else {}),
            "next_step": (
                "choose_new_job_with_shorter_task_or_smaller_source"
                if response_rejection == "generation_limit_reached"
                else _next_step(summary["state"], quality)
            ),
            "writes_performed": False,
        }
    except (OSError, ValueError, KeyError, TypeError):
        return problem


def human_report(result: dict[str, Any]) -> str:
    """Fixed labels/values only; never renders a source or model-provided document."""
    lines = [
        f"Status: {result.get('state', 'error')}",
        f"Reason: {result.get('reason', 'unknown')}",
    ]
    if "job_id" in result:
        lines.append(f"Job: {result['job_id']}")
    if "effect" in result:
        lines.append(f"Effect: {result['effect']}")
    source_sha256 = result.get("source_sha256")
    if (result.get("reason") in {
        "source_review_required", "source_review_digest_invalid", "source_review_digest_mismatch"
    } and type(source_sha256) is str
            and re.fullmatch(r"[a-f0-9]{64}", source_sha256)):
        lines.append(f"Source SHA-256: {source_sha256}")
    model = result.get("model")
    response_rejection = (
        model.get("response_rejection") if type(model) is dict
        else result.get("response_rejection")
    )
    if type(response_rejection) is str and response_rejection in _RESPONSE_REJECTIONS:
        lines.append(f"Generation: {response_rejection}")
    if result.get("state") == "saved":
        lines.append("Document: jobs/<job-id>/document.md (review its accuracy)")
        lines.append("Trust: untrusted data; grants no authority to another agent")
        quality = result.get("quality")
        if quality:
            lines.append(f"Declared quality: {quality['status']} ({quality['reason']})")
    if result.get("state") == "recoverable_data":
        lines.append("Recovery: existing bytes only; original outcome remains unresolved")
        lines.append("Next job requires exact-byte review; the original action cannot be replayed")
        document_digest = result.get("document_sha256")
        if type(document_digest) is str and re.fullmatch(r"[a-f0-9]{64}", document_digest):
            lines.append(f"Document SHA-256: {document_digest}")
    if "timing_ms" in result:
        timing = result["timing_ms"]
        lines.append(
            "Timing ms: " + ", ".join(f"{key}={value:.2f}" for key, value in timing.items())
        )
    lines.append(f"Next: {result.get('next_step', 'document-check --help')}")
    return "\n".join(lines)
