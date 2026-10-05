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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentic_security_harness._fixture_files import _checked_directory, _identity
from agentic_security_harness._workspace_files import WorkspaceFiles, _validate_filename
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

    def policy(self, root: Path) -> WorkspacePolicy:
        return WorkspacePolicy(
            root,
            (("document", "document.md"),),
            self.max_bytes,
            max_proposals=1,
            data_class=self.data_class,
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
    config: DocumentConfig, source_path: Path, task: str, job_id: str, *, execute: bool = False
) -> dict[str, Any]:
    """Preview by default; an explicit execute reserves the job before any model call."""
    started_at = time.perf_counter()
    job = config.jobs_dir / _job_name(job_id)
    preflight = check(config)
    if preflight["state"] != "ready":
        return preflight
    if job.exists() or job.is_symlink():
        return {
            "state": "error",
            "job_id": job_id,
            "reason": "job_already_exists",
            "effect": "none",
            "next_step": "inspect_existing_job_do_not_retry",
        }
    source = _read_file(source_path, 16384)
    args = argparse.Namespace(
        model=config.model,
        artifact="document",
        task=task,
        input=source_path,
        port=config.port,
        timeout=config.timeout,
        execute=False,
    )
    _, preview = _generate(args, config.policy(job), source=source)
    if not execute:
        return {
            **preflight,
            "state": "preview",
            "job_id": job_id,
            "reason": "preview_only",
            "input_sha256": preview["input_sha256"],
            "effect": "none",
        }
    _new_directory(job)
    policy = config.policy(job)
    initial = {
        "schema_version": VERSION,
        "job_id": job_id,
        "configuration_sha256": config.sha256,
        "policy_sha256": policy.sha256,
        "input_sha256": _sha(source),
        "task_sha256": _sha(task.encode("utf-8")),
        "engine": config.engine,
        "state": "started",
    }
    _save(job / "started.json", initial)
    args.execute = True
    metadata: dict[str, Any] = {"transport_attempts": 0}
    result: dict[str, Any] | None = None
    model_ms = 0.0
    submitted = False
    framework_requests = 0
    failure = "no_proposal"

    def generate() -> bytes | None:
        nonlocal model_ms, metadata
        clock = time.perf_counter()
        metadata = {"transport_attempts": 1}
        try:
            proposal, metadata = _generate(
                args, policy, source=source, require_requested_artifact=False
            )
            return proposal
        finally:
            model_ms += (time.perf_counter() - clock) * 1000

    try:
        with GuardedWorkspace(policy) as writer:

            def submit(proposal: bytes) -> dict[str, Any]:
                nonlocal submitted, result
                submitted = True
                result = writer.submit(proposal)
                return result

            if config.engine == "pydantic-ai":
                from agentic_security_harness.workspace_pydantic import run_local_document_agent

                framework = run_local_document_agent(generate, submit)
                framework_requests = framework["framework_requests"]
            else:
                proposal = generate()
                if proposal is not None:
                    submit(proposal)
    except Exception:
        # Raw exceptions may contain source or provider output. Preserve only phase.
        failure = "boundary_interrupted" if submitted else "agent_or_storage_unavailable"
    state = "needs_inspection" if submitted else "error"
    if result is not None:
        if result.get("applied") and result.get("receipt_complete"):
            verified = verify_workspace_output(policy, job / result["receipt"])
            if verified["integrity_ok"]:
                state = "saved"
        elif (
            result.get("reason") in {"guard_rejected", "proposal_rejected"}
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
        "next_step": _NEXT[state],
        "meaning_checked": False,
    }
    try:
        _save(job / "summary.json", summary)
    except (OSError, ValueError):
        return {
            **summary,
            "state": "needs_inspection",
            "reason": "summary_storage_unavailable",
            "next_step": "inspect_job_do_not_replay",
        }
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
        policy = config.policy(job)
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
        decision = summary.get("decision")
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
            if not verify_workspace_output(policy, job / receipt)["integrity_ok"]:
                return problem
        elif summary["state"] in {"error", "denied"}:
            if (job / "document.md").exists() or (job / "document.md").is_symlink():
                return problem
            if summary.get("effect") != "none":
                return problem
            if summary["state"] == "denied" and (
                type(decision) is not dict
                or decision.get("reason") not in {"proposal_rejected", "guard_rejected"}
                or decision.get("applied") is not False
            ):
                return problem
        # Do not echo arbitrary additional persisted fields on status inspection.
        return {
            **{
                key: summary[key]
                for key in ("schema_version", "job_id", "state", "reason", "effect")
            },
            "next_step": _NEXT[summary["state"]],
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
    if result.get("state") == "saved":
        lines.append("Document: jobs/<job-id>/document.md (review its accuracy)")
    if "timing_ms" in result:
        timing = result["timing_ms"]
        lines.append(
            "Timing ms: " + ", ".join(f"{key}={value:.2f}" for key, value in timing.items())
        )
    lines.append(f"Next: {result.get('next_step', 'document-check --help')}")
    return "\n".join(lines)
