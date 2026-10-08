"""Compile a bounded host-owned document recipe into existing job expectations.

Compilation reads selected files but never calls a model or creates a job. A plan
identifies expected work; it grants no authority to perform that work.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PureWindowsPath
from typing import Any

from agentic_security_harness.document_coverage import save_plan
from agentic_security_harness.document_expectations import (
    DocumentRunPlan,
    ExpectedDocumentJob,
    execution_sha256,
)
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.document_workflow import DocumentConfig, _job_name
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.workspace_writer import _canonical, _read_file

_VERSION = "ash.document-plan-spec.v1"
_FIELDS = frozenset({"schema_version", "jobs"})
_JOB_REQUIRED = frozenset({"job_id", "task"})
_JOB_OPTIONAL = frozenset({
    "input", "from_job", "requirements", "source_restrictions",
    "recover_source",
})


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path(parent: Path, value: object) -> Path:
    if type(value) is not str or not 0 < len(value) <= 512 or "\0" in value:
        raise ValueError("bounded relative spec path required")
    relative = Path(value)
    windows = PureWindowsPath(value)
    if (relative.is_absolute() or relative.anchor or relative.drive
            or windows.is_absolute() or windows.anchor or windows.drive):
        raise ValueError("relative spec path required")
    return (parent / relative).absolute()


def _optional_record(parent: Path, value: object, limit: int) -> dict[str, Any]:
    return _json(_read_file(_path(parent, value), limit), limit)


def _load_rows(
    config: DocumentConfig, spec_path: Path,
) -> tuple[Path, list[dict[str, Any]]]:
    if type(config) is not DocumentConfig or not isinstance(spec_path, Path):
        raise ValueError("document configuration and spec path required")
    spec_path = spec_path.absolute()
    spec = _json(_read_file(spec_path, 65536), 65536)
    if set(spec) != _FIELDS or spec["schema_version"] != _VERSION:
        raise ValueError("closed document plan spec required")
    rows = spec["jobs"]
    if type(rows) is not list or not 1 <= len(rows) <= 64:
        raise ValueError("plan requires 1..64 jobs")
    seen: set[str] = set()
    for row in rows:
        if (type(row) is not dict or not _JOB_REQUIRED <= set(row)
                or set(row) - (_JOB_REQUIRED | _JOB_OPTIONAL)):
            raise ValueError("closed document job spec required")
        job_id, task = row["job_id"], row["task"]
        _job_name(job_id)
        if job_id in seen:
            raise ValueError("duplicate planned job ID")
        if type(task) is not str or not 0 < len(task.encode("utf-8")) <= 4096:
            raise ValueError("task byte limit")
        if ("input" in row) == ("from_job" in row):
            raise ValueError("exactly one input or from_job required")
        source_job = row.get("from_job")
        if "from_job" in row and (type(source_job) is not str or source_job not in seen):
            raise ValueError("source job must appear earlier in plan")
        if "source_restrictions" in row and "from_job" in row:
            raise ValueError("from-job restrictions are inherited")
        recover = row.get("recover_source", False)
        if type(recover) is not bool or (recover and "from_job" not in row):
            raise ValueError("recovery requires from_job")
        for field in ("input", "requirements", "source_restrictions"):
            if field in row:
                _path(spec_path.parent, row[field])
        seen.add(job_id)
    return spec_path, rows


def _compile_job(
    config: DocumentConfig, parent: Path, row: dict[str, Any],
) -> tuple[ExpectedDocumentJob, dict[str, Any]]:
    requirements_record = (
        _optional_record(parent, row["requirements"], 8192)
        if "requirements" in row else None
    )
    requirements = (
        DocumentRequirements.from_record(requirements_record)
        if requirements_record is not None else None
    )
    restrictions_record = (
        _optional_record(parent, row["source_restrictions"], 8192)
        if "source_restrictions" in row else None
    )
    restrictions = (
        DocumentSourceRestrictions.from_record(restrictions_record)
        if restrictions_record is not None else None
    )
    source_path = _path(parent, row["input"]) if "input" in row else None
    raw = _read_file(source_path, 16384) if source_path is not None else None
    if raw is not None:
        raw.decode("utf-8")
    if restrictions is not None and raw is not None:
        bound = restrictions.record()
        if bound["content_sha256"] != _sha(raw):
            raise ValueError("source restriction digest mismatch")
        if bound["envelope"]["data_class"] != config.data_class:
            raise ValueError("source restriction class mismatch")

    requirements_sha = (
        _sha(_canonical(requirements.record())) if requirements is not None else None
    )
    task = row["task"]
    source_job = row.get("from_job")
    recover = row.get("recover_source", False)
    expectation = ExpectedDocumentJob(
        job_id=row["job_id"],
        task_sha256=_sha(task.encode("utf-8")),
        input_sha256=_sha(raw) if raw is not None else None,
        source_job=source_job,
        source_restrictions_sha256=restrictions.sha256 if restrictions is not None else None,
        execution_sha256=execution_sha256(
            requirements_sha256=requirements_sha,
            recover_source=recover,
        ),
    )
    arguments = {
        "source_path": source_path,
        "task": task,
        "source_job": source_job,
        "requirements": requirements,
        "source_restrictions": restrictions,
        "reviewed_source_sha256": None,
        "recover_source": recover,
    }
    return expectation, arguments


def compile_plan(config: DocumentConfig, spec_path: Path) -> DocumentRunPlan:
    """Read and validate a closed host spec, without writing or generating."""
    spec_path, rows = _load_rows(config, spec_path)
    expected = tuple(_compile_job(config, spec_path.parent, row)[0] for row in rows)
    return DocumentRunPlan(config.sha256, expected)


def job_arguments(config: DocumentConfig, spec_path: Path, job_id: str) -> dict[str, Any]:
    """Validate the recipe, then read only one job's ``run_job`` arguments."""
    spec_path, rows = _load_rows(config, spec_path)
    _job_name(job_id)
    for row in rows:
        if row["job_id"] == job_id:
            return _compile_job(config, spec_path.parent, row)[1]
    raise ValueError("job is not in host spec")


def prepare_plan(
    config: DocumentConfig, spec_path: Path, out_path: Path, *, execute: bool = False,
) -> dict[str, Any]:
    """Preview by default; explicit execute creates the plan once before jobs."""
    if type(execute) is not bool or not isinstance(out_path, Path):
        raise ValueError("plan output path and execute flag required")
    plan = compile_plan(config, spec_path)
    if execute:
        return save_plan(config, plan, out_path)
    return {"state": "preview", "plan_sha256": plan.sha256,
            "planned_jobs": len(plan.jobs), "writes_performed": False, "authority": "none"}
