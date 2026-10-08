"""Closed, content-free host expectations for a finite document job run.

An expectation identifies planned work; it does not authenticate the host,
authorize an effect, or establish document correctness.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from agentic_security_harness._workspace_files import _validate_filename

_PLAN_VERSION = "ash.document-run-plan.v1"
_JOB_VERSION = "ash.expected-document-job.v1"
_JOB_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z", re.ASCII)
_SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_JOB_FIELDS = frozenset({
    "schema_version", "job_id", "task_sha256", "input_sha256", "source_job",
    "source_restrictions_sha256",
})
_JOB_BOUND_FIELDS = _JOB_FIELDS | {"execution_sha256"}
_PLAN_FIELDS = frozenset({"schema_version", "configuration_sha256", "jobs"})


def _digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _job_id(value: object) -> bool:
    if type(value) is not str or _JOB_ID.fullmatch(value) is None:
        return False
    try:
        _validate_filename(value)
    except ValueError:
        return False
    return True


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def execution_sha256(*, requirements_sha256: str | None,
                     recover_source: bool = False) -> str:
    """Bind advance-known host criteria, not a later source-output digest."""
    if requirements_sha256 is not None and not _digest(requirements_sha256):
        raise ValueError("requirements digest required")
    if type(recover_source) is not bool:
        raise ValueError("recovery flag must be boolean")
    criteria = {
        "requirements_sha256": requirements_sha256,
        "recover_source": recover_source,
    }
    return hashlib.sha256(b"ash-document-execution-v1\0" + _canonical(criteria)).hexdigest()


@dataclass(frozen=True)
class ExpectedDocumentJob:
    job_id: str
    task_sha256: str
    input_sha256: str | None = None
    source_job: str | None = None
    source_restrictions_sha256: str | None = None
    execution_sha256: str | None = None

    def __post_init__(self) -> None:
        if not _job_id(self.job_id):
            raise ValueError("portable document job ID required")
        if not _digest(self.task_sha256):
            raise ValueError("task digest required")
        if (self.input_sha256 is None) == (self.source_job is None):
            raise ValueError("exactly one input digest or source job required")
        if self.input_sha256 is not None and not _digest(self.input_sha256):
            raise ValueError("input digest required")
        if self.source_job is not None and not _job_id(self.source_job):
            raise ValueError("portable source job ID required")
        if self.source_job is not None and self.source_restrictions_sha256 is not None:
            raise ValueError("from-job restrictions are inherited, not caller-supplied")
        if self.source_restrictions_sha256 is not None and not _digest(
            self.source_restrictions_sha256
        ):
            raise ValueError("source restrictions digest required")
        if self.execution_sha256 is not None and not _digest(self.execution_sha256):
            raise ValueError("execution digest required")

    def record(self) -> dict[str, Any]:
        record = {
            "schema_version": _JOB_VERSION,
            "job_id": self.job_id,
            "task_sha256": self.task_sha256,
            "input_sha256": self.input_sha256,
            "source_job": self.source_job,
            "source_restrictions_sha256": self.source_restrictions_sha256,
        }
        if self.execution_sha256 is not None:
            record["execution_sha256"] = self.execution_sha256
        return record

    @classmethod
    def from_record(cls, value: object) -> ExpectedDocumentJob:
        if type(value) is not dict or frozenset(value) not in {_JOB_FIELDS, _JOB_BOUND_FIELDS}:
            raise ValueError("closed expected job record required")
        if value["schema_version"] != _JOB_VERSION:
            raise ValueError("unsupported expected job version")
        if "execution_sha256" in value and not _digest(value["execution_sha256"]):
            raise ValueError("execution digest required")
        return cls(
            job_id=value["job_id"], task_sha256=value["task_sha256"],
            input_sha256=value["input_sha256"], source_job=value["source_job"],
            source_restrictions_sha256=value["source_restrictions_sha256"],
            execution_sha256=value.get("execution_sha256"),
        )


@dataclass(frozen=True)
class DocumentRunPlan:
    configuration_sha256: str
    jobs: tuple[ExpectedDocumentJob, ...]

    def __post_init__(self) -> None:
        if not _digest(self.configuration_sha256):
            raise ValueError("configuration digest required")
        if type(self.jobs) is not tuple or not 1 <= len(self.jobs) <= 64:
            raise ValueError("plan requires 1..64 immutable jobs")
        seen: set[str] = set()
        for job in self.jobs:
            if type(job) is not ExpectedDocumentJob:
                raise ValueError("closed expected job required")
            if job.job_id in seen:
                raise ValueError("duplicate planned job ID")
            if job.source_job is not None and job.source_job not in seen:
                raise ValueError("source job must appear earlier in this plan")
            seen.add(job.job_id)

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": _PLAN_VERSION,
            "configuration_sha256": self.configuration_sha256,
            "jobs": [job.record() for job in self.jobs],
        }

    @classmethod
    def from_record(cls, value: object) -> DocumentRunPlan:
        if type(value) is not dict or set(value) != _PLAN_FIELDS:
            raise ValueError("closed document plan record required")
        if value["schema_version"] != _PLAN_VERSION:
            raise ValueError("unsupported document plan version")
        jobs = value["jobs"]
        if type(jobs) is not list or not 1 <= len(jobs) <= 64:
            raise ValueError("bounded job records required")
        return cls(
            configuration_sha256=value["configuration_sha256"],
            jobs=tuple(ExpectedDocumentJob.from_record(job) for job in jobs),
        )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(b"ash-document-run-plan-v1\0" + _canonical(self.record())).hexdigest()

    def for_job(self, job_id: str) -> ExpectedDocumentJob:
        if not _job_id(job_id):
            raise ValueError("portable document job ID required")
        for job in self.jobs:
            if job.job_id == job_id:
                return job
        raise ValueError("job is not in host plan")
