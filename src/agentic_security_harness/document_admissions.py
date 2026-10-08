"""Create-only host decisions for bounded document-job admissions.

The separately retained head is an operator trust premise, not a remote witness.
These records neither authorize an effect nor infer decisions from model output.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

from agentic_security_harness._fixture_files import _checked_directory
from agentic_security_harness.document_expectations import DocumentRunPlan, ExpectedDocumentJob
from agentic_security_harness.document_workflow import DocumentConfig, _job_name, _save
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.workspace_writer import _canonical, _read_file

_VERSION = "ash.document-admission.v1"
_SHA = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_REASON = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z", re.ASCII)
_BASE = frozenset({"schema_version", "sequence", "previous_sha256", "kind"})
_FIELDS = {
    "root": _BASE | {"plan", "pending_decisions"},
    "declare": _BASE | {"decision_id", "parent_job"},
    "resolve_job": _BASE | {"decision_id", "job"},
    "resolve_stop": _BASE | {"decision_id", "reason"},
    "seal": _BASE,
}
_MAX_RECORDS = 256
_MAX_DECISIONS = 128


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(b"ash-document-admission-v1\0" + _canonical(value)).hexdigest()


def _checked_head(value: object) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError("separately retained admission head required")
    return value


def _checked_id(value: object) -> str:
    if type(value) is not str:
        raise ValueError("portable admission ID required")
    return _job_name(value)  # Same bounded, portable spelling as document jobs.


def _checked_path(config: DocumentConfig, path: Path) -> Path:
    if type(config) is not DocumentConfig or not isinstance(path, Path):
        raise ValueError("document configuration and ledger path required")
    result = Path(os.path.abspath(path))
    if result.is_relative_to(config.jobs_dir):
        raise ValueError("admission ledger must be outside jobs root")
    return result


def _record(kind: str, sequence: int, previous: str | None, **fields: Any) -> dict[str, Any]:
    return {"schema_version": _VERSION, "sequence": sequence,
            "previous_sha256": previous, "kind": kind, **fields}


def _closed(value: object, kind: str, sequence: int, previous: str | None) -> dict[str, Any]:
    if (type(value) is not dict or set(value) != _FIELDS[kind]
            or value["schema_version"] != _VERSION
            or value["kind"] != kind or type(value["sequence"]) is not int
            or value["sequence"] != sequence or value["previous_sha256"] != previous):
        raise ValueError("closed admission record required")
    return value


@dataclass(frozen=True)
class AdmissionSnapshot:
    """Immutable finite state reconstructed from exact numbered records."""

    plan: DocumentRunPlan
    job_plan_sha256: tuple[tuple[str, str], ...]
    pending_decisions: tuple[str, ...]
    resolved_decisions: tuple[str, ...]
    decision_parents: tuple[tuple[str, str | None], ...]
    sealed: bool
    head_sha256: str
    sequence: int

    def plan_sha256_for(self, job_id: str) -> str:
        _checked_id(job_id)
        for admitted_id, digest in self.job_plan_sha256:
            if admitted_id == job_id:
                return digest
        raise ValueError("job is not admitted")


def _root_snapshot(config: DocumentConfig, value: dict[str, Any]) -> AdmissionSnapshot:
    _closed(value, "root", 0, None)
    plan = DocumentRunPlan.from_record(value["plan"])
    if plan.configuration_sha256 != config.sha256:
        raise ValueError("admission configuration mismatch")
    if any(job.execution_sha256 is None for job in plan.jobs):
        raise ValueError("fully execution-bound root jobs required")
    pending = value["pending_decisions"]
    if type(pending) is not list or len(pending) > _MAX_DECISIONS:
        raise ValueError("bounded initial decisions required")
    ids = tuple(_checked_id(item) for item in pending)
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate initial decision")
    return AdmissionSnapshot(
        plan=plan, job_plan_sha256=tuple((job.job_id, plan.sha256) for job in plan.jobs),
        pending_decisions=ids, resolved_decisions=(),
        decision_parents=tuple((decision_id, None) for decision_id in ids),
        sealed=False, head_sha256=_digest(value), sequence=0,
    )


def _next_snapshot(state: AdmissionSnapshot, value: dict[str, Any]) -> AdmissionSnapshot:
    kind = value.get("kind") if type(value) is dict else None
    if type(kind) is not str or kind not in {"declare", "resolve_job", "resolve_stop", "seal"}:
        raise ValueError("unknown admission event")
    _closed(value, kind, state.sequence + 1, state.head_sha256)
    if state.sealed:
        raise ValueError("sealed admission ledger")
    plan = state.plan
    job_plan = state.job_plan_sha256
    pending = state.pending_decisions
    resolved = state.resolved_decisions
    parents = state.decision_parents
    if kind == "declare":
        decision_id = _checked_id(value["decision_id"])
        parent_job = _checked_id(value["parent_job"])
        plan.for_job(parent_job)
        if decision_id in {existing for existing, _ in parents}:
            raise ValueError("decision ID already used")
        if len(parents) >= _MAX_DECISIONS:
            raise ValueError("decision limit reached")
        pending = (*pending, decision_id)
        parents = (*parents, (decision_id, parent_job))
    elif kind in {"resolve_job", "resolve_stop"}:
        decision_id = _checked_id(value["decision_id"])
        if decision_id not in pending:
            raise ValueError("decision is not pending")
        pending = tuple(item for item in pending if item != decision_id)
        resolved = (*resolved, decision_id)
        if kind == "resolve_job":
            job = ExpectedDocumentJob.from_record(value["job"])
            if job.execution_sha256 is None:
                raise ValueError("fully execution-bound admitted job required")
            if job.job_id in {existing.job_id for existing in plan.jobs}:
                raise ValueError("job ID already admitted")
            # A later declared decision branches from its named parent. Initial
            # root decisions have no parent and may admit any host-selected job.
            declared_parent = dict(parents)[decision_id]
            if declared_parent is not None and job.source_job != declared_parent:
                raise ValueError("admitted job source differs from decision parent")
            # DocumentRunPlan enforces the 64-job cap and preceding source order.
            plan = DocumentRunPlan(plan.configuration_sha256, (*plan.jobs, job))
            job_plan = (*job_plan, (job.job_id, plan.sha256))
        elif type(value["reason"]) is not str or _REASON.fullmatch(value["reason"]) is None:
            raise ValueError("bounded no-job reason required")
    elif pending:
        raise ValueError("pending decisions must be resolved before seal")
    return AdmissionSnapshot(
        plan=plan, job_plan_sha256=job_plan, pending_decisions=pending,
        resolved_decisions=resolved, decision_parents=parents,
        sealed=kind == "seal", head_sha256=_digest(value), sequence=state.sequence + 1,
    )


def _names(path: Path) -> tuple[str, ...]:
    _checked_directory(path)
    entries = list(islice(path.iterdir(), _MAX_RECORDS + 1))
    if not 1 <= len(entries) <= _MAX_RECORDS:
        raise ValueError("bounded admission records required")
    names = tuple(sorted(entry.name for entry in entries))
    if names != tuple(f"{index:06d}.json" for index in range(len(names))):
        raise ValueError("contiguous admission records required")
    return names


def initialize_admissions(
    config: DocumentConfig, plan: DocumentRunPlan, path: Path,
    *, pending_decisions: tuple[str, ...] = (),
) -> AdmissionSnapshot:
    """Create the ledger root before any document jobs; return a head to retain."""
    path = _checked_path(config, path)
    if type(plan) is not DocumentRunPlan or type(pending_decisions) is not tuple:
        raise ValueError("closed initial plan and decision tuple required")
    _checked_directory(config.jobs_dir)
    if next(config.jobs_dir.iterdir(), None) is not None:
        raise ValueError("admission root must precede document jobs")
    root = _record("root", 0, None, plan=plan.record(),
                   pending_decisions=list(pending_decisions))
    state = _root_snapshot(config, root)
    _checked_directory(path.parent)
    os.mkdir(path, 0o700)
    _checked_directory(path)
    _save(path / "000000.json", root)
    return state


def load_admissions(
    config: DocumentConfig, path: Path, *, expected_head_sha256: str,
) -> AdmissionSnapshot:
    """Validate every record and directory inventory against an external head."""
    path = _checked_path(config, path)
    _checked_head(expected_head_sha256)
    names = _names(path)
    root = _json(_read_file(path / names[0], 65536), 65536)
    state = _root_snapshot(config, root)
    for name in names[1:]:
        value = _json(_read_file(path / name, 65536), 65536)
        state = _next_snapshot(state, value)
    if _names(path) != names:
        raise ValueError("admission directory changed during read")
    if state.head_sha256 != expected_head_sha256:
        raise ValueError("admission head differs from retained anchor")
    return state


def _append(
    config: DocumentConfig, path: Path, expected_head_sha256: str,
    kind: str, **fields: Any,
) -> AdmissionSnapshot:
    path = _checked_path(config, path)
    state = load_admissions(config, path, expected_head_sha256=expected_head_sha256)
    if state.sequence + 1 >= _MAX_RECORDS:
        raise ValueError("admission record limit reached")
    value = _record(kind, state.sequence + 1, state.head_sha256, **fields)
    updated = _next_snapshot(state, value)
    # Exclusive create/readback. A competing or partial next slot is never repaired.
    _save(path / f"{updated.sequence:06d}.json", value)
    return updated


def declare_decision(
    config: DocumentConfig, path: Path, *, expected_head_sha256: str,
    decision_id: str, parent_job: str,
) -> AdmissionSnapshot:
    """Declare a bounded pending branch after its parent job was admitted."""
    return _append(config, path, expected_head_sha256, "declare",
                   decision_id=decision_id, parent_job=parent_job)


def resolve_decision(
    config: DocumentConfig, path: Path, *, expected_head_sha256: str,
    decision_id: str, job: ExpectedDocumentJob | None = None,
    reason: str | None = None,
) -> AdmissionSnapshot:
    """Resolve a pending decision with one new job or an explicit no-job stop."""
    if (job is None) == (reason is None):
        raise ValueError("exactly one admitted job or no-job reason required")
    if job is not None:
        if type(job) is not ExpectedDocumentJob:
            raise ValueError("closed expected job required")
        return _append(config, path, expected_head_sha256, "resolve_job",
                       decision_id=decision_id, job=job.record())
    return _append(config, path, expected_head_sha256, "resolve_stop",
                   decision_id=decision_id, reason=reason)


def seal_admissions(
    config: DocumentConfig, path: Path, *, expected_head_sha256: str,
) -> AdmissionSnapshot:
    """Close new admissions only when every declared decision is resolved."""
    return _append(config, path, expected_head_sha256, "seal")
