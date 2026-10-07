"""Compare actual document jobs against a separately retained host expectation.

The host owns the plan and caller-retained digest. The document producer cannot
choose the expected set. This does not resist a compromised host, coordinated
rollback, or observe tools outside the declared document jobs directory.
"""

from __future__ import annotations

import os
import re
from itertools import islice
from pathlib import Path
from typing import Any

from agentic_security_harness import document_workflow as workflow
from agentic_security_harness._fixture_files import _checked_directory
from agentic_security_harness.document_expectations import DocumentRunPlan
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.workspace_writer import _read_file


def _checked_plan(config: workflow.DocumentConfig, plan: DocumentRunPlan) -> None:
    if type(plan) is not DocumentRunPlan or plan.configuration_sha256 != config.sha256:
        raise ValueError("plan configuration mismatch")


def save_plan(config: workflow.DocumentConfig, plan: DocumentRunPlan, path: Path) -> dict[str, Any]:
    """Create once outside the empty jobs root, before starting any planned job.

    Retain the returned digest under host control separately from producer reports.
    A digest loaded from the same untrusted record is not an independent anchor.
    """
    _checked_plan(config, plan)
    path = Path(os.path.abspath(path))
    if path.is_relative_to(config.jobs_dir):
        raise ValueError("plan must be outside document output root")
    _checked_directory(config.jobs_dir)
    if next(config.jobs_dir.iterdir(), None) is not None:
        raise ValueError("plan must precede all jobs in this workspace")
    workflow._save(path, plan.record())
    return {"state": "planned", "plan_sha256": plan.sha256, "planned_jobs": len(plan.jobs),
            "authority": "none"}


def load_plan(path: Path, *, expected_sha256: str) -> DocumentRunPlan:
    """Read a bounded plan against a digest independently retained by the host."""
    if type(expected_sha256) is not str or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None:
        raise ValueError("retained plan digest required")
    plan = DocumentRunPlan.from_record(_json(_read_file(path.absolute(), 65536), 65536))
    if plan.sha256 != expected_sha256:
        raise ValueError("plan differs from retained expectation")
    return plan


def run_planned_job(
    config: workflow.DocumentConfig, plan_path: Path, expected_plan_sha256: str,
    source_path: Path | None, task: str, job_id: str, *, execute: bool = False,
    source_job: str | None = None, requirements: DocumentRequirements | None = None,
    reviewed_source_sha256: str | None = None,
    source_restrictions: DocumentSourceRestrictions | None = None,
    recover_source: bool = False,
) -> dict[str, Any]:
    """Use the real workflow, but admit only the previously planned task/input."""
    return workflow.run_job(
        config, source_path, task, job_id, execute=execute, source_job=source_job,
        requirements=requirements, reviewed_source_sha256=reviewed_source_sha256,
        source_restrictions=source_restrictions,
        run_plan_sha256=expected_plan_sha256, run_plan_path=plan_path,
        recover_source=recover_source,
    )


def _terminal_inventory(root: Path, state: str) -> bool:
    """Use phase-specific sets, not a count chosen by the supplied summary."""
    entries = list(islice(root.iterdir(), 9))
    if len(entries) > 8:
        return False
    names = {path.name for path in entries}
    base = {"started.json", "summary.json"}
    if "session-closed.json" in names:
        base.add("session-closed.json")
    if state == "error":
        return names == base
    if state == "saved":
        base |= {"document.md", "quality.json"}
    receipts = names - base
    if not base <= names or len(receipts) != 2:
        return False
    intents = [name for name in receipts
               if re.fullmatch(r"\.ash-[a-f0-9]{32}-01-intent\.json", name)]
    return len(intents) == 1 and intents[0].replace("-intent.json", "-result.json") in receipts


def inspect_coverage(
    config: workflow.DocumentConfig, plan_path: Path, *, expected_plan_sha256: str,
) -> dict[str, Any]:
    """Read actual job evidence without executing, repairing, or replaying anything.

    Completeness means accounted terminal states, not useful/accurate documents.
    Quality and effects are returned separately; missing or interrupted work never
    disappears into a successful result just because remaining jobs look valid.
    """
    problem = {"state": "invalid", "reason": "coverage_evidence_unavailable_or_changed",
               "complete": False, "writes_performed": False, "authority": "none"}
    try:
        plan = load_plan(plan_path, expected_sha256=expected_plan_sha256)
        _checked_plan(config, plan)
        _checked_directory(config.jobs_dir)
        entries = list(islice(config.jobs_dir.iterdir(), 65))
        if len(entries) > 64:
            return {**problem, "reason": "coverage_entry_limit_exceeded"}
        expected_ids = {entry.job_id for entry in plan.jobs}
        observed_ids: set[str] = set()
        unexpected = 0
        for path in entries:
            if path.name not in expected_ids:
                unexpected += 1  # Do not echo unrecognized filesystem names.
            else:
                observed_ids.add(path.name)
        rows: list[dict[str, Any]] = []
        unresolved = 0
        for expected in plan.jobs:
            if expected.job_id not in observed_ids:
                rows.append({"job_id": expected.job_id, "state": "missing", "effect": "unknown"})
                unresolved += 1
                continue
            status = workflow.inspect_job(config, expected.job_id)
            state = status["state"]
            if state in {"saved", "denied", "error"}:
                initial = _json(_read_file(
                    config.jobs_dir / expected.job_id / "started.json", 65536,
                ), 65536)
                provenance = initial.get("input_provenance", {})
                matches = (
                    initial.get("run_plan_sha256") == plan.sha256
                    and initial.get("task_sha256") == expected.task_sha256
                    and provenance.get("source_job") == expected.source_job
                )
                if expected.source_job is None:
                    matches = (matches and initial.get("input_sha256") == expected.input_sha256
                               and initial.get("source_restrictions_sha256")
                               == expected.source_restrictions_sha256)
                if not matches:
                    state = "expectation_mismatch"
                elif not _terminal_inventory(config.jobs_dir / expected.job_id, state):
                    state = "unexpected_or_incomplete_events"
            if state not in {"saved", "denied", "error"}:
                unresolved += 1
            rows.append({
                "job_id": expected.job_id, "state": state,
                "effect": status.get("effect", "unknown_inspect_output"),
                "quality": (status.get("quality") or {}).get("status"),
            })
        complete = not unresolved and not unexpected
        return {
            "state": "complete" if complete else "incomplete", "complete": complete,
            "plan_sha256": plan.sha256, "expected_jobs": len(plan.jobs),
            "observed_jobs": len(observed_ids), "unexpected_entries": unexpected,
            "unresolved_jobs": unresolved, "jobs": rows,
            "saved_documents": sum(row["state"] == "saved" for row in rows),
            "declared_quality_checked": sum(
                row["state"] == "saved" and row.get("quality") == "checked" for row in rows
            ),
            "writes_performed": False, "authority": "none", "host_completeness_claim": False,
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return problem
