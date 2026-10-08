"""Execute and account host-admitted branches through the existing document writer.

The host retains the current ledger head separately. A ledger is not a sandbox,
an external rollback witness, or a model-selected source of execution authority.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentic_security_harness.document_admissions import AdmissionSnapshot, load_admissions
from agentic_security_harness.document_coverage import _inspect_plan
from agentic_security_harness.document_expectations import DocumentRunPlan
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.document_supervisor import run_supervised_job
from agentic_security_harness.document_workflow import DocumentConfig, run_job


def _admitting_plan(snapshot: AdmissionSnapshot, job_id: str) -> DocumentRunPlan:
    digest = snapshot.plan_sha256_for(job_id)
    # Root jobs share the entire original root plan, not their individual prefix.
    for count in range(1, len(snapshot.plan.jobs) + 1):
        prefix = DocumentRunPlan(snapshot.plan.configuration_sha256, snapshot.plan.jobs[:count])
        if prefix.sha256 == digest:
            prefix.for_job(job_id)
            return prefix
    raise ValueError("admitting plan is not a retained prefix")


def run_admitted_job(
    config: DocumentConfig, ledger_path: Path, expected_head_sha256: str,
    source_path: Path | None, task: str, job_id: str, *, execute: bool = False,
    source_job: str | None = None, requirements: DocumentRequirements | None = None,
    reviewed_source_sha256: str | None = None,
    source_restrictions: DocumentSourceRestrictions | DocumentMultiSourceRestrictions | None = None,
    recover_source: bool = False,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Require pre-existing host admission before calling the real job lifecycle."""
    snapshot = load_admissions(config, ledger_path, expected_head_sha256=expected_head_sha256)
    plan = _admitting_plan(snapshot, job_id)
    kwargs: dict[str, Any] = {
        "execute": execute, "source_job": source_job, "requirements": requirements,
        "reviewed_source_sha256": reviewed_source_sha256,
        "source_restrictions": source_restrictions, "recover_source": recover_source,
        "run_plan": plan, "run_plan_sha256": plan.sha256,
    }
    if timeout_seconds is not None:
        return run_supervised_job(
            config, source_path, task, job_id, timeout_seconds=timeout_seconds, **kwargs,
        )
    return run_job(config, source_path, task, job_id, **kwargs)


def inspect_admitted_coverage(
    config: DocumentConfig, ledger_path: Path, *, expected_head_sha256: str,
) -> dict[str, Any]:
    """Account terminal jobs AND unfinished decisions without effects or repair."""
    invalid = {"state": "invalid", "complete": False, "writes_performed": False,
               "authority": "none", "host_completeness_claim": False,
               "reason": "admission_or_job_evidence_unavailable_or_changed"}
    try:
        snapshot = load_admissions(config, ledger_path, expected_head_sha256=expected_head_sha256)
        coverage = _inspect_plan(config, snapshot.plan,
                                 job_plan_sha256=dict(snapshot.job_plan_sha256))
        # A concurrent append must not be hidden by the earlier snapshot.
        load_admissions(config, ledger_path, expected_head_sha256=expected_head_sha256)
        if coverage["state"] == "invalid":
            return invalid
        complete = (coverage["complete"] and snapshot.sealed
                    and not snapshot.pending_decisions)
        return {
            **coverage, "state": "complete" if complete else "incomplete",
            "complete": complete, "job_history_complete": coverage["complete"],
            "admission_head_sha256": snapshot.head_sha256,
            "admissions_sealed": snapshot.sealed,
            "pending_decisions": list(snapshot.pending_decisions),
            "resolved_decisions": list(snapshot.resolved_decisions),
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return invalid
