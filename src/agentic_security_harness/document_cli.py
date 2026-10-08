"""Setup, preview, execution and restart inspection for a document job."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agentic_security_harness import document_workflow as workflow
from agentic_security_harness._fixture_files import _checked_directory
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.workspace_writer import _read_file

COMMANDS = (
    "document-init", "document-check", "document-run", "document-status",
    "document-plan", "document-coverage", "document-admissions",
)


def add_commands(sub: Any) -> None:
    for command in COMMANDS:
        parser = sub.add_parser(
            command,
            help={
                "document-init": "create a new document workspace with starter configuration",
                "document-check": "inspect configuration and optionally the existing local model",
                "document-run": "preview or execute one create-only document job",
                "document-status": "inspect an existing job without replaying it",
                "document-plan": "preview or save a finite host-owned document job plan",
                "document-coverage": "compare jobs with an independently retained plan digest",
                "document-admissions": "preview or record host-owned dynamic job decisions",
            }[command],
        )
        parser.add_argument(
            "--json", action="store_true", help="content-free machine-readable result"
        )
        if command == "document-init":
            parser.add_argument(
                "--dir", type=Path, required=True, help="new directory; parent exists"
            )
            parser.add_argument("--model", required=True, help="exact existing local Ollama model")
            parser.add_argument("--engine", choices=("native", "pydantic-ai"), default="native")
        else:
            parser.add_argument("--config", type=Path, required=True)
        if command == "document-check":
            parser.add_argument(
                "--check-model",
                action="store_true",
                help="bounded loopback metadata check; no generation",
            )
        if command == "document-plan":
            parser.add_argument("--spec", type=Path, required=True,
                                help="host-owned task specification; paths relative to this file")
            parser.add_argument("--out", type=Path, required=True,
                                help="new plan file outside the empty jobs directory")
            parser.add_argument("--execute", action="store_true",
                                help="save plan only; does not call a model or run jobs")
        if command in {"document-run", "document-coverage"}:
            selection = parser.add_mutually_exclusive_group()
            selection.add_argument("--plan", type=Path, help="previously saved fixed host plan")
            selection.add_argument("--admissions", type=Path,
                                   help="host-owned create-only admission ledger")
            parser.add_argument("--plan-sha256", help="separately retained fixed-plan digest")
            parser.add_argument("--admissions-sha256",
                                help="separately retained current admission head")
        if command == "document-admissions":
            parser.add_argument("--action", choices=("init", "declare", "resolve-job",
                                                     "resolve-stop", "seal", "status"),
                                required=True)
            parser.add_argument("--ledger", type=Path, required=True,
                                help="new or existing ledger outside the jobs directory")
            parser.add_argument("--plan", type=Path,
                                help="existing fixed plan; required for init")
            parser.add_argument("--plan-sha256",
                                help="separately retained plan digest; required for init")
            parser.add_argument("--head-sha256",
                                help="separately retained current ledger head after init")
            parser.add_argument("--pending-decision", action="append", default=[],
                                help="initial root choice; repeat only on init")
            parser.add_argument("--decision", help="bounded host decision ID")
            parser.add_argument("--parent-job",
                                help="required for declare; initial root choices use init")
            parser.add_argument("--job-record", type=Path,
                                help="closed expected-job JSON for resolve-job")
            parser.add_argument("--reason", help="bounded no-job reason for resolve-stop")
            parser.add_argument("--execute", action="store_true",
                                help="append exactly one host record; status is always read-only")
        if command in {"document-run", "document-status"}:
            parser.add_argument(
                "--job", required=True, help="unique lowercase job ID; never resumed"
            )
        if command == "document-status":
            parser.add_argument("--inspect-recovery", action="store_true",
                                help="read-only assessment of fenced existing document bytes")
        if command == "document-run":
            source = parser.add_mutually_exclusive_group(required=True)
            source.add_argument("--input", type=Path, help="host-selected UTF-8 file")
            source.add_argument(
                "--from-job", help="verified saved job in this workspace, reused as untrusted data"
            )
            source.add_argument("--spec", type=Path,
                                help="job arguments from host spec; requires plan and digest")
            parser.add_argument(
                "--reviewed-source-sha256",
                help="host-reviewed SHA-256 of exact prior document bytes; requires --from-job",
            )
            parser.add_argument(
                "--recover-source", action="store_true",
                help="reuse fenced existing bytes after source interruption; requires exact review",
            )
            parser.add_argument(
                "--source-restrictions", type=Path,
                help="host-bound restrictions JSON for --input; --from-job inherits its binding",
            )
            parser.add_argument(
                "--requirements", type=Path,
                help="host-owned JSON output requirements; does not grant action authority",
            )
            parser.add_argument("--task", help="host-selected instruction; required without --spec")
            parser.add_argument(
                "--execute",
                action="store_true",
                help="reserve job, call local model once, submit to guarded writer",
            )
            parser.add_argument("--supervise-timeout", type=float,
                                help="run one owned child with bounded timeout in seconds")


def _run_job(config: workflow.DocumentConfig, args: argparse.Namespace) -> dict[str, Any]:
    fixed = args.plan is not None or args.plan_sha256 is not None
    dynamic = args.admissions is not None or args.admissions_sha256 is not None
    if (fixed and dynamic
            or (args.plan is None) != (args.plan_sha256 is None)
            or (args.admissions is None) != (args.admissions_sha256 is None)):
        raise ValueError("select one complete fixed plan or admission head")
    if args.spec is not None:
        from agentic_security_harness.document_coverage import load_plan
        from agentic_security_harness.document_plan import job_arguments

        if args.plan is None or dynamic or any(value is not None for value in (
            args.task, args.requirements, args.source_restrictions,
        )) or args.recover_source:
            raise ValueError("spec requires retained plan and forbids job argument overrides")
        plan = load_plan(args.plan, expected_sha256=args.plan_sha256)
        if (plan.configuration_sha256 != config.sha256
                or plan.for_job(args.job).execution_sha256 is None):
            raise ValueError("spec mode requires matching plan with execution criteria")
        kwargs = job_arguments(config, args.spec, args.job)
        # Review acknowledges actual bytes after generation, never predicted bytes
        # at plan creation. The existing source reader verifies the supplied digest.
        kwargs["reviewed_source_sha256"] = args.reviewed_source_sha256
    else:
        if args.task is None:
            raise ValueError("task required for direct document job")
        kwargs = {
            "source_path": args.input, "task": args.task, "source_job": args.from_job,
            "requirements": (
                DocumentRequirements.from_record(_json(_read_file(args.requirements, 8192), 8192))
                if args.requirements is not None else None
            ),
            "reviewed_source_sha256": args.reviewed_source_sha256,
            "recover_source": args.recover_source,
            "source_restrictions": (
                _source_restrictions(args.source_restrictions)
                if args.source_restrictions is not None else None
            ),
        }
    if dynamic:
        from agentic_security_harness.document_dynamic import run_admitted_job

        extra = ({"timeout_seconds": args.supervise_timeout}
                 if args.supervise_timeout is not None else {})
        return run_admitted_job(
            config, args.admissions, args.admissions_sha256,
            job_id=args.job, execute=args.execute, **kwargs, **extra,
        )
    if args.supervise_timeout is not None:
        from agentic_security_harness.document_supervisor import run_supervised_job

        return run_supervised_job(
            config, job_id=args.job, execute=args.execute,
            timeout_seconds=args.supervise_timeout,
            run_plan_path=args.plan, run_plan_sha256=args.plan_sha256, **kwargs,
        )
    return workflow.run_job(config, job_id=args.job, execute=args.execute,
                            run_plan_path=args.plan, run_plan_sha256=args.plan_sha256,
                            **kwargs)


def _source_restrictions(
    path: Path,
) -> DocumentSourceRestrictions | DocumentMultiSourceRestrictions:
    from agentic_security_harness.document_restrictions import parse_source_restrictions

    return parse_source_restrictions(_json(_read_file(path, 8192), 8192))


def _admission_summary(state: Any, label: str) -> dict[str, Any]:
    return {
        "state": label, "reason": "host_admission_record" if label == "admissions_updated"
        else "admission_preview_only" if label == "preview" else "admissions_inspected",
        "admission_head_sha256": state.head_sha256,
        "plan_sha256": state.plan.sha256,
        "admitted_jobs": len(state.plan.jobs),
        "pending_decisions": list(state.pending_decisions),
        "sealed": state.sealed,
        "sequence": state.sequence,
        "writes_performed": label == "admissions_updated",
        "authority": "none",
        "next_step": "retain_head_separately_then_use_next_admission_or_document_run",
    }


def _admissions(config: workflow.DocumentConfig, args: argparse.Namespace) -> dict[str, Any]:
    from agentic_security_harness import document_admissions as admission
    from agentic_security_harness.document_coverage import load_plan
    from agentic_security_harness.document_expectations import ExpectedDocumentJob

    action = args.action
    if action == "init":
        if (args.plan is None or args.plan_sha256 is None or args.head_sha256 is not None
                or any(value is not None for value in (
                    args.decision, args.parent_job, args.job_record, args.reason,
                ))):
            raise ValueError("init requires only fixed plan, retained digest and root choices")
        plan = load_plan(args.plan, expected_sha256=args.plan_sha256)
        if args.execute:
            state = admission.initialize_admissions(
                config, plan, args.ledger, pending_decisions=tuple(args.pending_decision),
            )
            return _admission_summary(state, "admissions_updated")
        path = admission._checked_path(config, args.ledger)
        _checked_directory(path.parent)
        _checked_directory(config.jobs_dir)
        if path.exists() or path.is_symlink() or any(config.jobs_dir.iterdir()):
            raise ValueError("new ledger and empty jobs directory required")
        root = admission._record("root", 0, None, plan=plan.record(),
                                 pending_decisions=args.pending_decision)
        state = admission._root_snapshot(config, root)
        return {**_admission_summary(state, "preview"),
                "admission_head_sha256": None,
                "proposed_head_sha256": state.head_sha256}
    if (args.head_sha256 is None or args.plan is not None or args.plan_sha256 is not None
            or args.pending_decision):
        raise ValueError("current retained admission head required after init")
    state = admission.load_admissions(config, args.ledger,
                                      expected_head_sha256=args.head_sha256)
    if action == "status":
        if args.execute or any(value is not None for value in (
            args.decision, args.parent_job, args.job_record, args.reason,
        )):
            raise ValueError("status is read-only and has no mutation arguments")
        return _admission_summary(state, "admissions_status")
    if action == "declare":
        if (args.decision is None or args.parent_job is None
                or args.job_record is not None or args.reason is not None):
            raise ValueError("declare requires decision and parent job")
        kind, fields = "declare", {"decision_id": args.decision,
                                   "parent_job": args.parent_job}
    elif action == "resolve-job":
        if (args.decision is None or args.job_record is None
                or args.parent_job is not None or args.reason is not None):
            raise ValueError("resolve-job requires decision and closed job record")
        job = ExpectedDocumentJob.from_record(
            _json(_read_file(args.job_record, 16384), 16384),
        )
        kind, fields = "resolve_job", {"decision_id": args.decision,
                                       "job": job.record()}
    elif action == "resolve-stop":
        if (args.decision is None or args.reason is None
                or args.parent_job is not None or args.job_record is not None):
            raise ValueError("resolve-stop requires decision and bounded reason")
        kind, fields = "resolve_stop", {"decision_id": args.decision,
                                        "reason": args.reason}
    else:
        if any(value is not None for value in (
            args.decision, args.parent_job, args.job_record, args.reason,
        )):
            raise ValueError("seal takes only current admission head")
        kind, fields = "seal", {}
    candidate = admission._record(kind, state.sequence + 1, state.head_sha256, **fields)
    next_state = admission._next_snapshot(state, candidate)
    if not args.execute:
        return _admission_summary(state, "preview")
    if kind == "declare":
        updated = admission.declare_decision(
            config, args.ledger, expected_head_sha256=state.head_sha256,
            decision_id=fields["decision_id"], parent_job=fields["parent_job"],
        )
    elif kind == "resolve_job":
        updated = admission.resolve_decision(
            config, args.ledger, expected_head_sha256=state.head_sha256,
            decision_id=fields["decision_id"], job=job,
        )
    elif kind == "resolve_stop":
        updated = admission.resolve_decision(
            config, args.ledger, expected_head_sha256=state.head_sha256,
            decision_id=fields["decision_id"], reason=fields["reason"],
        )
    else:
        updated = admission.seal_admissions(
            config, args.ledger, expected_head_sha256=state.head_sha256,
        )
    if updated != next_state:
        raise ValueError("admission changed before append")
    return _admission_summary(updated, "admissions_updated")


def _human_report(result: dict[str, Any]) -> str:
    if "plan_sha256" not in result and "complete" not in result:
        return workflow.human_report(result)
    lines = [workflow.human_report(result)]
    if "admission_head_sha256" in result:
        if result["admission_head_sha256"] is None:
            lines.append("Admission head: not persisted by this preview")
        else:
            lines.append(f"Admission head SHA-256: {result['admission_head_sha256']}")
            lines.append("Retain this head separately under host control.")
        if "admitted_jobs" in result:
            lines.append(f"Admitted jobs: {result['admitted_jobs']}; "
                         f"pending decisions: {len(result['pending_decisions'])}; "
                         f"sealed: {result['sealed']}")
        elif "admissions_sealed" in result:
            lines.append(f"Admissions sealed: {result['admissions_sealed']}; "
                         f"pending decisions: {len(result['pending_decisions'])}")
    if "plan_sha256" in result:
        lines.append(f"Plan SHA-256: {result['plan_sha256']}")
        if "admission_head_sha256" not in result:
            lines.append("Retain this digest separately under host control, not in model output.")
        else:
            lines.append("This plan digest is derived from admissions; retain the ledger head.")
    if "planned_jobs" in result:
        lines.append(f"Planned jobs: {result['planned_jobs']}")
    if "complete" in result:
        lines.append(f"History complete: {result['complete']} (not document correctness)")
        for job in result.get("jobs", []):
            lines.append(f"Job {job['job_id']}: {job['state']}; "
                         f"quality={job.get('quality') or 'not_checked'}")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    phase = "setup" if args.command == "document-init" else "configuration"
    try:
        if args.command == "document-init":
            result = workflow.initialize(args.dir, args.model, args.engine)
        else:
            config = workflow.DocumentConfig.load(args.config)
            if args.command == "document-admissions":
                phase = "admissions"
                result = _admissions(config, args)
            elif args.command == "document-plan":
                from agentic_security_harness.document_plan import prepare_plan

                phase = "plan"
                result = prepare_plan(config, args.spec, args.out, execute=args.execute)
            elif args.command == "document-coverage":
                phase = "coverage"
                fixed = args.plan is not None or args.plan_sha256 is not None
                dynamic = args.admissions is not None or args.admissions_sha256 is not None
                if (fixed == dynamic
                        or (args.plan is None) != (args.plan_sha256 is None)
                        or (args.admissions is None) != (args.admissions_sha256 is None)):
                    raise ValueError("select one complete fixed plan or admission head")
                if dynamic:
                    from agentic_security_harness.document_dynamic import inspect_admitted_coverage

                    result = inspect_admitted_coverage(
                        config, args.admissions, expected_head_sha256=args.admissions_sha256,
                    )
                else:
                    from agentic_security_harness.document_coverage import inspect_coverage

                    result = inspect_coverage(
                        config, args.plan, expected_plan_sha256=args.plan_sha256,
                    )
            elif args.command == "document-check":
                result = workflow.check(config, check_model=args.check_model)
            elif args.command == "document-status":
                if args.inspect_recovery:
                    from agentic_security_harness.document_recovery import inspect_recovery

                    result = inspect_recovery(config, args.job)
                else:
                    result = workflow.inspect_job(config, args.job)
            else:
                phase = "input_or_job"
                result = _run_job(config, args)
    except workflow.SourceQualityBlocked:
        result = {
            "state": "error", "job_id": args.job, "effect": "none",
            "reason": "source_quality_failed", "model": {"transport_attempts": 0},
            "next_step": "review_failed_document_requirements_do_not_chain",
        }
    except FileExistsError:
        result = {
            "state": "error",
            "reason": "directory_or_job_already_exists",
            "next_step": "inspect_existing_state_or_choose_new_name_no_overwrite",
        }
    except PermissionError:
        result = {
            "state": "error",
            "reason": f"{phase}_permission_denied",
            "next_step": "choose_a_writable_owned_directory_do_not_retry_existing_job",
        }
    except FileNotFoundError:
        result = {
            "state": "error",
            "reason": f"{phase}_path_not_found",
            "next_step": "check_config_input_and_existing_parent_directories",
        }
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        result = {
            "state": "error",
            "reason": f"{phase}_unavailable_or_invalid",
            "next_step": "check_config_limits_utf8_and_job_id_inspect_partial_state",
        }
    print(json.dumps(result, sort_keys=True) if args.json else _human_report(result))
    if result.get("state") == "saved" and (result.get("quality") or {}).get("status") == "failed":
        return 2  # File saved, declared requirements failed; never silently treat as ready.
    return 0 if result.get("state") in {
        "initialized", "ready", "preview", "saved", "recoverable_data", "already_complete",
        "planned", "complete", "admissions_updated", "admissions_status",
    } else 1
