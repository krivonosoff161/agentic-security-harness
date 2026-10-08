"""Setup, preview, execution and restart inspection for a document job."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agentic_security_harness import document_workflow as workflow
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.ollama_quarantine_adapter import _json
from agentic_security_harness.workspace_writer import _read_file

COMMANDS = (
    "document-init", "document-check", "document-run", "document-status",
    "document-plan", "document-coverage",
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
            parser.add_argument("--plan", type=Path, required=command == "document-coverage",
                                help="previously saved host plan")
            parser.add_argument("--plan-sha256", required=command == "document-coverage",
                                help="plan digest retained separately by the host")
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


def _run_job(config: workflow.DocumentConfig, args: argparse.Namespace) -> dict[str, Any]:
    if (args.plan is None) != (args.plan_sha256 is None):
        raise ValueError("plan and separately retained digest are required together")
    if args.spec is not None:
        from agentic_security_harness.document_coverage import load_plan
        from agentic_security_harness.document_plan import job_arguments

        if args.plan is None or any(value is not None for value in (
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
                DocumentSourceRestrictions.from_record(
                    _json(_read_file(args.source_restrictions, 8192), 8192)
                ) if args.source_restrictions is not None else None
            ),
        }
    return workflow.run_job(
        config, job_id=args.job, execute=args.execute, run_plan_path=args.plan,
        run_plan_sha256=args.plan_sha256, **kwargs,
    )


def _human_report(result: dict[str, Any]) -> str:
    if "plan_sha256" not in result and "complete" not in result:
        return workflow.human_report(result)
    lines = [workflow.human_report(result)]
    if "plan_sha256" in result:
        lines.append(f"Plan SHA-256: {result['plan_sha256']}")
        lines.append("Retain this digest separately under host control, not in model output.")
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
            if args.command == "document-plan":
                from agentic_security_harness.document_plan import prepare_plan

                phase = "plan"
                result = prepare_plan(config, args.spec, args.out, execute=args.execute)
            elif args.command == "document-coverage":
                from agentic_security_harness.document_coverage import inspect_coverage

                phase = "coverage"
                result = inspect_coverage(config, args.plan, expected_plan_sha256=args.plan_sha256)
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
        "planned", "complete",
    } else 1
