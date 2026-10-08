"""Content-free dynamic admissions CLI, with explicit mutation and exact head."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness.document_coverage import save_plan
from agentic_security_harness.document_expectations import (
    DocumentRunPlan,
    ExpectedDocumentJob,
    execution_sha256,
)
from test_document_workflow import reply, setup


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _call(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    code = cli.main([*argv, "--json"])
    return code, json.loads(capsys.readouterr().out)


def _root_plan(config: Any, source: Path) -> DocumentRunPlan:
    first = ExpectedDocumentJob(
        "first", _sha(b"Summarize"), input_sha256=_sha(source.read_bytes()),
        execution_sha256=execution_sha256(requirements_sha256=None),
    )
    return DocumentRunPlan(config.sha256, (first,))


def test_admission_previews_stale_head_and_dynamic_real_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    plan = _root_plan(config, source)
    plan_path = tmp_path / "plan.json"
    save_plan(config, plan, plan_path)
    ledger = tmp_path / "admissions"
    common = ("document-admissions", "--config", str(config_path),
              "--ledger", str(ledger))
    init = (*common, "--action", "init", "--plan", str(plan_path),
            "--plan-sha256", plan.sha256, "--pending-decision", "route")
    code, preview = _call(capsys, *init)
    assert code == 0 and preview["state"] == "preview" and not ledger.exists()
    code, state = _call(capsys, *init, "--execute")
    assert code == 0 and state["state"] == "admissions_updated"
    root_head = state["admission_head_sha256"]
    assert state["pending_decisions"] == ["route"] and not list(config.jobs_dir.iterdir())
    code, rejected = _call(
        capsys, "document-run", "--config", str(config_path),
        "--admissions", str(ledger), "--admissions-sha256", root_head,
        "--spec", str(tmp_path / "unused-spec.json"), "--job", "first", "--execute",
    )
    assert code == 1 and rejected["state"] == "error"
    assert not list(config.jobs_dir.iterdir())

    run = ("document-run", "--config", str(config_path), "--admissions", str(ledger),
           "--admissions-sha256", root_head, "--input", str(source),
           "--task", "Summarize", "--job", "first")
    calls = reply(monkeypatch, "A concise public summary.")
    code, first_preview = _call(capsys, *run)
    assert code == 0 and first_preview["state"] == "preview"
    assert not calls and not list(config.jobs_dir.iterdir())
    code, first = _call(capsys, *run, "--execute")
    assert code == 0 and first["state"] == "saved" and len(calls) == 1
    reviewed = _sha((config.jobs_dir / "first" / "document.md").read_bytes())

    second = ExpectedDocumentJob(
        "second", _sha(b"Summarize"), source_job="first",
        execution_sha256=execution_sha256(requirements_sha256=None),
    )
    job_record = tmp_path / "second-job.json"
    job_record.write_text(json.dumps(second.record()), encoding="utf-8")
    resolve = (*common, "--action", "resolve-job", "--head-sha256", root_head,
               "--decision", "route", "--job-record", str(job_record))
    before = {path.name: path.read_bytes() for path in ledger.iterdir()}
    code, pending = _call(capsys, *resolve)
    assert code == 0 and pending["state"] == "preview"
    assert {path.name: path.read_bytes() for path in ledger.iterdir()} == before
    code, state = _call(capsys, *resolve, "--execute")
    assert code == 0 and state["pending_decisions"] == []
    next_head = state["admission_head_sha256"]
    code, stale = _call(capsys, *common, "--action", "status", "--head-sha256", root_head)
    assert code == 1 and stale["state"] == "error"
    code, coverage = _call(capsys, "document-coverage", "--config", str(config_path),
                           "--admissions", str(ledger), "--admissions-sha256", next_head)
    assert code == 1 and coverage["complete"] is False
    second_run = ("document-run", "--config", str(config_path),
                  "--admissions", str(ledger), "--admissions-sha256", next_head,
                  "--from-job", "first", "--reviewed-source-sha256", reviewed,
                  "--task", "Summarize", "--job", "second")
    code, saved = _call(capsys, *second_run, "--execute")
    assert code == 0 and saved["state"] == "saved" and len(calls) == 2
    seal = (*common, "--action", "seal", "--head-sha256", next_head)
    count = len(list(ledger.iterdir()))
    code, preview = _call(capsys, *seal)
    assert code == 0 and preview["state"] == "preview" and len(list(ledger.iterdir())) == count
    code, state = _call(capsys, *seal, "--execute")
    assert code == 0 and state["sealed"] is True
    code, coverage = _call(capsys, "document-coverage", "--config", str(config_path),
                           "--admissions", str(ledger),
                           "--admissions-sha256", state["admission_head_sha256"])
    assert code == 0 and coverage["complete"] is True
    assert coverage["saved_documents"] == 2
    code = cli.main(["document-coverage", "--config", str(config_path),
                     "--admissions", str(ledger),
                     "--admissions-sha256", state["admission_head_sha256"]])
    human = capsys.readouterr().out
    assert code == 0 and "History complete: True" in human
    assert "Admissions sealed: True" in human


def test_declare_requires_parent_and_supervisor_preview_never_spawns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    plan = _root_plan(config, source)
    plan_path = tmp_path / "plan.json"
    save_plan(config, plan, plan_path)
    ledger = tmp_path / "admissions"
    _, state = _call(capsys, "document-admissions", "--config", str(config_path),
                     "--ledger", str(ledger), "--action", "init", "--plan", str(plan_path),
                     "--plan-sha256", plan.sha256, "--execute")
    common = ("document-admissions", "--config", str(config_path),
              "--ledger", str(ledger), "--head-sha256", state["admission_head_sha256"])
    code, refused = _call(capsys, *common, "--action", "declare", "--decision", "later",
                          "--execute")
    assert code == 1 and refused["state"] == "error"
    assert len(list(ledger.iterdir())) == 1
    code, preview = _call(capsys, *common, "--action", "declare", "--decision", "later",
                          "--parent-job", "first")
    assert code == 0 and preview["state"] == "preview"
    assert len(list(ledger.iterdir())) == 1

    from agentic_security_harness import document_supervisor

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("preview spawned a worker")

    monkeypatch.setattr(document_supervisor.multiprocessing, "get_context", forbidden)
    code, preview = _call(capsys, "document-run", "--config", str(config_path),
                          "--input", str(source), "--task", "Summarize", "--job", "first",
                          "--supervise-timeout", "1.5")
    assert code == 0 and preview["state"] == "preview"
    assert not list(config.jobs_dir.iterdir())


def test_declared_stop_and_seal_do_not_hide_missing_job(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    plan = _root_plan(config, source)
    plan_path = tmp_path / "plan.json"
    save_plan(config, plan, plan_path)
    ledger = tmp_path / "admissions"
    common = ("document-admissions", "--config", str(config_path), "--ledger", str(ledger))
    _, state = _call(capsys, *common, "--action", "init", "--plan", str(plan_path),
                     "--plan-sha256", plan.sha256, "--execute")
    _, state = _call(capsys, *common, "--action", "declare", "--decision", "route",
                     "--parent-job", "first", "--head-sha256",
                     state["admission_head_sha256"], "--execute")
    stop = (*common, "--action", "resolve-stop", "--decision", "route",
            "--reason", "no_further_work", "--head-sha256", state["admission_head_sha256"])
    before = len(list(ledger.iterdir()))
    code, preview = _call(capsys, *stop)
    assert code == 0 and preview["state"] == "preview"
    assert len(list(ledger.iterdir())) == before
    _, state = _call(capsys, *stop, "--execute")
    _, state = _call(capsys, *common, "--action", "seal", "--head-sha256",
                     state["admission_head_sha256"], "--execute")
    code, coverage = _call(capsys, "document-coverage", "--config", str(config_path),
                           "--admissions", str(ledger),
                           "--admissions-sha256", state["admission_head_sha256"])
    assert code == 1 and coverage["complete"] is False
    assert coverage["unresolved_jobs"] == 1 and coverage["pending_decisions"] == []
