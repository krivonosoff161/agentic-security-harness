"""Real guarded jobs retain admissions across dynamically chosen host branches."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agentic_security_harness.document_admissions import (
    initialize_admissions,
    resolve_decision,
    seal_admissions,
)
from agentic_security_harness.document_dynamic import inspect_admitted_coverage, run_admitted_job
from agentic_security_harness.document_expectations import (
    DocumentRunPlan,
    ExpectedDocumentJob,
    execution_sha256,
)
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_workflow import run_job
from agentic_security_harness.workspace_writer import _canonical
from test_document_workflow import reply, setup


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _job(job_id: str, source: Path | None = None, source_job: str | None = None,
         requirements: DocumentRequirements | None = None) -> ExpectedDocumentJob:
    return ExpectedDocumentJob(
        job_id, _sha(b"Summarize"), input_sha256=_sha(source.read_bytes()) if source else None,
        source_job=source_job, execution_sha256=execution_sha256(requirements_sha256=(
            _sha(_canonical(requirements.record())) if requirements else None)),
    )


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_useful_dynamic_chain_and_pending_choice_never_disappear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, _ = setup(tmp_path, engine)
    criteria = DocumentRequirements("exact_json", expected_json={"ok": True})
    root_plan = DocumentRunPlan(config.sha256, (_job("first", source, requirements=criteria),))
    ledger = tmp_path / "host-admissions"
    state = initialize_admissions(config, root_plan, ledger, pending_decisions=("route",))
    calls = reply(monkeypatch, '{"ok":true}')
    first = run_admitted_job(config, ledger, state.head_sha256, source, "Summarize", "first",
                             execute=True, requirements=criteria)
    assert first["state"] == "saved" and len(calls) == 1
    interim = inspect_admitted_coverage(config, ledger, expected_head_sha256=state.head_sha256)
    assert interim["job_history_complete"] is True
    assert interim["complete"] is False and interim["pending_decisions"] == ["route"]
    prior = {p: p.read_bytes() for p in (config.jobs_dir / "first").iterdir()}
    state = resolve_decision(config, ledger, expected_head_sha256=state.head_sha256,
                             decision_id="route", job=_job("second", source_job="first",
                                                          requirements=criteria))
    result = run_admitted_job(config, ledger, state.head_sha256, None, "Summarize", "second",
                              source_job="first", execute=True, requirements=criteria)
    assert result["state"] == "saved" and len(calls) == 2
    assert not inspect_admitted_coverage(config, ledger,
                                         expected_head_sha256=state.head_sha256)["complete"]
    state = seal_admissions(config, ledger, expected_head_sha256=state.head_sha256)
    coverage = inspect_admitted_coverage(config, ledger, expected_head_sha256=state.head_sha256)
    assert coverage["complete"] is True and coverage["saved_documents"] == 2
    assert coverage["declared_quality_checked"] == 2 and coverage["writes_performed"] is False
    assert {p: p.read_bytes() for p in prior} == prior


def test_root_plan_with_multiple_jobs_keeps_its_original_full_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = DocumentRunPlan(config.sha256, (_job("first", source), _job("second", source)))
    ledger = tmp_path / "admissions"
    state = initialize_admissions(config, plan, ledger)
    reply(monkeypatch, "A useful document")
    for job in plan.jobs:
        assert run_admitted_job(config, ledger, state.head_sha256, source,
                                "Summarize", job.job_id, execute=True)["state"] == "saved"
    state = seal_admissions(config, ledger, expected_head_sha256=state.head_sha256)
    assert inspect_admitted_coverage(config, ledger,
                                     expected_head_sha256=state.head_sha256)["complete"]


def test_unadmitted_or_rebound_job_refuses_before_model_or_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    ledger = tmp_path / "admissions"
    plan = DocumentRunPlan(config.sha256, (_job("first", source),))
    state = initialize_admissions(config, plan, ledger)
    calls = reply(monkeypatch, "unused")
    for job, task in (("not-admitted", "Summarize"), ("first", "Changed task")):
        with pytest.raises(ValueError):
            run_admitted_job(config, ledger, state.head_sha256, source, task, job, execute=True)
    with pytest.raises(ValueError, match="execution"):
        run_admitted_job(config, ledger, state.head_sha256, source, "Summarize", "first",
                         execute=True, requirements=DocumentRequirements("exact_json",
                                                                        expected_json={}))
    assert not calls and list(config.jobs_dir.iterdir()) == []


def test_stop_decision_is_explicit_but_failed_quality_is_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    criteria = DocumentRequirements("exact_json", expected_json={"ok": True})
    plan = DocumentRunPlan(config.sha256, (_job("first", source, requirements=criteria),))
    ledger = tmp_path / "admissions"
    state = initialize_admissions(config, plan, ledger, pending_decisions=("route",))
    calls = reply(monkeypatch, '{"ok":false}')
    result = run_admitted_job(config, ledger, state.head_sha256, source, "Summarize", "first",
                              execute=True, requirements=criteria)
    assert result["quality"]["status"] == "failed"
    state = resolve_decision(config, ledger, expected_head_sha256=state.head_sha256,
                             decision_id="route", reason="failed_source_quality")
    state = seal_admissions(config, ledger, expected_head_sha256=state.head_sha256)
    coverage = inspect_admitted_coverage(config, ledger, expected_head_sha256=state.head_sha256)
    assert coverage["complete"] and coverage["declared_quality_checked"] == 0
    assert len(calls) == 1


def test_lost_head_and_unplanned_effect_do_not_produce_complete_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = DocumentRunPlan(config.sha256, (_job("first", source),))
    ledger = tmp_path / "admissions"
    state = initialize_admissions(config, plan, ledger)
    old_head = state.head_sha256
    state = seal_admissions(config, ledger, expected_head_sha256=old_head)
    stale = inspect_admitted_coverage(config, ledger, expected_head_sha256=old_head)
    assert stale["state"] == "invalid"
    reply(monkeypatch, "Generated draft")
    run_job(config, source, "Summarize", "unexpected", execute=True)
    coverage = inspect_admitted_coverage(config, ledger, expected_head_sha256=state.head_sha256)
    assert not coverage["complete"] and coverage["unexpected_entries"] == 1


def test_object_plan_requires_exact_anchor_and_exclusive_path_choice(tmp_path: Path) -> None:
    config, source, _ = setup(tmp_path)
    plan = DocumentRunPlan(config.sha256, (_job("first", source),))
    for kwargs in (
        {"run_plan": plan},
        {"run_plan": plan, "run_plan_sha256": "0" * 64},
        {"run_plan": plan, "run_plan_sha256": plan.sha256, "run_plan_path": tmp_path / "p"},
        {"supervisor_nonce": "not-a-nonce"},
    ):
        with pytest.raises(ValueError):
            run_job(config, source, "Summarize", "first", **kwargs)
    assert list(config.jobs_dir.iterdir()) == []
