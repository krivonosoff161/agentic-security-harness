"""Planned versus observed coverage uses actual guarded jobs, not model prose."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import document_coverage as coverage
from agentic_security_harness import document_workflow as doc
from agentic_security_harness import workspace_writer as writer
from agentic_security_harness.document_expectations import DocumentRunPlan, ExpectedDocumentJob
from agentic_security_harness.document_quality import DocumentRequirements
from test_document_workflow import reply, setup


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def plan_for(config: doc.DocumentConfig, source: Path, *, chain: bool = False) -> DocumentRunPlan:
    return DocumentRunPlan(config.sha256, (
        ExpectedDocumentJob("first", digest(b"Summarize"),
                            input_sha256=digest(source.read_bytes())),
        ExpectedDocumentJob("second", digest(b"Summarize"), **(
            {"source_job": "first"} if chain else {"input_sha256": digest(source.read_bytes())}
        )),
    ))


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
@pytest.mark.parametrize("chain", [False, True])
def test_real_planned_jobs_missing_then_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str, chain: bool,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, _ = setup(tmp_path, engine)
    plan = plan_for(config, source, chain=chain)
    path = tmp_path / "host-plan.json"
    saved = coverage.save_plan(config, plan, path)
    assert saved["plan_sha256"] == plan.sha256
    assert coverage.load_plan(path, expected_sha256=plan.sha256) == plan
    initial = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert not initial["complete"] and initial["unresolved_jobs"] == 2
    calls = reply(monkeypatch, '{"ok":true}')
    spec = DocumentRequirements("exact_json", expected_json={"ok": True})
    first = coverage.run_planned_job(config, path, plan.sha256, source, "Summarize", "first",
                                     execute=True, requirements=spec)
    assert first["state"] == "saved"
    interim = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert interim["state"] == "incomplete" and interim["saved_documents"] == 1
    assert interim["jobs"][1]["state"] == "missing"
    second = coverage.run_planned_job(
        config, path, plan.sha256, None if chain else source, "Summarize", "second",
        source_job="first" if chain else None, execute=True, requirements=spec,
    )
    assert second["state"] == "saved" and len(calls) == 2
    before = {p: p.read_bytes() for p in config.jobs_dir.rglob("*") if p.is_file()}
    final = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert final["complete"] and final["saved_documents"] == 2
    assert final["declared_quality_checked"] == 2
    assert final["writes_performed"] is False and final["authority"] == "none"
    assert before == {p: p.read_bytes() for p in before}


@pytest.mark.parametrize("change", ["task", "source", "job", "restriction", "parent"])
def test_admission_mismatch_has_no_call_or_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = plan_for(config, source)
    path = tmp_path / "host-plan.json"
    coverage.save_plan(config, plan, path)
    calls = reply(monkeypatch)
    extras: dict[str, Any] = {}
    if change == "source":
        source.write_bytes(b"changed source bytes")
    if change == "restriction":
        from test_document_source_restrictions import bind
        extras["source_restrictions"] = bind(source)
    if change == "parent":
        extras["source_job"] = "first"
    with pytest.raises(ValueError):
        coverage.run_planned_job(
            config, path, plan.sha256, source, "Changed" if change == "task" else "Summarize",
            "third" if change == "job" else "first", execute=True, **extras,
        )
    assert not calls and list(config.jobs_dir.iterdir()) == []


def test_refuses_posthoc_or_output_owned_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = plan_for(config, source)
    with pytest.raises(ValueError, match="outside"):
        coverage.save_plan(config, plan, config.jobs_dir / "plan.json")
    reply(monkeypatch)
    doc.run_job(config, source, "Summarize", "first", execute=True)
    with pytest.raises(ValueError, match="precede"):
        coverage.save_plan(config, plan, tmp_path / "late-plan.json")


@pytest.mark.parametrize("change", ["missing_result", "missing_start", "task", "plan_marker",
                                    "extra_intent", "relabel_error", "duplicate_receipt"])
def test_missing_or_changed_event_is_not_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = DocumentRunPlan(config.sha256, (plan_for(config, source).jobs[0],))
    path = tmp_path / "plan.json"
    coverage.save_plan(config, plan, path)
    reply(monkeypatch)
    result = coverage.run_planned_job(config, path, plan.sha256, source, "Summarize", "first",
                                      execute=True)
    assert result["state"] == "saved"
    root = config.jobs_dir / "first"
    if change == "missing_result":
        (root / result["decision"]["receipt"]).unlink()
    elif change == "missing_start":
        (root / "started.json").unlink()
    elif change in {"task", "plan_marker", "relabel_error"}:
        for name in ("started.json", "summary.json"):
            file = root / name
            value = json.loads(file.read_text())
            if change == "task":
                value["task_sha256"] = "0" * 64
            elif change == "plan_marker":
                value.pop("run_plan_sha256")
            elif name == "summary.json":
                value.update(state="error", reason="no_proposal", effect="none", decision=None)
            file.write_text(json.dumps(value), encoding="utf-8")
        if change == "relabel_error":
            # Included summary cannot erase the existing intent/receipt branch.
            (root / "document.md").unlink()
    elif change == "extra_intent":
        (root / (".ash-" + "a" * 32 + "-01-intent.json")).write_text("{}")
    else:
        receipt = root / result["decision"]["receipt"]
        receipt.with_name(receipt.name.replace("-01-", "-02-")).write_bytes(receipt.read_bytes())
    observed = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert not observed["complete"] and observed["unresolved_jobs"] == 1
    assert observed["saved_documents"] == 0


def test_unplanned_job_and_deleted_directory_cannot_disappear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = plan_for(config, source)
    path = tmp_path / "plan.json"
    coverage.save_plan(config, plan, path)
    reply(monkeypatch)
    for job in ("first", "second"):
        coverage.run_planned_job(config, path, plan.sha256, source, "Summarize", job, execute=True)
    doc.run_job(config, source, "Summarize", "outside-plan", execute=True)
    unexpected = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert not unexpected["complete"] and unexpected["unexpected_entries"] == 1
    (config.jobs_dir / "first").rename(tmp_path / "preserved-first")
    missing = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert missing["jobs"][0]["state"] == "missing" and missing["saved_documents"] == 1


def test_guard_denial_is_accounted_but_not_a_saved_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = DocumentRunPlan(config.sha256, (plan_for(config, source).jobs[0],))
    path = tmp_path / "plan.json"
    coverage.save_plan(config, plan, path)
    reply(monkeypatch)
    original = writer.GuardedWorkspace.submit

    def forbidden(self: Any, raw: bytes) -> Any:
        proposal = json.loads(raw)
        proposal["artifact"] = "protected"
        return original(self, json.dumps(proposal).encode())

    monkeypatch.setattr(writer.GuardedWorkspace, "submit", forbidden)
    result = coverage.run_planned_job(config, path, plan.sha256, source, "Summarize", "first",
                                      execute=True)
    assert result["state"] == "denied"
    observed = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert observed["complete"] and observed["saved_documents"] == 0
    assert observed["jobs"][0]["state"] == "denied"


def test_changed_plan_rejected_against_retained_digest(tmp_path: Path) -> None:
    config, source, _ = setup(tmp_path)
    plan = plan_for(config, source)
    path = tmp_path / "plan.json"
    coverage.save_plan(config, plan, path)
    value = plan.record()
    value["jobs"].pop()
    path.write_text(json.dumps(value), encoding="utf-8")
    observed = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert observed["state"] == "invalid"
    with pytest.raises(ValueError, match="retained expectation"):
        coverage.run_planned_job(config, path, plan.sha256, source, "Summarize", "first",
                                 execute=True)


def test_no_plan_marker_is_not_admitted_by_posthoc_matching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = DocumentRunPlan(config.sha256, (plan_for(config, source).jobs[0],))
    path = tmp_path / "plan.json"
    coverage.save_plan(config, plan, path)
    reply(monkeypatch)
    doc.run_job(config, source, "Summarize", "first", execute=True)
    observed = coverage.inspect_coverage(config, path, expected_plan_sha256=plan.sha256)
    assert not observed["complete"]
    assert observed["jobs"][0]["state"] == "expectation_mismatch"


def test_direct_call_cannot_precede_retained_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    plan = plan_for(config, source)
    path = tmp_path / "not-yet-saved.json"
    calls = reply(monkeypatch)
    with pytest.raises(ValueError, match="supplied together"):
        doc.run_job(config, source, "Summarize", "first", execute=True, run_plan_sha256=plan.sha256)
    with pytest.raises(FileNotFoundError):
        doc.run_job(config, source, "Summarize", "first", execute=True,
                    run_plan_sha256=plan.sha256, run_plan_path=path)
    assert not calls and not list(config.jobs_dir.iterdir())
