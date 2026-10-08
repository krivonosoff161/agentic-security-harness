"""Multi-source labels pass through real bounded document jobs as host data."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentic_security_harness import document_workflow as doc
from agentic_security_harness import workspace_writer as writer
from agentic_security_harness.document_admissions import initialize_admissions
from agentic_security_harness.document_coverage import inspect_coverage, run_planned_job
from agentic_security_harness.document_dynamic import run_admitted_job
from agentic_security_harness.document_expectations import (
    DocumentRunPlan,
    ExpectedDocumentJob,
    execution_sha256,
)
from agentic_security_harness.document_multisource import DocumentMultiSourceRestrictions
from agentic_security_harness.document_plan import job_arguments, prepare_plan
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_recovery import (
    inspect_recovery,
    read_recovered_document,
)
from agentic_security_harness.document_restrictions import (
    DocumentSourceRestrictions,
    parse_source_restrictions,
)
from agentic_security_harness.models import DataEnvelope
from test_document_workflow import reply, setup


def _leaf(
    raw: bytes, *, origin: datetime, ttl: int | None = 3600,
    recipients: list[str] | None = None, purposes: list[str] | None = None,
) -> DocumentSourceRestrictions:
    return DocumentSourceRestrictions.bind(raw, DataEnvelope(
        data_class="private",
        allowed_recipients=["local-model"] if recipients is None else recipients,
        allowed_purpose=["document-generation"] if purposes is None else purposes,
        can_store=True, can_forward=True, ttl_seconds=ttl,
        requires_confirmation=False, classification_source="host-config",
        classification_mutable=False,
    ), created_at=origin)


def _composed(
    *, ttl: int | None = 3600, recipients: list[str] | None = None,
    purposes: list[str] | None = None, origin: datetime | None = None,
) -> tuple[bytes, DocumentMultiSourceRestrictions]:
    first, second = b"Public agenda one", b"Public agenda two"
    start = origin or datetime.now(UTC)
    return DocumentMultiSourceRestrictions.compose((
        ("one", first, _leaf(first, origin=start, ttl=ttl)),
        ("two", second, _leaf(second, origin=start - timedelta(seconds=1),
                              ttl=ttl, recipients=recipients, purposes=purposes)),
    ))


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_saved_multisource_checked_handoff_preserves_originals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, _ = setup(tmp_path, engine)
    content, binding = _composed()
    source.write_bytes(content)
    answer = '{"ok":true}'
    requirements = DocumentRequirements("exact_json", expected_json=json.loads(answer))
    calls = reply(monkeypatch, answer)
    first = doc.run_job(config, source, "Extract status", "first", execute=True,
                        requirements=requirements, source_restrictions=binding)
    assert first["state"] == "saved" and len(calls) == 1
    assert first["source_restrictions_sha256"] == binding.sha256
    assert first["output_restrictions"] == binding.for_output(answer.encode()).record()
    observed = doc.inspect_job(config, "first")
    assert observed["state"] == "saved"
    captured = doc.read_job_document(config, "first")
    assert captured.restrictions == binding.for_output(answer.encode())
    second = doc.run_job(config, None, "Use checked status", "second", execute=True,
                         source_job="first", requirements=requirements)
    assert second["state"] == "saved" and len(calls) == 2
    assert second["source_restrictions"] == first["output_restrictions"]
    assert second["output_restrictions"]["leaves"] == binding.record()["leaves"]
    assert second["output_restrictions"]["assembly_sha256"] == binding.record()[
        "assembly_sha256"
    ]
    assert doc.inspect_job(config, "second")["state"] == "saved"


def test_reviewed_handoff_and_closed_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    content, binding = _composed(ttl=None)
    source.write_bytes(content)
    answer = "# Public result\n"
    calls = reply(monkeypatch, answer)
    first = doc.run_job(config, source, "Summarize", "first", execute=True,
                        source_restrictions=binding)
    assert first["state"] == "saved" and len(calls) == 1
    denied = doc.run_job(config, None, "Use result", "unreviewed", execute=True,
                         source_job="first")
    assert denied["reason"] == "source_review_required" and len(calls) == 1
    assert not (config.jobs_dir / "unreviewed").exists()
    digest = hashlib.sha256(answer.encode()).hexdigest()
    second = doc.run_job(config, None, "Use result", "reviewed", execute=True,
                         source_job="first", reviewed_source_sha256=digest)
    assert second["state"] == "saved" and len(calls) == 2
    assert second["source_restrictions"]["leaves"] == binding.record()["leaves"]
    malformed = binding.record()
    malformed["unexpected"] = True
    with pytest.raises(ValueError):
        parse_source_restrictions(malformed)
    with pytest.raises(ValueError):
        parse_source_restrictions({"schema_version": "unknown"})


@pytest.mark.parametrize(("options", "reason"), [
    ({"recipients": []}, "source_recipient_forbidden"),
    ({"purposes": []}, "source_purpose_forbidden"),
    ({"ttl": 1, "origin": datetime(2020, 1, 1, tzinfo=UTC)}, "source_expired"),
])
def test_composed_denial_precedes_model_and_job_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    options: dict[str, object], reason: str,
) -> None:
    config, source, _ = setup(tmp_path)
    content, binding = _composed(**options)  # type: ignore[arg-type]
    source.write_bytes(content)
    calls = reply(monkeypatch)
    result = doc.run_job(config, source, "Summarize", "blocked", execute=True,
                         source_restrictions=binding)
    assert result["reason"] == reason and result["effect"] == "none"
    assert result["model"]["transport_attempts"] == 0 and calls == []
    assert not (config.jobs_dir / "blocked").exists()


def test_earliest_multisource_deadline_expires_after_intent_before_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    content, binding = _composed(ttl=60)
    source.write_bytes(content)
    deadline = binding.expires_at
    assert deadline is not None
    calls = reply(monkeypatch)
    write_once = writer.WorkspaceFiles.write_once

    class DeadlineClock:
        @staticmethod
        def now(zone: object) -> datetime:
            assert deadline is not None
            return deadline

    def expire_after_intent(self: object, artifact: str, raw: bytes) -> object:
        result = write_once(self, artifact, raw)  # type: ignore[arg-type]
        if artifact == "intent1":
            monkeypatch.setattr(writer, "datetime", DeadlineClock)
        return result

    monkeypatch.setattr(writer.WorkspaceFiles, "write_once", expire_after_intent)
    result = doc.run_job(config, source, "Summarize", "expired-after-intent",
                         execute=True, source_restrictions=binding)
    monkeypatch.setattr(writer, "datetime", datetime)
    assert len(calls) == 1
    assert result["state"] == "denied" and result["reason"] == "source_expired"
    assert result["effect"] == "none"
    assert result["decision"]["decision"]["disposition"] == "allow"
    assert not (config.jobs_dir / "expired-after-intent" / "document.md").exists()
    assert doc.inspect_job(config, "expired-after-intent")["state"] == "denied"


def test_admitted_multisource_supervised_preview_and_invalid_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    content, binding = _composed()
    source.write_bytes(content)
    plan = DocumentRunPlan(config.sha256, (ExpectedDocumentJob(
        "first", hashlib.sha256(b"Summarize").hexdigest(),
        input_sha256=hashlib.sha256(content).hexdigest(),
        source_restrictions_sha256=binding.sha256,
        execution_sha256=execution_sha256(requirements_sha256=None),
    ),))
    ledger = tmp_path / "admissions"
    state = initialize_admissions(config, plan, ledger)
    calls = reply(monkeypatch)
    with pytest.raises(ValueError, match="timeout_seconds"):
        run_admitted_job(config, ledger, state.head_sha256, source, "Summarize", "first",
                         execute=True, source_restrictions=binding, timeout_seconds=0)
    preview = run_admitted_job(config, ledger, state.head_sha256, source, "Summarize", "first",
                               source_restrictions=binding, timeout_seconds=1)
    assert preview["state"] == "preview" and not calls
    assert not (config.jobs_dir / "first").exists()


def test_compiled_plan_multisource_binding_and_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    content, binding = _composed()
    source.write_bytes(content)
    restriction_path = tmp_path / "restriction.json"
    restriction_path.write_text(json.dumps(binding.record()), encoding="utf-8")
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({
        "schema_version": "ash.document-plan-spec.v1",
        "jobs": [
            {"job_id": "first", "task": "Summarize", "input": source.name,
             "source_restrictions": restriction_path.name},
            {"job_id": "second", "task": "Use result", "from_job": "first"},
        ],
    }), encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    planned = prepare_plan(config, spec_path, plan_path, execute=True)
    assert planned["state"] == "planned"
    arguments = job_arguments(config, spec_path, "first")
    assert arguments["source_restrictions"] == binding
    calls = reply(monkeypatch, "# Public result\n")
    first = run_planned_job(config, plan_path, planned["plan_sha256"], source,
                            "Summarize", "first", execute=True,
                            source_restrictions=binding)
    assert first["state"] == "saved" and len(calls) == 1
    review = doc.inspect_job(config, "first")["document_sha256"]
    second = run_planned_job(config, plan_path, planned["plan_sha256"], None,
                             "Use result", "second", execute=True, source_job="first",
                             reviewed_source_sha256=review)
    assert second["state"] == "saved" and len(calls) == 2
    assert second["source_restrictions"]["leaves"] == binding.record()["leaves"]
    coverage = inspect_coverage(config, plan_path, expected_plan_sha256=planned["plan_sha256"])
    assert coverage["complete"] is True and coverage["saved_documents"] == 2


def test_multisource_recovery_keeps_original_leaves_and_no_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    content, binding = _composed(ttl=None)
    source.write_bytes(content)
    answer = "# Recovered public result\n"
    calls = reply(monkeypatch, answer)
    original = doc.WorkspaceFiles.write_once

    def fail_result(self: object, alias: str, raw: bytes) -> object:
        if alias == "result1":
            raise OSError("synthetic result receipt failure")
        return original(self, alias, raw)  # type: ignore[arg-type]

    monkeypatch.setattr(doc.WorkspaceFiles, "write_once", fail_result)
    first = doc.run_job(config, source, "Summarize", "first", execute=True,
                        source_restrictions=binding)
    assert first["state"] == "needs_inspection" and len(calls) == 1
    status = inspect_recovery(config, "first")
    assert status["state"] == "recoverable_data"
    assert status["output_restrictions"] == binding.for_output(answer.encode()).record()
    job = config.jobs_dir / "first"
    before = {path.name: path.read_bytes() for path in job.iterdir()}
    captured = read_recovered_document(
        config, "first", reviewed_source_sha256=status["document_sha256"],
    )
    assert captured.restrictions == binding.for_output(answer.encode())
    assert {path.name: path.read_bytes() for path in job.iterdir()} == before
    assert len(calls) == 1
