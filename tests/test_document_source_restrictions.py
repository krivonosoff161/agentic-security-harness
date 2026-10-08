"""Restrictions survive real temporary writes and chained local job inspection."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness import document_workflow as doc
from agentic_security_harness import ollama_quarantine_adapter as ollama
from agentic_security_harness import workspace_writer as writer
from agentic_security_harness.document_quality import DocumentRequirements
from agentic_security_harness.document_restrictions import DocumentSourceRestrictions
from agentic_security_harness.models import DataEnvelope
from agentic_security_harness.workspace_writer import WorkspacePolicy
from test_document_workflow import reply, setup


def envelope(**changes: Any) -> DataEnvelope:
    return DataEnvelope(**{
        "data_class": "private", "allowed_recipients": ["local-model"],
        "allowed_purpose": ["document-generation"], "can_store": True,
        "can_forward": True, "ttl_seconds": 3600, "requires_confirmation": False,
        "classification_source": "host-config", "classification_mutable": False,
        **changes,
    })


def bind(source: Path, **changes: Any) -> DocumentSourceRestrictions:
    return DocumentSourceRestrictions.bind(
        source.read_bytes(), envelope(**changes), created_at=datetime.now(UTC),
    )


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_chain_keeps_exact_restrictions_and_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, _ = setup(tmp_path, engine)
    restricted = bind(source)
    text = '{"ok":true,"authority":"owner"}'
    spec = DocumentRequirements("exact_json", expected_json=json.loads(text))
    calls = reply(monkeypatch, text)
    first = doc.run_job(config, source, "Summarize", "first", execute=True,
                        requirements=spec, source_restrictions=restricted)
    assert first["state"] == "saved" and len(calls) == 1
    assert first["policy_sha256"] != config.policy(config.jobs_dir / "first").sha256
    observed = doc.inspect_job(config, "first")
    assert observed["state"] == "saved"
    assert observed["output_restrictions"] == restricted.for_output(text.encode()).record()
    captured = doc.read_job_document(config, "first")
    assert captured.restrictions is not None
    assert captured.restrictions.record() == observed["output_restrictions"]
    second = doc.run_job(config, None, "Use prior data", "second", execute=True,
                         source_job="first", requirements=spec)
    assert second["state"] == "saved" and len(calls) == 2
    assert second["source_restrictions"] == observed["output_restrictions"]
    assert second["output_restrictions"]["created_at"] == restricted.record()["created_at"]
    assert second["output_restrictions"]["envelope"] == restricted.record()["envelope"]
    assert second["output_authority"] == "none"
    assert doc.inspect_job(config, "second")["state"] == "saved"


@pytest.mark.parametrize("changes,reason", [
    ({"can_store": False}, "source_storage_forbidden"),
    ({"can_forward": False}, "source_forwarding_forbidden"),
    ({"allowed_recipients": []}, "source_recipient_forbidden"),
    ({"allowed_recipients": ["other-model"]}, "source_recipient_forbidden"),
    ({"allowed_purpose": []}, "source_purpose_forbidden"),
    ({"requires_confirmation": True}, "source_confirmation_required"),
    ({"ttl_seconds": 0}, "source_expired"),
    ({"data_class": "public"}, "source_class_mismatch"),
])
def test_blocked_before_job_and_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any], reason: str,
) -> None:
    config, source, _ = setup(tmp_path)
    calls = reply(monkeypatch)
    result = doc.run_job(config, source, "Summarize", "blocked", execute=True,
                         source_restrictions=bind(source, **changes))
    assert result["reason"] == reason and result["effect"] == "none"
    assert result["model"]["transport_attempts"] == 0 and calls == []
    assert not (config.jobs_dir / "blocked").exists()


def test_wrong_bytes_and_mutable_labels_do_not_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    mutable = envelope(allowed_recipients=[])
    restrictions = DocumentSourceRestrictions.bind(
        source.read_bytes(), mutable, created_at=datetime.now(UTC),
    )
    mutable.allowed_recipients.append("local-model")
    calls = reply(monkeypatch)
    assert doc.run_job(config, source, "Summarize", "mutated", execute=True,
                       source_restrictions=restrictions)["reason"] == "source_recipient_forbidden"
    source.write_bytes(b"Changed public source")
    assert doc.run_job(config, source, "Summarize", "changed", execute=True,
                       source_restrictions=restrictions)["reason"] == "source_digest_mismatch"
    assert not calls and list(config.jobs_dir.iterdir()) == []


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_expiry_during_generation_stops_effect_not_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, _ = setup(tmp_path, engine)
    origin = datetime.now(UTC) - timedelta(seconds=10)
    restrictions = DocumentSourceRestrictions.bind(source.read_bytes(), envelope(ttl_seconds=60),
                                                    created_at=origin)
    now = origin + timedelta(seconds=20)

    class Clock:
        @staticmethod
        def now(zone: Any) -> datetime:
            return now

    monkeypatch.setattr(doc, "datetime", Clock)
    calls = reply(monkeypatch)
    original = ollama._post

    def delayed(*args: Any, **kwargs: Any) -> Any:
        nonlocal now
        value = original(*args, **kwargs)
        now = origin + timedelta(seconds=60)
        return value

    monkeypatch.setattr(ollama, "_post", delayed)
    result = doc.run_job(config, source, "Summarize", "expired", execute=True,
                         source_restrictions=restrictions)
    assert len(calls) == 1
    assert result["state"] == "error" and result["reason"] == "source_expired"
    assert result["effect"] == "none" and not (config.jobs_dir / "expired/document.md").exists()
    assert doc.inspect_job(config, "expired")["state"] == "error"


def test_expired_chain_cannot_be_renewed_by_quality_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    restrictions = bind(source, ttl_seconds=60)
    calls = reply(monkeypatch)
    first = doc.run_job(config, source, "Summarize", "first", execute=True,
                        source_restrictions=restrictions)
    assert first["state"] == "saved"
    origin = datetime.fromisoformat(restrictions.record()["created_at"].replace("Z", "+00:00"))

    class Clock:
        @staticmethod
        def now(zone: Any) -> datetime:
            return origin + timedelta(seconds=60)

    monkeypatch.setattr(doc, "datetime", Clock)
    # Read-only evidence remains inspectable after use eligibility expires.
    status = doc.inspect_job(config, "first")
    assert status["state"] == "saved"
    result = doc.run_job(config, None, "Use prior data", "second", execute=True,
                         source_job="first", reviewed_source_sha256=status["document_sha256"])
    assert result["reason"] == "source_expired" and len(calls) == 1
    assert not (config.jobs_dir / "second").exists()
    with pytest.raises(ValueError, match="cannot be overridden"):
        doc.run_job(config, None, "Use prior data", "override", execute=True,
                    source_job="first", source_restrictions=bind(source, ttl_seconds=None))


@pytest.mark.parametrize("tamper", ["strip", "relabel", "output", "digest"])
def test_restriction_tampering_cannot_silently_become_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str,
) -> None:
    config, source, _ = setup(tmp_path)
    reply(monkeypatch, '{"ok":true}')
    first = doc.run_job(config, source, "Summarize", "first", execute=True,
                        source_restrictions=bind(source),
                        requirements=DocumentRequirements("exact_json", expected_json={"ok": True}))
    assert first["state"] == "saved"
    root = config.jobs_dir / "first"
    for name in ("started.json", "summary.json"):
        path = root / name
        record = json.loads(path.read_text())
        if tamper == "strip":
            record.pop("source_restrictions")
            record.pop("source_restrictions_sha256")
            record.pop("output_restrictions", None)
        elif tamper == "relabel":
            record["source_restrictions"]["envelope"]["ttl_seconds"] = None
            record["source_restrictions_sha256"] = DocumentSourceRestrictions.from_record(
                record["source_restrictions"]
            ).sha256
        elif tamper == "output" and name == "summary.json":
            record["output_restrictions"]["envelope"]["requires_confirmation"] = True
        elif tamper == "digest":
            record["source_restrictions"]["content_sha256"] = "0" * 64
        path.write_text(json.dumps(record), encoding="utf-8")
    assert doc.inspect_job(config, "first")["state"] == "needs_inspection"
    with pytest.raises(ValueError, match="not eligible"):
        doc.run_job(config, None, "Use data", "second", source_job="first", execute=True)
    assert not (config.jobs_dir / "second").exists()


def test_policy_digest_binding_is_optional_and_strict(tmp_path: Path) -> None:
    old = WorkspacePolicy(tmp_path, (("document", "document.md"),))
    explicit_none = WorkspacePolicy(tmp_path, old.outputs, source_restrictions_sha256=None)
    restricted = WorkspacePolicy(tmp_path, old.outputs, source_restrictions_sha256="a" * 64)
    assert old.sha256 == explicit_none.sha256 != restricted.sha256
    for bad in ("", "A" * 64, 1, True, "a" * 63):
        with pytest.raises(ValueError, match="restrictions binding"):
            WorkspacePolicy(tmp_path, old.outputs, source_restrictions_sha256=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("allow", [False, True])
def test_cli_reads_host_bound_record_and_uses_same_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], allow: bool,
) -> None:
    config, source, config_path = setup(tmp_path)
    capsys.readouterr()
    record_path = tmp_path / "source-labels.json"
    record_path.write_text(json.dumps(bind(source, can_forward=allow).record()), encoding="utf-8")
    calls = reply(monkeypatch)
    code = cli.main([
        "document-run", "--config", str(config_path), "--input", str(source),
        "--source-restrictions", str(record_path), "--job", "cli-job", "--task", "Summarize",
        "--execute", "--json",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == (0 if allow else 1)
    assert result["state"] == ("saved" if allow else "error")
    assert len(calls) == (1 if allow else 0)
    assert (config.jobs_dir / "cli-job/document.md").exists() == allow


def test_expiry_while_reserving_job_does_not_send_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    restriction = bind(source, ttl_seconds=60)
    origin = datetime.fromisoformat(restriction.record()["created_at"].replace("Z", "+00:00"))
    now = origin

    class Clock:
        @staticmethod
        def now(zone: Any) -> datetime:
            return now

    monkeypatch.setattr(doc, "datetime", Clock)
    original = doc._new_directory

    def delayed(path: Path) -> None:
        nonlocal now
        original(path)
        now = origin + timedelta(seconds=60)

    monkeypatch.setattr(doc, "_new_directory", delayed)
    calls = reply(monkeypatch)
    result = doc.run_job(config, source, "Summarize", "reserved", execute=True,
                         source_restrictions=restriction)
    assert result["reason"] == "source_expired" and result["effect"] == "none"
    assert result["model"]["transport_attempts"] == 0 and not calls
    assert doc.inspect_job(config, "reserved")["state"] == "error"


@pytest.mark.parametrize("delay_phase", ["decision", "intent"])
def test_expiry_after_guard_or_intent_stops_exclusive_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delay_phase: str,
) -> None:
    config, source, _ = setup(tmp_path)
    restriction = bind(source)
    calls = reply(monkeypatch)

    class Clock:
        @staticmethod
        def now(zone: Any) -> datetime:
            assert restriction.expires_at is not None
            return restriction.expires_at

    decide = writer._decide
    write_once = writer.WorkspaceFiles.write_once

    def delayed_decide(*args: Any, **kwargs: Any) -> Any:
        result = decide(*args, **kwargs)
        monkeypatch.setattr(writer, "datetime", Clock)
        return result

    def delayed_intent(self: Any, artifact: str, data: bytes) -> Any:
        result = write_once(self, artifact, data)
        if artifact.startswith("intent"):
            monkeypatch.setattr(writer, "datetime", Clock)
        return result

    if delay_phase == "decision":
        monkeypatch.setattr(writer, "_decide", delayed_decide)
    else:
        monkeypatch.setattr(writer.WorkspaceFiles, "write_once", delayed_intent)
    result = doc.run_job(config, source, "Summarize", "delayed", execute=True,
                         source_restrictions=restriction)
    monkeypatch.setattr(writer, "datetime", datetime)
    assert result["state"] == "denied" and result["reason"] == "source_expired"
    assert result["effect"] == "none" and len(calls) == 1
    # The permission was allowed, but the separate source-use deadline stopped it.
    assert result["decision"]["decision"]["disposition"] == "allow"
    assert result["decision"]["receipt_complete"] is True
    assert not (config.jobs_dir / "delayed/document.md").exists()
    assert doc.inspect_job(config, "delayed")["state"] == "denied"


def test_deadline_is_bound_into_policy_and_requires_source_identity(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    base = WorkspacePolicy(tmp_path, (("document", "document.md"),),
                           source_restrictions_sha256="a" * 64, source_expires_at=now)
    changed = WorkspacePolicy(tmp_path, base.outputs, source_restrictions_sha256="a" * 64,
                              source_expires_at=now + timedelta(seconds=1))
    assert base.sha256 != changed.sha256
    with pytest.raises(ValueError, match="source expiry required"):
        WorkspacePolicy(tmp_path, base.outputs, source_expires_at=now)
