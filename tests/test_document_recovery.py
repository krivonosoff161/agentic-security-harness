"""Recovery only inspects public synthetic jobs in temporary directories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness import document_recovery as recovery
from agentic_security_harness import document_workflow as doc
from agentic_security_harness import ollama_quarantine_adapter as ollama

_CONTENT = "# Checklist\n- Alice: deliver Friday.\n"


def _job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, lose_result: bool = True,
) -> tuple[doc.DocumentConfig, Path, list[bytes]]:
    directory = tmp_path / "work"
    doc.initialize(directory, "local-model:latest")
    config = doc.DocumentConfig.load(directory / "document.json")
    source = tmp_path / "source.txt"
    source.write_text("Public meeting notes.", encoding="utf-8")
    calls: list[bytes] = []

    def post(_config: Any, raw: bytes) -> tuple[bytes, int, str]:
        calls.append(raw)
        request = json.loads(raw)
        return (json.dumps({"model": request["model"], "response": _CONTENT,
                            "done": True, "done_reason": "stop"}).encode(), 200, "ok")

    monkeypatch.setattr(ollama, "_post", post)
    if lose_result:
        original = doc.WorkspaceFiles.write_once

        def write_without_result(self: Any, alias: str, content: bytes) -> Any:
            if self._targets[alias].endswith("-result.json"):
                raise OSError("synthetic lost result")
            return original(self, alias, content)

        monkeypatch.setattr(doc.WorkspaceFiles, "write_once", write_without_result)
    outcome = doc.run_job(config, source, "Make a checklist", "first", execute=True)
    assert outcome["state"] == ("needs_inspection" if lose_result else "saved")
    assert len(calls) == 1
    return config, config.jobs_dir / "first", calls


def _record(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _replace(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def test_lost_result_recovers_exact_data_without_writes_or_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, root, calls = _job(tmp_path, monkeypatch)
    assert doc.inspect_job(config, "first")["state"] == "needs_inspection"
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    status = recovery.inspect_recovery(config, "first")
    assert status["state"] == "recoverable_data"
    assert status["replay_allowed"] is False
    assert status["original_completion_proven"] is False
    assert status["writes_performed"] is False
    assert len(status["recovery_evidence_sha256"]) == 64
    assert status["quality"]["status"] == "review_required"
    with pytest.raises(doc.SourceReviewBlocked):
        recovery.read_recovered_document(config, "first", reviewed_source_sha256="0" * 64)
    captured = recovery.read_recovered_document(
        config, "first", reviewed_source_sha256=status["document_sha256"]
    )
    assert captured.content == _CONTENT.encode()
    assert captured.recovery_sha256 == status["recovery_evidence_sha256"]
    assert captured.record()["kind"] == "recovered_document"
    assert doc.inspect_job(config, "first")["state"] == "needs_inspection"
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before
    assert len(calls) == 1


@pytest.mark.parametrize("change", [
    "missing_closure", "partial_closure", "wrong_session", "wrong_policy",
    "zero_attempts", "extra_attempt", "missing_output", "changed_output",
    "denied_intent", "bad_decision", "extra_file", "failed_quality",
])
def test_ambiguous_or_contradictory_evidence_never_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    config, root, calls = _job(tmp_path, monkeypatch)
    closure_path = root / "session-closed.json"
    closure = _record(closure_path)
    intent_path = next(root.glob("*-intent.json"))
    intent = _record(intent_path)
    if change == "missing_closure":
        closure_path.unlink()
    elif change == "partial_closure":
        closure.pop("closed")
        _replace(closure_path, closure)
    elif change == "wrong_session":
        closure["session_id"] = "0" * 32
        _replace(closure_path, closure)
    elif change == "wrong_policy":
        closure["policy_sha256"] = "0" * 64
        _replace(closure_path, closure)
    elif change == "zero_attempts":
        closure["attempts"] = 0
        _replace(closure_path, closure)
    elif change == "extra_attempt":
        (root / f".ash-{closure['session_id']}-02-intent.json").write_text("{}")
    elif change == "missing_output":
        (root / "document.md").unlink()
    elif change == "changed_output":
        (root / "document.md").write_text("changed", encoding="utf-8")
    elif change == "denied_intent":
        intent["write_authorized"] = False
        _replace(intent_path, intent)
    elif change == "bad_decision":
        intent["decision"]["disposition"] = "deny"
        _replace(intent_path, intent)
    elif change == "extra_file":
        (root / "extra.json").write_text("{}")
    else:
        quality = doc.evaluate_document(_CONTENT.encode())
        quality["status"] = "failed"
        quality["reason"] = "empty_document"
        _replace(root / "quality.json", quality)
    status = recovery.inspect_recovery(config, "first")
    assert status["state"] == "needs_inspection", status
    assert status["replay_allowed"] is False
    with pytest.raises(ValueError):
        recovery.read_recovered_document(config, "first", reviewed_source_sha256="0" * 64)
    assert len(calls) == 1


def test_complete_no_effect_result_blocks_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, root, _ = _job(tmp_path, monkeypatch)
    intent = _record(next(root.glob("*-intent.json")))
    result = {key: value for key, value in intent.items()
              if key not in {"phase", "write_authorized"}}
    result.update(receipt_complete=True, applied=False, effect="none", reason="guard_rejected")
    result["receipt"] = next(root.glob("*-intent.json")).name.replace(
        "-intent.json", "-result.json"
    )
    _replace(root / result["receipt"], result)
    assert recovery.inspect_recovery(config, "first")["state"] == "needs_inspection"


def test_absent_or_invalid_review_never_returns_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _job(tmp_path, monkeypatch)
    for digest in ("A" * 64, "", "0" * 64):
        with pytest.raises(doc.SourceReviewBlocked):
            recovery.read_recovered_document(config, "first", reviewed_source_sha256=digest)


def test_summary_cannot_claim_no_effect_with_existing_authorized_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, root, _ = _job(tmp_path, monkeypatch)
    path = root / "summary.json"
    value = _record(path)
    value.update(state="error", effect="none", decision=None, reason="no_proposal")
    _replace(path, value)
    observed = recovery.inspect_recovery(config, "first")
    assert observed["state"] == "needs_inspection"
    assert observed["reason"] == "recovery_contradictory_summary"


@pytest.mark.parametrize("key,value", [
    ("applied", True), ("effect", "created"), ("receipt_complete", True),
    ("reason", "write_completed"), ("proposal_sha256", "X" * 64),
    ("proposal_sha256", None), ("unexpected", "claim"),
])
def test_pre_effect_intent_must_have_exact_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str, value: Any,
) -> None:
    config, root, _ = _job(tmp_path, monkeypatch)
    path = next(root.glob("*-intent.json"))
    intent = _record(path)
    intent[key] = value
    _replace(path, intent)
    assert recovery.inspect_recovery(config, "first")["state"] == "needs_inspection"


def test_complete_job_uses_normal_handoff_not_ambiguous_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, calls = _job(tmp_path, monkeypatch, lose_result=False)
    observed = recovery.inspect_recovery(config, "first")
    assert observed["state"] == "already_complete"
    assert observed["reason"] == "use_normal_source_handoff"
    with pytest.raises(ValueError, match="use_normal_source_handoff"):
        recovery.read_recovered_document(config, "first",
                                         reviewed_source_sha256=observed["document_sha256"])
    assert len(calls) == 1


def test_cli_recovery_inspection_is_read_only_and_explains_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, root, calls = _job(tmp_path, monkeypatch)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    code = cli.main([
        "document-status", "--config", str(config.jobs_dir.parent / "document.json"),
        "--job", "first", "--inspect-recovery",
    ])
    text = capsys.readouterr().out
    assert code == 0 and "original outcome remains unresolved" in text
    assert _CONTENT not in text and len(calls) == 1
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}
