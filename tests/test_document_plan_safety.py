"""Planned CLI jobs keep review, recovery and source restrictions host-owned."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness import workspace_writer as writer
from test_document_source_restrictions import bind
from test_document_workflow import reply, setup


def _invoke(
    capsys: pytest.CaptureFixture[str], command: list[str],
) -> tuple[int, dict[str, Any]]:
    code = cli.main([*command, "--json"])
    return code, json.loads(capsys.readouterr().out)


def _spec(path: Path, jobs: list[dict[str, Any]]) -> Path:
    path.write_text(json.dumps({
        "schema_version": "ash.document-plan-spec.v1", "jobs": jobs,
    }), encoding="utf-8")
    return path


def _planned(
    capsys: pytest.CaptureFixture[str], config_path: Path, spec: Path, plan: Path,
) -> tuple[list[str], list[str]]:
    common = ["--config", str(config_path)]
    code, saved = _invoke(capsys, [
        "document-plan", *common, "--spec", str(spec), "--out", str(plan), "--execute",
    ])
    assert code == 0 and saved["state"] == "planned"
    return common, ["--plan", str(plan), "--plan-sha256", saved["plan_sha256"]]


def _run(
    capsys: pytest.CaptureFixture[str], common: list[str], pinned: list[str],
    spec: Path, job_id: str, *extra: str,
) -> tuple[int, dict[str, Any]]:
    return _invoke(capsys, [
        "document-run", *common, *pinned, "--spec", str(spec),
        "--job", job_id, "--execute", *extra,
    ])


def test_planned_fenced_recovery_never_replays_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    spec = _spec(tmp_path / "spec.json", [
        {"job_id": "first", "task": "Summarize", "input": source.name},
        {"job_id": "second", "task": "Reuse as untrusted data", "from_job": "first",
         "recover_source": True},
    ])
    plan = tmp_path / "host-plan.json"
    common, pinned = _planned(capsys, config_path, spec, plan)
    planned_bytes = plan.read_bytes()
    text = '{"ok":true}'
    calls = reply(monkeypatch, text)
    original_write = writer.WorkspaceFiles.write_once

    def lose_result(self: Any, alias: str, raw: bytes) -> Any:
        if alias == "result1":
            raise OSError("synthetic result storage failure")
        return original_write(self, alias, raw)

    with monkeypatch.context() as fault:
        fault.setattr(writer.WorkspaceFiles, "write_once", lose_result)
        code, first = _run(capsys, common, pinned, spec, "first")
    assert code == 1 and first["state"] == "needs_inspection" and len(calls) == 1
    old = config.jobs_dir / "first"
    assert (old / "document.md").read_text(encoding="utf-8") == text
    assert (old / "session-closed.json").is_file()
    old_files = {path.name: path.read_bytes() for path in old.iterdir()}
    code, inspection = _invoke(capsys, [
        "document-status", *common, "--job", "first", "--inspect-recovery",
    ])
    assert code == 0 and inspection["state"] == "recoverable_data"
    # The operator reviews the existing exact bytes, not a predicted plan digest.
    reviewed = hashlib.sha256((old / "document.md").read_bytes()).hexdigest()
    assert inspection["document_sha256"] == reviewed

    code, missing = _run(capsys, common, pinned, spec, "second")
    assert code == 1 and missing["reason"] == "source_recovery_review_required"
    code, wrong = _run(capsys, common, pinned, spec, "second",
                       "--reviewed-source-sha256", "0" * 64)
    assert code == 1 and wrong["state"] == "error"
    assert len(calls) == 1 and not (config.jobs_dir / "second").exists()

    code, second = _run(capsys, common, pinned, spec, "second",
                        "--reviewed-source-sha256", reviewed)
    assert code == 0 and second["state"] == "saved" and len(calls) == 2
    assert second["input_provenance"]["kind"] == "recovered_document"
    assert {path.name: path.read_bytes() for path in old.iterdir()} == old_files
    assert plan.read_bytes() == planned_bytes
    code, coverage = _invoke(capsys, ["document-coverage", *common, *pinned])
    assert code == 1 and coverage["complete"] is False
    assert coverage["unresolved_jobs"] >= 1
    assert len(calls) == 2


def test_planned_review_required_handoff_needs_runtime_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    spec = _spec(tmp_path / "spec.json", [
        {"job_id": "first", "task": "Summarize", "input": source.name},
        {"job_id": "second", "task": "Use the reviewed draft", "from_job": "first"},
    ])
    plan = tmp_path / "host-plan.json"
    common, pinned = _planned(capsys, config_path, spec, plan)
    plan_bytes = plan.read_bytes()
    calls = reply(monkeypatch)
    code, first = _run(capsys, common, pinned, spec, "first")
    assert code == 0 and first["state"] == "saved"
    assert first["quality"]["status"] == "review_required" and len(calls) == 1
    code, blocked = _run(capsys, common, pinned, spec, "second")
    assert code == 1 and blocked["reason"] == "source_review_required"
    assert len(calls) == 1 and not (config.jobs_dir / "second").exists()
    reviewed = hashlib.sha256((config.jobs_dir / "first" / "document.md").read_bytes()).hexdigest()
    code, second = _run(capsys, common, pinned, spec, "second",
                        "--reviewed-source-sha256", reviewed)
    assert code == 0 and second["state"] == "saved" and len(calls) == 2
    assert plan.read_bytes() == plan_bytes


def test_compiled_forwarding_denial_and_no_from_job_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    restrictions = tmp_path / "restrictions.json"
    restrictions.write_text(json.dumps(bind(source, can_forward=False).record()), encoding="utf-8")
    spec = _spec(tmp_path / "spec.json", [
        {"job_id": "first", "task": "Summarize", "input": source.name,
         "source_restrictions": restrictions.name},
        {"job_id": "second", "task": "Use first", "from_job": "first"},
    ])
    common, pinned = _planned(capsys, config_path, spec, tmp_path / "host-plan.json")
    calls = reply(monkeypatch)
    code, denied = _run(capsys, common, pinned, spec, "first")
    assert code == 1 and denied["reason"] == "source_forwarding_forbidden"
    assert not calls and not list(config.jobs_dir.iterdir())
    # A from-job restriction override is rejected by the closed compiler, not accepted
    # as a way to turn a denied source into unrestricted input.
    override = _spec(tmp_path / "override.json", [
        {"job_id": "first", "task": "Summarize", "input": source.name,
         "source_restrictions": restrictions.name},
        {"job_id": "second", "task": "Use first", "from_job": "first",
         "source_restrictions": restrictions.name},
    ])
    code, rejected = _invoke(capsys, [
        "document-plan", *common, "--spec", str(override),
        "--out", str(tmp_path / "unused-plan.json"),
    ])
    assert code == 1 and rejected["state"] == "error"
    assert not calls and not list(config.jobs_dir.iterdir())
