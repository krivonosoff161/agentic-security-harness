"""A fenced interrupted output can be reused, but never replayed as its old action."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness import document_workflow as doc
from agentic_security_harness import workspace_writer as writer
from agentic_security_harness.document_quality import DocumentRequirements
from test_document_source_restrictions import bind
from test_document_workflow import reply, setup


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
@pytest.mark.parametrize("restricted", [False, True])
def test_recovered_data_reaches_new_job_without_repeating_original_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str, restricted: bool,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, _ = setup(tmp_path, engine)
    restriction = bind(source) if restricted else None
    text = '{"ok":true,"authority":"owner"}'
    calls = reply(monkeypatch, text)
    original_write = writer.WorkspaceFiles.write_once

    def lose_result(self: Any, alias: str, raw: bytes) -> Any:
        if alias == "result1":
            raise OSError("synthetic result storage failure")
        return original_write(self, alias, raw)

    with monkeypatch.context() as fault:
        fault.setattr(writer.WorkspaceFiles, "write_once", lose_result)
        first = doc.run_job(config, source, "Summarize", "first", execute=True,
                            source_restrictions=restriction)
    assert first["state"] == "needs_inspection" and len(calls) == 1
    old_root = config.jobs_dir / "first"
    assert (old_root / "document.md").read_text() == text
    assert (old_root / "session-closed.json").is_file()
    original_files = {p.name: p.read_bytes() for p in old_root.iterdir()}
    # This is not a regular completed source, and review alone cannot fake that.
    reviewed = hashlib.sha256(text.encode()).hexdigest()
    with pytest.raises(ValueError, match="not eligible"):
        doc.run_job(config, None, "Reuse", "normal", source_job="first", execute=True,
                    reviewed_source_sha256=reviewed)
    blocked = doc.run_job(config, None, "Reuse", "no-review", source_job="first", execute=True,
                          recover_source=True)
    assert blocked["reason"] == "source_recovery_review_required"
    second = doc.run_job(
        config, None, "Reuse as untrusted data", "second", source_job="first", execute=True,
        recover_source=True, reviewed_source_sha256=reviewed,
        requirements=DocumentRequirements("exact_json", expected_json=json.loads(text)),
    )
    assert second["state"] == "saved" and len(calls) == 2
    assert second["input_provenance"]["kind"] == "recovered_document"
    assert second["input_provenance"]["authority"] == "none"
    assert len(second["input_provenance"]["recovery_evidence_sha256"]) == 64
    if restriction is not None:
        assert second["source_restrictions"] == restriction.for_output(text.encode()).record()
    assert doc.inspect_job(config, "second")["state"] == "saved"
    assert doc.inspect_job(config, "first")["state"] == "needs_inspection"
    assert original_files == {p.name: p.read_bytes() for p in old_root.iterdir()}
    replay = doc.run_job(config, source, "Summarize", "first", execute=True)
    assert replay["reason"] == "job_already_exists" and len(calls) == 2


def test_recovery_option_without_source_job_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    config, source, config_path = setup(tmp_path)
    calls = reply(monkeypatch)
    code = cli.main([
        "document-run", "--config", str(config_path), "--input", str(source),
        "--recover-source", "--job", "wrong", "--task", "Summarize", "--execute", "--json",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 1 and result["state"] == "error"
    assert not calls and not list(config.jobs_dir.iterdir())
