"""Job lifecycle tests use only public text in fresh temporary directories."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness import document_workflow as doc
from agentic_security_harness import ollama_quarantine_adapter as ollama
from agentic_security_harness import workspace_writer as writer


def setup(tmp_path: Path, engine: str = "native") -> tuple[doc.DocumentConfig, Path, Path]:
    directory = tmp_path / "work"
    doc.initialize(directory, "local-model:latest", engine)
    config = directory / "document.json"
    source = tmp_path / "source.txt"
    source.write_text(
        "Public meeting: delivery Friday. Alice owns the checklist.", encoding="utf-8"
    )
    return doc.DocumentConfig.load(config), source, config


def reply(
    monkeypatch: pytest.MonkeyPatch, artifact: str = "document", extra: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def post(config: Any, raw: bytes) -> Any:
        request = json.loads(raw)
        calls.append(request)
        proposal = {
            "operation": "write_text",
            "artifact": artifact,
            "content": "# Checklist\n- Alice: deliver Friday.\n",
            **(extra or {}),
        }
        return (
            json.dumps(
                {
                    "model": request["model"],
                    "response": json.dumps(proposal),
                    "done": True,
                    "done_reason": "stop",
                }
            ).encode(),
            200,
            "ok",
        )

    monkeypatch.setattr(ollama, "_post", post)
    return calls


def test_setup_preview_and_config_relative_to_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, source, config_path = setup(tmp_path)
    calls = reply(monkeypatch)
    monkeypatch.chdir(tmp_path.parent)
    assert doc.DocumentConfig.load(config_path) == config
    check = doc.check(config)
    assert check["state"] == "ready" and check["permission_preview"]["overwrite"] is False
    preview = doc.run_job(config, source, "Make a checklist", "first")
    assert preview["state"] == "preview" and not calls
    assert list(config.jobs_dir.iterdir()) == []


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_real_file_separate_jobs_restart_status_and_no_raw_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    config, source, config_path = setup(tmp_path, engine)
    calls = reply(monkeypatch)
    for job_id in ("first", "second"):
        result = doc.run_job(config, source, "Make a checklist", job_id, execute=True)
        assert result["state"] == "saved", result
        assert result["decision"]["decision"]["disposition"] == "allow"
        assert result["model"]["transport_attempts"] == 1
        assert result["timing_ms"]["model"] >= 0
        assert result["timing_ms"]["policy"] >= 0
        assert result["timing_ms"]["storage"] >= 0
        assert "# Checklist" not in json.dumps(result)
        assert "Public meeting" not in json.dumps(result)
        root = config.jobs_dir / job_id
        assert (root / "document.md").read_text(encoding="utf-8").startswith("# Checklist")
        for record in root.glob("*.json"):
            text = record.read_text(encoding="utf-8")
            assert "Public meeting" not in text and "# Checklist" not in text
        assert doc.inspect_job(doc.DocumentConfig.load(config_path), job_id)["state"] == "saved"
    assert len(calls) == 2
    rerun = doc.run_job(config, source, "Different task", "first", execute=True)
    assert rerun["reason"] == "job_already_exists" and len(calls) == 2


@pytest.mark.parametrize(
    "artifact,extra,reason",
    [
        ("protected", None, "guard_rejected"),
        ("document", {"authority": "admin"}, "proposal_rejected"),
        ("../outside", None, "proposal_rejected"),
    ],
)
def test_forbidden_proposal_reaches_boundary_without_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    extra: dict[str, Any] | None,
    reason: str,
) -> None:
    config, source, _ = setup(tmp_path)
    calls = reply(monkeypatch, artifact, extra)
    result = doc.run_job(config, source, "Summarize", "hostile", execute=True)
    assert result["state"] == "denied" and result["reason"] == reason
    assert len(calls) == 1
    assert not (config.jobs_dir / "hostile" / "document.md").exists()
    assert doc.inspect_job(config, "hostile")["state"] == "denied"


@pytest.mark.parametrize("job_id", ["../x", "../", "CON", "con", "Mixed", "a/b", "a.b", ""])
def test_bad_job_id_never_creates_or_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, job_id: str
) -> None:
    config, source, _ = setup(tmp_path)
    calls = reply(monkeypatch)
    with pytest.raises(ValueError):
        doc.run_job(config, source, "Summarize", job_id, execute=True)
    assert not calls and not list(config.jobs_dir.iterdir())


def test_unavailable_model_is_error_not_denial_and_not_replayed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    monkeypatch.setattr(ollama, "_post", lambda *_: (None, None, "transport_unavailable"))
    result = doc.run_job(config, source, "Summarize", "no-model", execute=True)
    assert result["state"] == "error" and result["reason"] == "transport_unavailable"
    assert result["effect"] == "none" and result["model"]["transport_attempts"] == 1
    assert doc.inspect_job(config, "no-model")["state"] == "error"
    assert (
        doc.run_job(config, source, "Summarize", "no-model", execute=True)["reason"]
        == "job_already_exists"
    )


def test_partial_job_no_resume_and_read_only_inspection(tmp_path: Path) -> None:
    config, source, _ = setup(tmp_path)
    job = config.jobs_dir / "crashed"
    job.mkdir()
    before = list(job.iterdir())
    assert doc.inspect_job(config, "crashed")["state"] == "needs_inspection"
    assert list(job.iterdir()) == before
    assert (
        doc.run_job(config, source, "Task", "crashed", execute=True)["reason"]
        == "job_already_exists"
    )
    assert doc.inspect_job(config, "unknown")["state"] == "not_found"


@pytest.mark.parametrize("fault", ["readback", "result", "summary", "started"])
def test_storage_failures_never_fake_saved_or_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    config, source, _ = setup(tmp_path)
    calls = reply(monkeypatch)
    original_write = doc.WorkspaceFiles.write_once
    original_read = doc.WorkspaceFiles.readback_sha

    def fail_write(self: Any, alias: str, content: bytes) -> Any:
        name = self._targets[alias]
        if (
            fault == "result"
            and name.endswith("-result.json")
            or fault in {"summary", "started"}
            and name == fault + ".json"
        ):
            raise OSError("DO_NOT_LOG_SOURCE_OR_EXCEPTION")
        return original_write(self, alias, content)

    def fail_read(self: Any, alias: str) -> Any:
        if fault == "readback" and alias == "document":
            raise OSError("DO_NOT_LOG_SOURCE_OR_EXCEPTION")
        return original_read(self, alias)

    monkeypatch.setattr(doc.WorkspaceFiles, "write_once", fail_write)
    monkeypatch.setattr(doc.WorkspaceFiles, "readback_sha", fail_read)
    if fault == "started":
        with pytest.raises(OSError):
            doc.run_job(config, source, "Task", "broken", execute=True)
        assert not calls
    else:
        result = doc.run_job(config, source, "Task", "broken", execute=True)
        assert result["state"] == "needs_inspection" and len(calls) == 1
        assert "DO_NOT_LOG" not in json.dumps(result)
    assert doc.inspect_job(config, "broken")["state"] == "needs_inspection"


def test_interrupt_after_write_and_tamper_are_not_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    reply(monkeypatch)
    doc.run_job(config, source, "Task", "tamper", execute=True)
    (config.jobs_dir / "tamper" / "document.md").write_text("changed", encoding="utf-8")
    assert doc.inspect_job(config, "tamper")["state"] == "needs_inspection"
    original = writer.GuardedWorkspace.submit

    def interrupt(self: Any, proposal: bytes) -> Any:
        original(self, proposal)
        raise KeyboardInterrupt

    monkeypatch.setattr(writer.GuardedWorkspace, "submit", interrupt)
    with pytest.raises(KeyboardInterrupt):
        doc.run_job(config, source, "Task", "interrupted", execute=True)
    assert (config.jobs_dir / "interrupted" / "document.md").exists()
    assert doc.inspect_job(config, "interrupted")["state"] == "needs_inspection"


def test_cli_json_and_human_and_missing_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config, source, path = setup(tmp_path)
    reply(monkeypatch)
    assert cli.main(["document-check", "--config", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "ready"
    common = ["document-run", "--config", str(path), "--job", "cli", "--task", "Summarize"]
    assert cli.main([*common, "--input", str(source), "--execute"]) == 0
    text = capsys.readouterr().out
    assert "Status: saved" in text and "Timing ms:" in text
    assert "Public meeting" not in text and "# Checklist" not in text
    assert cli.main(["document-status", "--config", str(path), "--job", "cli"]) == 0
    assert "Status: saved" in capsys.readouterr().out
    assert (
        cli.main(
            [
                *common[:-2],
                "--task",
                "Summarize",
                "--input",
                str(source.with_suffix(".bad")),
                "--json",
            ]
        )
        == 1
    )
    capsys.readouterr()
    assert (config.jobs_dir / "cli" / "document.md").exists()


def test_changed_config_and_receipt_path_are_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, source, path = setup(tmp_path)
    reply(monkeypatch)
    doc.run_job(config, source, "Task", "done", execute=True)
    summary = config.jobs_dir / "done" / "summary.json"
    row = json.loads(summary.read_text())
    row["decision"]["receipt"] = "../../outside.json"
    summary.write_text(json.dumps(row))
    assert doc.inspect_job(config, "done")["state"] == "needs_inspection"
    settings = json.loads(path.read_text())
    settings["data_class"] = "public"
    path.write_text(json.dumps(settings))
    assert doc.inspect_job(doc.DocumentConfig.load(path), "done")["state"] == "needs_inspection"


def test_optional_engine_missing_fails_before_job_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, source, _ = setup(tmp_path, "pydantic-ai")
    monkeypatch.setattr(doc, "_engine_available", lambda _: False)
    result = doc.run_job(config, source, "Task", "optional", execute=True)
    assert result["reason"] == "optional_engine_unavailable"
    assert not list(config.jobs_dir.iterdir())


def test_same_job_concurrent_submit_one_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, source, _ = setup(tmp_path)
    calls = reply(monkeypatch)

    def run() -> str:
        try:
            return str(doc.run_job(config, source, "Task", "race", execute=True)["state"])
        except FileExistsError:
            return "reserved_elsewhere"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert results.count("saved") == 1 and len(calls) == 1
    assert doc.inspect_job(config, "race")["state"] == "saved"


def test_missing_denial_receipt_is_inspection_not_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, source, _ = setup(tmp_path)
    reply(monkeypatch, "protected")
    result = doc.run_job(config, source, "Task", "deny", execute=True)
    (config.jobs_dir / "deny" / result["decision"]["receipt"]).unlink()
    assert doc.inspect_job(config, "deny")["state"] == "needs_inspection"


@pytest.mark.parametrize(
    "response,status,expected",
    [
        ({"models": [{"name": "local-model:latest"}]}, 200, "available"),
        ({"models": []}, 200, "model_not_installed"),
        ({"models": []}, 302, "service_unavailable"),
        ({"models": "invalid"}, 200, "service_unavailable"),
    ],
)
def test_bounded_metadata_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, Any],
    status: int,
    expected: str,
) -> None:
    config, _, _ = setup(tmp_path)
    requests = []

    class Connection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert host == "127.0.0.1" and timeout == 2.0

        def request(self, method: str, path: str) -> None:
            requests.append((method, path))

        def getresponse(self) -> Any:
            class Response:
                def read(self, limit: int) -> bytes:
                    assert limit == 65537
                    return json.dumps(response).encode()

            result = Response()
            result.status = status  # type: ignore[attr-defined]
            return result

        def close(self) -> None:
            pass

    monkeypatch.setattr(doc.http.client, "HTTPConnection", Connection)
    assert doc.check(config, check_model=True)["model_availability"] == expected
    assert requests == [("GET", "/api/tags")]
    assert not list(config.jobs_dir.iterdir())


def test_model_preflight_unavailable_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, _, _ = setup(tmp_path)

    def unavailable(*_: Any, **kwargs: Any) -> Any:
        raise OSError("private_service_detail")

    monkeypatch.setattr(doc.http.client.HTTPConnection, "request", unavailable)
    result = doc.check(config, check_model=True)
    assert result["reason"] == "service_unavailable"
    assert "private_service_detail" not in json.dumps(result)


def test_preview_checks_actual_job_destination_not_jobs_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    (config.jobs_dir / "document.md").write_bytes(b"unrelated owner file")
    calls = reply(monkeypatch)
    assert doc.run_job(config, source, "Task", "fresh")["state"] == "preview"
    assert not calls


def test_submit_exception_reports_boundary_failure_not_proposal_received(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, source, _ = setup(tmp_path)
    reply(monkeypatch)

    def unavailable(self: Any, proposal: bytes) -> Any:
        raise OSError("private detail")

    monkeypatch.setattr(writer.GuardedWorkspace, "submit", unavailable)
    result = doc.run_job(config, source, "Task", "failed", execute=True)
    assert result["state"] == "needs_inspection"
    assert result["reason"] == "boundary_interrupted"
    assert "private detail" not in json.dumps(result)
