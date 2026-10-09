"""Application-level checks; data and all effects are owned temporary files."""

from __future__ import annotations

import io
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import cli
from agentic_security_harness import workspace_writer as writer
from agentic_security_harness.workspace_writer import (
    GuardedWorkspace,
    WorkspacePolicy,
    verify_workspace_output,
)


def proposal(artifact: str = "draft", content: str = "A useful document.\n",
             **extra: Any) -> bytes:
    return json.dumps({"operation": "write_text", "artifact": artifact,
                       "content": content, **extra}, ensure_ascii=False).encode()


def policy(tmp_path: Path, **kwargs: Any) -> WorkspacePolicy:
    return WorkspacePolicy(tmp_path, (("draft", "draft.md"), ("notes", "notes.txt")), **kwargs)


def config_file(tmp_path: Path, **kwargs: Any) -> Path:
    config = tmp_path / "policy.json"
    config.write_text(json.dumps({"schema_version": "ash.workspace-write.v1",
                                  "output_dir": ".", "outputs": {"draft": "draft.md"},
                                  **kwargs}), encoding="utf-8")
    return config


def test_real_text_not_fixture_counts_and_no_raw_receipts(tmp_path: Path) -> None:
    text = "# Итог\nОбычный текст приложения, а не два счётчика.\n"
    config = policy(tmp_path)
    with GuardedWorkspace(config) as workspace:
        assert list(tmp_path.iterdir()) == []
        result = workspace.submit(proposal(content=text))
    assert result["applied"] and result["receipt_complete"]
    assert result["decision"]["disposition"] == "allow"
    assert (tmp_path / "draft.md").read_bytes() == text.encode()
    assert text not in json.dumps(result, ensure_ascii=False)
    receipts = list(tmp_path.glob(".ash-*.json"))
    assert len(receipts) == 2
    assert all(text not in path.read_text(encoding="utf-8") for path in receipts)
    verified = verify_workspace_output(config, tmp_path / result["receipt"])
    assert verified["integrity_ok"]
    assert not verified["meaning_checked"] and not verified["origin_authenticated"]


@pytest.mark.parametrize("raw", [
    b"not json", b"[]", b"{}", proposal("../outside"), proposal("C:outside"),
    proposal(authority="owner"), proposal(path="outside.txt"), proposal(content=""),
    proposal(content="x\x00y"), b'{"operation":"write_text","operation":"write_text"}',
    b'{"operation":"write_text","artifact":"draft","content":"\\ud800"}',
])
def test_malformed_or_authority_payload_cannot_write(tmp_path: Path, raw: bytes) -> None:
    with GuardedWorkspace(policy(tmp_path)) as workspace:
        result = workspace.submit(raw)
        assert not result["applied"] and result["reason"] == "proposal_rejected"
        assert result["receipt_complete"]
    assert not (tmp_path / "draft.md").exists()
    assert not (tmp_path / "notes.txt").exists()


def test_unknown_alias_is_guard_denied_then_valid_proposal_works(tmp_path: Path) -> None:
    protected = tmp_path / "protected.txt"
    protected.write_bytes(b"owner data")
    with GuardedWorkspace(policy(tmp_path)) as workspace:
        result = workspace.submit(proposal("protected", "overwrite"))
        assert result["reason"] == "guard_rejected"
        assert result["decision"]["disposition"] == "block"
        assert workspace.submit(proposal())["applied"]
    assert protected.read_bytes() == b"owner data"


def test_guard_denial_precedes_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = writer._decide

    def denied(config: WorkspacePolicy, alias: str, content: bytes,
               call_id: str, session_id: str) -> Any:
        return original(config, "forbidden", content, call_id, session_id)

    monkeypatch.setattr(writer, "_decide", denied)
    with GuardedWorkspace(policy(tmp_path)) as workspace:
        result = workspace.submit(proposal())
    assert result["reason"] == "guard_rejected"
    assert not (tmp_path / "draft.md").exists()


def test_existing_file_and_restart_cannot_overwrite(tmp_path: Path) -> None:
    config = policy(tmp_path)
    with GuardedWorkspace(config) as workspace:
        assert workspace.submit(proposal(content="first"))["applied"]
    with GuardedWorkspace(config) as workspace:
        result = workspace.submit(proposal(content="second"))
        assert not result["applied"]
        assert result["reason"] == "target_already_exists" and result["effect"] == "none"
        assert workspace.submit(proposal("notes"))["reason"] == "session_unavailable"
    assert (tmp_path / "draft.md").read_bytes() == b"first"


def test_byte_limit_budget_and_closed_state(tmp_path: Path) -> None:
    with GuardedWorkspace(policy(tmp_path, max_bytes=4, max_proposals=2)) as workspace:
        assert workspace.submit(proposal(content="12345"))["reason"] == "proposal_rejected"
        assert workspace.submit(proposal(content="four"))["applied"]
        assert workspace.submit(proposal("notes", "text"))["reason"] == "proposal_budget_exhausted"
    assert workspace.submit(proposal())["reason"] == "session_unavailable"


def test_interruption_after_effect_stops_session(tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    with GuardedWorkspace(policy(tmp_path)) as workspace:
        def interrupt(*args: Any) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(workspace._files, "readback_sha", interrupt)
        with pytest.raises(KeyboardInterrupt):
            workspace.submit(proposal())
        assert (tmp_path / "draft.md").exists()
        assert workspace.submit(proposal("notes"))["reason"] == "session_unavailable"
        assert not (tmp_path / "notes.txt").exists()


@pytest.mark.parametrize("phase", ["intent", "result"])
def test_receipt_error_is_terminal_and_reports_effect_honestly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    with GuardedWorkspace(policy(tmp_path)) as workspace:
        original = workspace._audit.write_once

        def fail(alias: str, content: bytes) -> Any:
            if alias.startswith(phase):
                raise OSError("private detail must not escape")
            return original(alias, content)

        monkeypatch.setattr(workspace._audit, "write_once", fail)
        result = workspace.submit(proposal())
        assert result["reason"] == f"{phase}_storage_unavailable"
        assert result["applied"] is (phase == "result")
        assert not result["receipt_complete"]
        assert "private detail" not in json.dumps(result)
        assert (tmp_path / "draft.md").exists() is (phase == "result")
        assert workspace.submit(proposal("notes"))["reason"] == "session_unavailable"


@pytest.mark.parametrize("damage", ["output", "intent", "decision", "policy"])
def test_verifier_rejects_mismatch(tmp_path: Path, damage: str) -> None:
    config = policy(tmp_path)
    with GuardedWorkspace(config) as workspace:
        result = workspace.submit(proposal())
    receipt = tmp_path / result["receipt"]
    if damage == "output":
        (tmp_path / "draft.md").write_text("altered", encoding="utf-8")
    elif damage == "intent":
        next(tmp_path.glob("*-intent.json")).write_text("{}", encoding="utf-8")
    elif damage == "decision":
        result["decision"]["evidence"]["content_sha256"] = "f" * 64
        receipt.write_text(json.dumps(result), encoding="utf-8")
    else:
        config = policy(tmp_path, max_bytes=200)
    assert not verify_workspace_output(config, receipt)["integrity_ok"]


def test_config_relative_to_file_not_cwd_and_check_no_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_file(tmp_path)
    monkeypatch.chdir(tmp_path.parent)
    loaded = WorkspacePolicy.load(config)
    assert loaded.output_dir == tmp_path
    before = set(tmp_path.iterdir())
    loaded.check()
    assert set(tmp_path.iterdir()) == before
    with pytest.raises(FrozenInstanceError):
        loaded.max_bytes = 10  # type: ignore[misc]


@pytest.mark.parametrize("update", [
    {"extra": True}, {"schema_version": "unknown"}, {"max_bytes": True},
    {"max_proposals": 0}, {"data_class": "secret"}, {"outputs": {"x": ".ash-evil.json"}},
    {"outputs": {"x": "../outside"}}, {"outputs": {"x": "C:ads"}},
])
def test_bad_host_configuration_fails_without_effect(tmp_path: Path,
                                                      update: dict[str, Any]) -> None:
    config = config_file(tmp_path, **update)
    with pytest.raises((ValueError, OSError)):
        WorkspacePolicy.load(config).check()
    assert list(tmp_path.iterdir()) == [config]


def test_installed_command_contract_check_submit_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_file(tmp_path)
    assert cli.main(["workspace-check", "--config", str(config)]) == 0
    assert json.loads(capsys.readouterr().out)["writes_performed"] is False
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(proposal())))
    assert cli.main(["workspace-write", "--config", str(config)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert cli.main(["workspace-verify", "--config", str(config), "--receipt",
                     str(tmp_path / result["receipt"])]) == 0
    assert json.loads(capsys.readouterr().out)["integrity_ok"]


def test_cli_diagnostics_do_not_print_private_inputs(tmp_path: Path,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    config = config_file(tmp_path, output_dir="missing-private-path")
    assert cli.main(["workspace-check", "--config", str(config)]) == 1
    out = capsys.readouterr().out
    assert json.loads(out)["reason"] == "workspace_configuration_or_input_unavailable"
    assert "missing-private-path" not in out and "Traceback" not in out


def test_parent_relative_config_has_stable_readback_identity(tmp_path: Path) -> None:
    configs = tmp_path / "config"
    configs.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    config = config_file(configs, output_dir="../output")
    loaded = WorkspacePolicy.load(config)
    assert loaded.output_dir == output
    with GuardedWorkspace(loaded) as workspace:
        result = workspace.submit(proposal())
    assert verify_workspace_output(loaded, output / result["receipt"])["integrity_ok"]


@pytest.mark.parametrize("execute", [False, True])
def test_existing_output_rejected_before_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], execute: bool,
) -> None:
    from agentic_security_harness import workspace_cli

    config = config_file(tmp_path)
    target = tmp_path / "draft.md"
    target.write_bytes(b"SYNTHETIC_EXISTING_CONTENT")

    def forbidden(*args: Any) -> None:
        pytest.fail("existing output must not spend a model call")

    monkeypatch.setattr(workspace_cli.ollama, "_post", forbidden)
    assert cli.main(["workspace-check", "--config", str(config)]) == 1
    checked = capsys.readouterr().out
    assert json.loads(checked) == {
        "applied": False, "effect": "none", "reason": "workspace_output_already_exists",
        "next_step": "inspect_existing_output_or_choose_new_destination",
    }
    args = ["workspace-run", "--config", str(config), "--input", str(target),
            "--task", "Summarize", "--artifact", "draft", "--model", "test-model"]
    assert cli.main(args + (["--execute"] if execute else [])) == 1
    output = capsys.readouterr().out
    assert json.loads(output) == json.loads(checked)
    assert str(target) not in output and "SYNTHETIC_EXISTING_CONTENT" not in output
    assert target.read_bytes() == b"SYNTHETIC_EXISTING_CONTENT"


def test_model_cannot_switch_to_other_allowed_artifact(tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    from agentic_security_harness import workspace_cli

    config = config_file(tmp_path, outputs={"draft": "draft.md", "notes": "notes.md"})
    source = tmp_path / "source.txt"
    source.write_text("Public source", encoding="utf-8")
    body = {"model": "test-model", "done": True, "done_reason": "stop",
            "response": proposal("notes").decode()}
    monkeypatch.setattr(workspace_cli.ollama, "_post",
                        lambda *_: (json.dumps(body).encode(), 200, "ok"))
    assert cli.main(["workspace-run", "--config", str(config), "--input", str(source),
                     "--task", "Summarize", "--artifact", "draft", "--model", "test-model",
                     "--execute"]) == 1
    assert not (tmp_path / "draft.md").exists()
    assert not (tmp_path / "notes.md").exists()


@pytest.mark.parametrize("execute", [False, True])
def test_local_model_path_is_explicit_one_call_and_actual_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
    execute: bool,
) -> None:
    from agentic_security_harness import workspace_cli

    config = config_file(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text("Public source text", encoding="utf-8")
    calls: list[bytes] = []

    def post(config: Any, request: bytes) -> Any:
        assert config.host == "127.0.0.1"
        calls.append(request)
        body = {"model": "test-model", "done": True, "done_reason": "stop",
                "response": proposal(content="Generated draft").decode()}
        return json.dumps(body).encode(), 200, "ok"

    monkeypatch.setattr(workspace_cli.ollama, "_post", post)
    args = ["workspace-run", "--config", str(config), "--input", str(source),
            "--task", "Summarize", "--artifact", "draft", "--model", "test-model"]
    assert cli.main(args + (["--execute"] if execute else [])) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(calls) == int(execute)
    assert result["applied"] is execute
    assert (tmp_path / "draft.md").exists() is execute
    if execute:
        assert (tmp_path / "draft.md").read_bytes() == b"Generated draft"
        assert cli.main(args + ["--execute"]) == 1
        refused = json.loads(capsys.readouterr().out)
        assert refused == {
            "applied": False, "effect": "none", "reason": "workspace_output_already_exists",
            "next_step": "inspect_existing_output_or_choose_new_destination",
        }
        assert len(calls) == 1
        assert (tmp_path / "draft.md").read_bytes() == b"Generated draft"


@pytest.mark.parametrize("outer", [
    {"model": "other", "done": True, "done_reason": "stop", "response": proposal().decode()},
    {"model": "test-model", "done": False, "done_reason": "length",
     "response": proposal().decode()},
    {"model": "test-model", "done": True, "done_reason": "stop", "response": "invalid"},
    {"model": "test-model", "done": True, "done_reason": "stop",
     "response": proposal("forbidden").decode()},
])
def test_untrusted_model_output_cannot_bypass_configured_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outer: dict[str, Any],
) -> None:
    from agentic_security_harness import workspace_cli

    config = config_file(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text("Public source", encoding="utf-8")
    monkeypatch.setattr(workspace_cli.ollama, "_post",
                        lambda *_: (json.dumps(outer).encode(), 200, "ok"))
    assert cli.main(["workspace-run", "--config", str(config), "--input", str(source),
                     "--task", "Summarize", "--artifact", "draft", "--model", "test-model",
                     "--execute"]) == 1
    assert not (tmp_path / "draft.md").exists()
