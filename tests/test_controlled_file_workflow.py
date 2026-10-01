"""Offline integration and adverse evidence checks for the controlled file workflow."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import agentic_security_harness.controlled_file_workflow as workflow
from agentic_security_harness._file_corpus import cases
from agentic_security_harness._fixture_files import INITIAL_PROTECTED, INITIAL_REPORT, FixtureFiles
from agentic_security_harness.ancestry_store import AncestryStore
from agentic_security_harness.controlled_file_verifier import verify_controlled_file_workflow


def _proposal(artifact: str = "report", approved: int = 1, rejected: int = 2) -> bytes:
    return workflow._canonical({
        "operation": "write_report", "artifact": artifact,
        "approved_count": approved, "rejected_count": rejected,
    })


def _outer(model: str, response: bytes, **changes: object) -> bytes:
    value = {"model": model, "response": response.decode(), "done": True,
             "done_reason": "stop", "prompt_eval_count": 3, "eval_count": 4}
    value.update(changes)
    return workflow._canonical(value)


def _local_area(tmp_path: Path) -> tuple[FixtureFiles, AncestryStore]:
    area = tmp_path / "case-local"
    area.mkdir()
    files = FixtureFiles.create(area / "files")
    return files, workflow._store(area, "case-local", "synthetic document")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(workflow._canonical(value) + b"\n")


def test_fresh_interpreter_import_has_no_network_or_child_process() -> None:
    root = Path(__file__).resolve().parents[1]
    script = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "src"))
FORBIDDEN = {"socket.__new__", "socket.connect", "subprocess.Popen",
             "os.system", "os.posix_spawn", "os.startfile"}
def reject_effect(event, args):
    if event in FORBIDDEN:
        raise RuntimeError("passive import attempted a forbidden effect: " + event)
sys.addaudithook(reject_effect)
import agentic_security_harness._fixture_files
import agentic_security_harness._file_policy
import agentic_security_harness.controlled_file_workflow
import agentic_security_harness.controlled_file_verifier
"""
    completed = subprocess.run(
        [sys.executable, "-c", script], cwd=root, capture_output=True, text=True,
        timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stderr[-1000:]


def test_offline_end_to_end_and_verifier_disk_fail_closed(tmp_path: Path) -> None:
    out = tmp_path / "run"
    result = workflow.run_controlled_file_workflow(out)
    verified = verify_controlled_file_workflow(out)
    assert verified["integrity_ok"] is True
    assert verified["causal_control_verified"] is True
    assert verified["accurate_reports"] == verified["applied_reports"] == 6
    assert verified["model_calls"] == result["model_calls"] == 0
    assert result["causal_controls"][0]["applied"] is False
    assert result["causal_controls"][1]["applied"] is True
    assert (out / "control-guarded" / "files" / "protected.txt").read_bytes() == INITIAL_PROTECTED
    assert (out / "control-ablated" / "files" / "protected.txt").read_bytes() == (
        b"approved=7\nrejected=9\n"
    )
    assert list(out.rglob("*response*")) == []
    with pytest.raises((FileExistsError, ValueError)):
        workflow.run_controlled_file_workflow(out)

    (out / "case-01" / "files" / "report.txt").write_bytes(b"changed\n")
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False
    (out / "case-01" / "files" / "report.txt").unlink()
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False


def test_verifier_rejects_changed_packaged_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = cases()
    altered = (
        replace(original[0], document=original[0].document + "\nUnregistered appendix."),
        *original[1:],
    )
    monkeypatch.setattr(workflow, "cases", lambda: altered)
    out = tmp_path / "changed-corpus"
    produced = workflow.run_controlled_file_workflow(out)
    assert produced["cases"][0]["report_exact"] is True
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False


@pytest.mark.parametrize("first_terminal", ["write_completed", "transport_rejected"])
def test_verifier_rejects_second_turn_after_terminal_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, first_terminal: str
) -> None:
    def fake_post(config: object, request: bytes) -> tuple[bytes | None, int | None, str]:
        sent = json.loads(request)
        matching = [case for case in cases() if case.document in sent["prompt"]]
        assert len(matching) == 1
        case = matching[0]
        if case.case_id == "case-06" and first_terminal == "transport_rejected":
            return None, None, "transport_unavailable"
        return (
            _outer(sent["model"], _proposal("report", case.approved, case.rejected)),
            200,
            "evaluated",
        )

    monkeypatch.setattr(workflow._ollama, "_post", fake_post)
    out = tmp_path / "model"
    produced = workflow.run_controlled_file_workflow(out, model="local-test")
    assert verify_controlled_file_workflow(out)["integrity_ok"] is True
    last = produced["cases"][-1]
    assert len(last["turns"]) == 1
    assert last["turns"][0]["reason"] == first_terminal

    extra = {"applied": False, "reason": "transport_rejected",
             "transport": {"transport_attempts": 1}}
    last["turns"].append(extra)
    produced["model_calls"] += 1
    area = out / "case-06"
    _write_json(area / "call-2-intent.json", {
        "attempt": 7, "prompt_sha256": "0" * 64, "status": "started",
    })
    _write_json(area / "call-2-result.json", extra)
    _write_json(out / "result.json", produced)
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False


@pytest.mark.parametrize("raw", [
    b"not JSON",
    b'{"operation":"write_report","artifact":"report","approved_count":true,"rejected_count":2}',
    b'{"operation":"write_report","artifact":"report","approved_count":1,"rejected_count":2,"extra":1}',
    b'{"operation":"write_report","artifact":"report","artifact":"protected","approved_count":1,"rejected_count":2}',
    b"{" + b" " * 4096 + b"}",
])
def test_malformed_proposals_have_no_effect(tmp_path: Path, raw: bytes) -> None:
    files, store = _local_area(tmp_path)
    with files:
        result = workflow._apply(files, store, raw, call_id="bad", context="case-local")
        assert result["applied"] is False
        assert result["reason"] == "proposal_rejected"
        assert (tmp_path / "case-local" / "files" / "report.txt").read_bytes() == INITIAL_REPORT
        assert (tmp_path / "case-local" / "files" / "protected.txt").read_bytes() == (
            INITIAL_PROTECTED
        )


def test_guard_rejects_protected_but_wrong_report_is_authorized(tmp_path: Path) -> None:
    files, store = _local_area(tmp_path)
    with files:
        protected = workflow._apply(
            files, store, _proposal("protected"), call_id="first", context="case-local"
        )
        assert protected["ancestry_verified"] is True
        assert protected["guard_disposition"] != "allow"
        assert protected["applied"] is False
        assert (tmp_path / "case-local" / "files" / "protected.txt").read_bytes() == (
            INITIAL_PROTECTED
        )

        wrong = workflow._apply(
            files, store, _proposal("report", 0, 0), call_id="second", context="case-local"
        )
        assert wrong["ancestry_verified"] is True
        assert wrong["guard_disposition"] == "allow"
        assert wrong["applied"] is True
        assert (tmp_path / "case-local" / "files" / "report.txt").read_bytes() == (
            b"approved=0\nrejected=0\n"
        )


def test_replay_and_tampered_ancestry_stop_before_effect(tmp_path: Path) -> None:
    files, store = _local_area(tmp_path)
    with files:
        first = workflow._apply(
            files, store, _proposal(), call_id="first", context="case-local"
        )
        assert first["applied"] is True
        with pytest.raises(ValueError):
            workflow._apply(files, store, _proposal(), call_id="first", context="case-local")
        before = (tmp_path / "case-local" / "files" / "report.txt").read_bytes()
        with sqlite3.connect(store.db_path) as connection:
            connection.execute(
                "UPDATE records SET payload = ? WHERE record_id = ?", (b"tampered", "first")
            )
        with pytest.raises(ValueError):
            workflow._apply(files, store, _proposal("report", 9, 9),
                            call_id="second", context="case-local")
        assert (tmp_path / "case-local" / "files" / "report.txt").read_bytes() == before


def test_fake_transport_two_turns_and_wrong_but_authorized_task_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    prompts = {case.case_id: case for case in cases()}

    def fake_post(config: object, request: bytes) -> tuple[bytes, int, str]:
        sent = json.loads(request)
        matching = [case for case in prompts.values() if case.document in sent["prompt"]]
        assert len(matching) == 1
        case = matching[0]
        turn = counts[case.case_id] = counts.get(case.case_id, 0) + 1
        if turn == 1:
            response = _proposal("protected", case.approved, case.rejected)
        else:
            approved = case.approved + (1 if case.case_id == "case-01" else 0)
            response = _proposal("report", approved, case.rejected)
        return _outer(sent["model"], response), 200, "evaluated"

    monkeypatch.setattr(workflow._ollama, "_post", fake_post)
    out = tmp_path / "model"
    result = workflow.run_controlled_file_workflow(out, model="local-test")
    checked = verify_controlled_file_workflow(out)
    assert counts == {case.case_id: 2 for case in cases()}
    assert result["model_calls"] == checked["model_calls"] == 12
    assert checked["integrity_ok"] is True
    assert checked["applied_reports"] == 6
    assert checked["accurate_reports"] == 5
    assert all(not row["turns"][0]["applied"] and row["turns"][1]["applied"]
               for row in result["cases"])
    assert sorted(path.name for path in (out / "case-01").glob("*-intent.json")) == [
        "call-1-intent.json", "call-2-intent.json"
    ]


@pytest.mark.parametrize("body,reason", [
    (None, "transport_unavailable"),
    (_outer("other-model", _proposal()), "outer_contract_rejected"),
    (_outer("local-test", _proposal(), done=False), "outer_contract_rejected"),
    (_outer("local-test", _proposal(), eval_count=True), "outer_contract_rejected"),
    (_outer("local-test", _proposal(), thinking="unexpected"), "outer_contract_rejected"),
])
def test_failed_incomplete_or_mismatched_outer_data(
    monkeypatch: pytest.MonkeyPatch, body: bytes | None, reason: str
) -> None:
    monkeypatch.setattr(workflow._ollama, "_post", lambda config, request: (body, 200, reason))
    config = workflow._ollama.OllamaQuarantineConfigV1()
    raw, metadata = workflow._model_proposal(config, "local-test", "synthetic prompt")
    assert raw is None
    assert metadata["transport_attempts"] == 1
    assert metadata["transport_reason"] == reason
