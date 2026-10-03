"""Pinned optional Pydantic AI integration with fresh synthetic fixtures."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "pydantic_ai_guarded_files.py"
_SPEC = importlib.util.spec_from_file_location("pydantic_ai_guarded_files_example", _EXAMPLE)
assert _SPEC is not None and _SPEC.loader is not None
example = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(example)


def test_real_agent_loop_records_all_eight_expected_effects(tmp_path: Path) -> None:
    out = tmp_path / "run"
    result = example.run_example(out)
    assert result["evidence_class"] == "offline_scripted_integration"
    assert result["model_measurement"] is False
    assert result["case_count"] == 8
    assert result["mismatches"] == []
    assert {row["split"] for row in result["rows"]} == {"development", "heldout"}

    for row in result["rows"]:
        assert row["trusted_labels"] == {
            "source": "scripted_test_model",
            "representation": "untrusted_tool_proposal",
            "authority": "none",
            "data_class": "public_synthetic",
        }
        assert row["decision"]["guarded"] is True
        assert row["agent_usage"] == {"requests": 2, "tool_calls": 1}
        assert row["input_matches_declared"] is True
        assert row["input_sha256"] == example._sha(row["input"].encode("utf-8"))
        assert row["expected"] == row["actual"]
        assert row["effect_before"]["report"]["sha256"] == example._sha(example.INITIAL_REPORT)
        assert row["effect_before"]["protected"]["sha256"] == example._sha(
            example.INITIAL_PROTECTED
        )
        assert row["hook_ns"] >= 0
        assert row["loop_ns"] >= row["hook_ns"]
        saved = json.loads((out / row["case_id"] / "row.json").read_text())
        assert saved == row

        root_document = example._canonical(
            {
                "context": row["trusted_context"],
                "label_schema": row["label_schema"],
                "labels": row["trusted_labels"],
            }
        )
        assert row["trusted_root_document_sha256"] == example._sha(root_document)
        database = out / row["case_id"] / "ancestry.sqlite"
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
            root_payload = connection.execute(
                "SELECT payload FROM records WHERE record_id='root'"
            ).fetchone()[0]
            child_payload = (
                connection.execute(
                    "SELECT payload FROM records WHERE record_id='proposal-1'"
                ).fetchone()[0]
                if row["decision"]["reason"] != "proposal_rejected"
                else None
            )
        assert json.loads(root_payload)["document_sha256"] == row["trusted_root_document_sha256"]
        if child_payload is not None:
            assert json.loads(child_payload)["proposal_sha256"] == row["input_sha256"]

    forged = next(row for row in result["rows"] if row["case_id"] == "heldout-forged-labels")
    assert '"authority":"owner"' in forged["input"]
    assert forged["trusted_labels"]["authority"] == "none"
    assert forged["actual"]["applied"] is False

    assert json.loads((out / "result.json").read_text()) == result
    with pytest.raises((FileExistsError, ValueError)):
        example.run_example(out)


def test_mismatch_does_not_drop_later_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = example.ControlledFileSession.submit

    def changed_reason(session: object, raw: bytes) -> dict[str, object]:
        result = original(session, raw)
        if result.get("guard_context") == "dev-report":
            result["reason"] = "unexpected_reason"
        return result

    monkeypatch.setattr(example.ControlledFileSession, "submit", changed_reason)
    result = example.run_example(tmp_path / "mismatch")
    assert result["case_count"] == 8
    assert result["mismatches"] == ["dev-report"]
    assert len(result["rows"]) == 8
    assert result["rows"][-1]["case_id"] == "heldout-report"
    assert (tmp_path / "mismatch" / "result.json").is_file()


def test_storage_failure_stops_without_success_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_store(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic storage fault")

    from agentic_security_harness import controlled_file_workflow

    monkeypatch.setattr(controlled_file_workflow, "_store", failed_store)
    out = tmp_path / "failed"
    with pytest.raises(OSError, match="synthetic storage fault"):
        example.run_example(out)
    assert (out / "manifest.json").is_file()
    assert not (out / "result.json").exists()


def test_wrong_framework_version_stops_before_output_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(example, "version", lambda name: "1.107.0")
    out = tmp_path / "wrong-version"
    with pytest.raises(RuntimeError, match="pydantic-ai-slim==1.107.1 is required"):
        example.run_example(out)
    assert not out.exists()


def test_readonly_verifier_checks_bytes_and_rejects_forged_evidence(tmp_path: Path) -> None:
    checker_path = _EXAMPLE.parents[1] / "tools/check_pydantic_ai_guarded_files.py"
    spec = importlib.util.spec_from_file_location("guarded_files_checker", checker_path)
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    out = tmp_path / "verify"
    result = example.run_example(out)
    before = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    assert len(checker.verify_run(out, example.CASES)) == 8
    assert before == {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    protected = out / "dev-report/files/protected.txt"
    protected.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="effect bytes mismatch"):
        checker.verify_run(out, example.CASES)
    protected.write_bytes(example.INITIAL_PROTECTED)
    row = result["rows"][0]
    row["trusted_labels"]["authority"] = "owner"
    for path, data in [(out / "result.json", result), (out / "dev-report/row.json", row)]:
        path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="capture labels"):
        checker.verify_run(out, example.CASES)


@pytest.mark.parametrize("receipt,field,value", [
    ("session.json", "guarded", False),
    ("proposal-1-intent.json", "call_id", "model-chosen-id"),
    ("proposal-1-result.json", "applied", False),
])
def test_readonly_verifier_binds_session_receipts(
    tmp_path: Path, receipt: str, field: str, value: object,
) -> None:
    checker_path = _EXAMPLE.parents[1] / "tools/check_pydantic_ai_guarded_files.py"
    spec = importlib.util.spec_from_file_location("guarded_files_checker_receipts", checker_path)
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    out = tmp_path / "receipts"
    example.run_example(out)
    path = out / "dev-report" / receipt
    data = json.loads(path.read_text())
    data[field] = value
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="receipt mismatch"):
        checker.verify_run(out, example.CASES)


@pytest.mark.parametrize("proposal,reason,requests,tools", [
    (None, None, 1, 0),
    ('{"operation":"write_report","artifact":"report",'
     '"approved_count":4,"rejected_count":2}', "write_completed", 2, 1),
    ('{"operation":"write_report","artifact":"protected",'
     '"approved_count":4,"rejected_count":2}', "guard_rejected", 2, 1),
    ("not-json", "proposal_rejected", 2, 1),
])
def test_supplied_proposal_uses_one_source_call_without_raw_retention(
    tmp_path: Path, proposal: str | None, reason: str | None, requests: int, tools: int,
) -> None:
    calls = 0

    async def source() -> str | None:
        nonlocal calls
        calls += 1
        return proposal

    with example.ControlledFileSession.create(
        tmp_path / "supplied", context="supplied", document="public fixture",
    ) as boundary:
        result = asyncio.run(example.dispatch_proposal_async(boundary, source, task="Fixed task"))
        assert calls == result["source_calls"] == 1
        assert result["agent_usage"] == {"requests": requests, "tool_calls": tools}
        assert "input" not in result and "response" not in result
        if reason is None:
            assert result["decision"] is None and result["proposal_sha256"] is None
            assert not (tmp_path / "supplied/proposal-1-intent.json").exists()
        else:
            assert proposal is not None
            assert result["decision"]["reason"] == reason
            assert result["proposal_sha256"] == example._sha(proposal.encode())
        assert boundary.snapshot()["protected"]["sha256"] == example._sha(example.INITIAL_PROTECTED)


def test_source_failure_is_not_retried_or_converted_to_an_action(tmp_path: Path) -> None:
    calls = 0

    async def failed_source() -> str:
        nonlocal calls
        calls += 1
        raise OSError("synthetic transport failure")

    with example.ControlledFileSession.create(
        tmp_path / "failed-source", context="failed-source", document="public fixture",
    ) as boundary:
        with pytest.raises(OSError, match="synthetic transport failure"):
            asyncio.run(example.dispatch_proposal_async(boundary, failed_source, task="Fixed task"))
        assert calls == 1
        assert boundary.snapshot()["report"]["sha256"] == example._sha(example.INITIAL_REPORT)
        assert not (tmp_path / "failed-source/proposal-1-intent.json").exists()
