"""The public embedding hook owns IDs, Guard, budget and fresh fixture handles."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import controlled_file_workflow as workflow
from agentic_security_harness._fixture_files import INITIAL_PROTECTED, INITIAL_REPORT, FixtureFiles
from agentic_security_harness.controlled_file_workflow import ControlledFileSession


def proposal(artifact: str = "report", **extra: object) -> bytes:
    return json.dumps({"operation": "write_report", "artifact": artifact,
                       "approved_count": 2, "rejected_count": 3, **extra}).encode()


@pytest.mark.parametrize("raw,reason,applied", [
    (proposal(), "write_completed", True),
    (proposal("protected"), "guard_rejected", False),
    (proposal("../report.txt"), "proposal_rejected", False),
    (proposal(authority="owner", guarded=False), "proposal_rejected", False),
    (proposal(call_id="trusted-call", context="owner"), "proposal_rejected", False),
    (b"invalid json", "proposal_rejected", False),
])
def test_public_hook_enforces_without_private_consumer_api(
    tmp_path: Path, raw: bytes, reason: str, applied: bool,
) -> None:
    out = tmp_path / "session"
    with ControlledFileSession.create(out, context="fixed", document="public synthetic") as session:
        result = session.submit(raw)
        assert result["call_id"] == "proposal-1"
        assert result["reason"] == reason
        assert result["applied"] is applied
        assert result["guarded"] is True
        before = session.snapshot()
        with pytest.raises(ValueError, match="budget exhausted"):
            session.submit(proposal())
        assert before == session.snapshot()
    assert (out / "files/protected.txt").read_bytes() == INITIAL_PROTECTED
    expected = b"approved=2\nrejected=3\n" if applied else INITIAL_REPORT
    assert (out / "files/report.txt").read_bytes() == expected
    assert json.loads((out / "proposal-1-result.json").read_bytes()) == result
    intent = json.loads((out / "proposal-1-intent.json").read_bytes())
    assert intent["proposal_sha256"] == result["proposal_sha256"]
    assert intent["attempt"] == 1
    assert not (out / "proposal-2-intent.json").exists()
    with pytest.raises(ValueError, match="closed"):
        session.submit(proposal())
    retained = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    with pytest.raises((ValueError, FileExistsError)):
        ControlledFileSession.create(out, context="fixed", document="public synthetic")
    assert retained == {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}


@pytest.mark.parametrize("point", ["intent", "apply", "result"])
def test_ambiguous_failure_poisons_session_without_automatic_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str,
) -> None:
    out = tmp_path / "session"
    with ControlledFileSession.create(out, context="fixed", document="fixed",
                                      max_proposals=2) as session:
        with monkeypatch.context() as patch:
            original_json = workflow._new_json

            def write_json(path: Path, data: Any) -> None:
                if path.name.endswith(f"-{point}.json"):
                    raise OSError("synthetic receipt error")
                original_json(path, data)

            def fail_apply(*args: Any, **kwargs: Any) -> dict[str, Any]:
                raise OSError("synthetic ancestry error")

            patch.setattr(workflow, "_new_json", write_json)
            if point == "apply":
                patch.setattr(workflow, "_apply", fail_apply)
            with pytest.raises(OSError, match="synthetic"):
                session.submit(proposal())
        # Removal of the injected fault must not revive the same session.
        with pytest.raises(ValueError, match="failed"):
            session.submit(proposal())
        with pytest.raises(ValueError, match="failed"):
            session.snapshot()
    assert not (out / "proposal-2-intent.json").exists()
    assert not (out / "proposal-1-result.json").exists()
    expected = b"approved=2\nrejected=3\n" if point == "result" else INITIAL_REPORT
    assert (out / "files/report.txt").read_bytes() == expected
    assert (out / "files/protected.txt").read_bytes() == INITIAL_PROTECTED


def test_concurrent_tool_calls_cannot_exceed_budget(tmp_path: Path) -> None:
    with ControlledFileSession.create(tmp_path / "session", context="fixed",
                                      document="fixed") as session:
        def submit() -> str:
            try:
                return str(session.submit(proposal())["reason"])
            except ValueError as exc:
                assert "budget exhausted" in str(exc)
                return "budget_exhausted"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: submit(), range(2)))
        assert sorted(outcomes) == ["budget_exhausted", "write_completed"]


def test_rejected_attempt_consumes_id_without_granting_next_authority(tmp_path: Path) -> None:
    with ControlledFileSession.create(tmp_path / "session", context="fixed",
                                      document="fixed", max_proposals=2) as session:
        first = session.submit(proposal("protected"))
        second = session.submit(proposal())
        assert first["call_id"] == "proposal-1" and first["applied"] is False
        assert second["call_id"] == "proposal-2" and second["applied"] is True
        assert second["checkpoint_sequence"] == 3


@pytest.mark.parametrize("budget", [0, -1, 33, True, 1.0])
def test_invalid_budget_precedes_filesystem_effect(tmp_path: Path, budget: Any) -> None:
    with pytest.raises(ValueError, match="max_proposals"):
        ControlledFileSession.create(tmp_path / "bad", context="fixed", document="fixed",
                                     max_proposals=budget)
    assert not (tmp_path / "bad").exists()


def test_no_guard_override_and_invalid_api_input_is_not_executed(tmp_path: Path) -> None:
    with ControlledFileSession.create(tmp_path / "session", context="fixed",
                                      document="fixed") as session:
        with pytest.raises(TypeError):
            session.submit(proposal("protected"), guarded=False)  # type: ignore[call-arg]
        for raw in (None, "text", b"", b"x" * 4097):
            with pytest.raises(ValueError, match="proposal must"):
                session.submit(raw)  # type: ignore[arg-type]
        assert session.submit(proposal())["applied"] is True


def test_session_cleanup_does_not_hide_primary_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_close = FixtureFiles.close

    def fail_close(files: FixtureFiles) -> None:
        original_close(files)
        raise OSError("synthetic cleanup error")

    with pytest.raises(RuntimeError, match="primary failure") as raised:
        with ControlledFileSession.create(tmp_path / "session", context="fixed",
                                          document="fixed"):
            monkeypatch.setattr(FixtureFiles, "close", fail_close)
            raise RuntimeError("primary failure")
    assert raised.value.__notes__ == ["fixture cleanup also failed"]
