"""A closure record exists only for a fenced, unchanged writer instance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness._workspace_files import WorkspaceFiles
from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy


def _policy(root: Path) -> WorkspacePolicy:
    return WorkspacePolicy(root, (("draft", "draft.md"),), max_proposals=2,
                           data_class="synthetic")


def _proposal(alias: str = "draft", content: str = "Useful text.") -> bytes:
    return json.dumps({"operation": "write_text", "artifact": alias,
                       "content": content}).encode()


def test_before_close_refused_then_success_fenced_and_no_replay(tmp_path: Path) -> None:
    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        tool = workspace.bind_text_tool("draft")
        with pytest.raises(ValueError, match="not fenced"):
            workspace.closure_record()
        result = tool("Useful text.")
        assert result["applied"] is True
    record = workspace.closure_record()
    assert record == {
        "schema_version": "ash.workspace-session-closed.v1",
        "session_id": workspace._opened_session_id,
        "policy_sha256": workspace._opened_policy_sha256,
        "attempts": 1,
        "closed": True,
        "replay_allowed": False,
    }
    record["attempts"] = 99
    assert workspace.closure_record()["attempts"] == 1
    assert tool("second text")["reason"] == "session_unavailable"
    assert (tmp_path / "draft.md").read_bytes() == b"Useful text."
    workspace.close()
    assert workspace.closure_record()["attempts"] == 1


def test_denial_and_handled_submit_error_can_still_close(tmp_path: Path) -> None:
    denied_root = tmp_path / "denied"
    denied_root.mkdir()
    with GuardedWorkspace(_policy(denied_root)) as denied:
        outcome = denied.submit(_proposal("unconfigured"))
        assert outcome["reason"] == "guard_rejected"
    assert denied.closure_record()["attempts"] == 1
    assert not (denied_root / "draft.md").exists()

    error_root = tmp_path / "error"
    error_root.mkdir()
    with GuardedWorkspace(_policy(error_root)) as failed:
        def unavailable(_alias: str, _content: bytes) -> Any:
            raise OSError("synthetic write failure")

        failed._files.write_once = unavailable  # type: ignore[assignment]
        outcome = failed.submit(_proposal())
        assert outcome["reason"] == "output_unavailable"
        assert outcome["applied"] is False
    assert failed.closure_record()["attempts"] == 1
    assert not (error_root / "draft.md").exists()


@pytest.mark.parametrize("which", ["files", "audit"])
def test_close_failure_never_gets_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str,
) -> None:
    workspace = GuardedWorkspace(_policy(tmp_path))
    target = workspace._files if which == "files" else workspace._audit
    original_close = WorkspaceFiles.close

    def close_then_fail(instance: WorkspaceFiles) -> None:
        original_close(instance)
        if instance is target:
            raise OSError("synthetic close failure")

    monkeypatch.setattr(WorkspaceFiles, "close", close_then_fail)
    with pytest.raises(OSError, match="synthetic close failure"):
        workspace.close()
    assert workspace._closed is True
    assert workspace._fenced is False
    assert workspace._files._closed is True
    assert workspace._audit._closed is True
    with pytest.raises(ValueError, match="not fenced"):
        workspace.closure_record()
    assert workspace.submit(_proposal())["reason"] == "session_unavailable"


@pytest.mark.parametrize("change", ["policy", "session"])
def test_closed_identity_drift_refuses_record(tmp_path: Path, change: str) -> None:
    workspace = GuardedWorkspace(_policy(tmp_path))
    workspace.close()
    assert workspace.closure_record()["attempts"] == 0
    if change == "policy":
        other = tmp_path / "other"
        other.mkdir()
        workspace.policy = _policy(other)
    else:
        workspace.session_id = "different"
    with pytest.raises(ValueError, match="not fenced"):
        workspace.closure_record()


def test_attempt_count_must_remain_exact_integer(tmp_path: Path) -> None:
    workspace = GuardedWorkspace(_policy(tmp_path))
    workspace.close()
    workspace._attempts = True
    with pytest.raises(ValueError, match="not fenced"):
        workspace.closure_record()
