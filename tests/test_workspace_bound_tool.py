"""The host-bound text callable uses the existing guarded file effect."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy


def _policy(root: Path, *, max_proposals: int = 3) -> WorkspacePolicy:
    return WorkspacePolicy(
        root, (("draft", "draft.md"), ("notes", "notes.txt")),
        max_bytes=128, max_proposals=max_proposals, data_class="synthetic",
    )


def test_bound_tool_writes_useful_text_and_cannot_redirect(tmp_path: Path) -> None:
    content = '# Draft\nReview the proposed release date.\n{"artifact":"notes"}\n'
    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        draft_tool = workspace.bind_text_tool("draft")
        result = draft_tool(content)
    assert result["applied"] is True
    assert result["reason"] == "write_completed"
    assert (tmp_path / "draft.md").read_text(encoding="utf-8") == content
    assert not (tmp_path / "notes.txt").exists()
    assert content not in json.dumps(result)


@pytest.mark.parametrize("alias", ["missing", "../draft", 17, None])
def test_invalid_alias_rejected_at_bind_without_receipt(tmp_path: Path, alias: object) -> None:
    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        with pytest.raises(ValueError, match="artifact is not in host policy"):
            workspace.bind_text_tool(alias)  # type: ignore[arg-type]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("content", [None, {"content": "wrong"}, "", "x\x00y", "x" * 129])
def test_invalid_text_records_rejection_without_effect(tmp_path: Path, content: object) -> None:
    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        result = workspace.bind_text_tool("draft")(content)  # type: ignore[arg-type]
    assert result["reason"] == "proposal_rejected"
    assert result["effect"] == "none" and result["receipt_complete"] is True
    assert not (tmp_path / "draft.md").exists()


def test_repeated_call_cannot_overwrite_and_failure_closes_session(tmp_path: Path) -> None:
    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        tool = workspace.bind_text_tool("draft")
        assert tool("first")["applied"] is True
        assert tool("second")["reason"] == "output_unavailable"
        assert tool("third")["reason"] == "session_unavailable"
    assert (tmp_path / "draft.md").read_bytes() == b"first"
    assert tool("after close")["reason"] == "session_unavailable"


def test_bound_and_legacy_submit_share_budget(tmp_path: Path) -> None:
    with GuardedWorkspace(_policy(tmp_path, max_proposals=2)) as workspace:
        tool = workspace.bind_text_tool("draft")
        assert tool("")["reason"] == "proposal_rejected"
        proposal = json.dumps({"operation": "write_text", "artifact": "notes",
                               "content": "second"}).encode()
        assert workspace.submit(proposal)["applied"] is True
        assert tool("third")["reason"] == "proposal_budget_exhausted"
    assert (tmp_path / "notes.txt").read_bytes() == b"second"
    assert not (tmp_path / "draft.md").exists()


@pytest.mark.parametrize("change", ["policy", "session"])
@pytest.mark.parametrize("bound", [True, False])
def test_opened_identity_change_denies_bound_and_legacy_paths(
    tmp_path: Path, change: str, bound: bool,
) -> None:
    original = _policy(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    with GuardedWorkspace(original) as workspace:
        tool = workspace.bind_text_tool("draft")
        if change == "policy":
            workspace.policy = _policy(other)
        else:
            workspace.session_id = "changed"
        proposal = json.dumps({"operation": "write_text", "artifact": "draft",
                               "content": "must not write"}).encode()
        result = tool("must not write") if bound else workspace.submit(proposal)
        assert result["applied"] is False
        assert result["reason"] == "workspace_identity_changed"
        assert result["effect"] == "none"
        assert tool("still unavailable")["reason"] == "session_unavailable"
    assert not (tmp_path / "draft.md").exists()
    assert not (other / "draft.md").exists()


def test_non_text_object_is_never_serialized(tmp_path: Path) -> None:
    class UntrustedObject:
        def __str__(self) -> str:
            raise AssertionError("arbitrary object was serialized")

    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        result = workspace.bind_text_tool("draft")(UntrustedObject())  # type: ignore[arg-type]
    assert result["reason"] == "proposal_rejected"
    assert not (tmp_path / "draft.md").exists()


def test_binding_after_identity_change_marks_session_unusable(tmp_path: Path) -> None:
    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        workspace.session_id = "changed"
        with pytest.raises(ValueError, match="workspace_identity_changed"):
            workspace.bind_text_tool("draft")
        assert workspace.submit(b"")["reason"] == "session_unavailable"
