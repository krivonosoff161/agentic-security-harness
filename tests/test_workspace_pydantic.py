"""Offline tests for the optional one-tool document bridge."""

from __future__ import annotations

import builtins
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy


@pytest.fixture(autouse=True)
def optional_framework(request: pytest.FixtureRequest) -> None:
    if request.node.name != "test_base_module_import_does_not_import_optional_framework":
        pytest.importorskip("pydantic_ai", reason="optional document-agent dependency")


def _proposal(artifact: str = "draft", content: str = "# Document\n", **extra: Any) -> bytes:
    return json.dumps({"operation": "write_text", "artifact": artifact,
                       "content": content, **extra}, ensure_ascii=False).encode("utf-8")


def _policy(path: Path) -> WorkspacePolicy:
    return WorkspacePolicy(path, (("draft", "draft.md"),), max_proposals=1)


@pytest.mark.parametrize(("raw", "reason", "created"), [
    (_proposal(), "write_completed", True),
    (_proposal("protected"), "guard_rejected", False),
    (b"invalid JSON", "proposal_rejected", False),
    (_proposal(authority="owner"), "proposal_rejected", False),
])
def test_local_framework_forwards_one_untrusted_proposal(
    tmp_path: Path, raw: bytes, reason: str, created: bool
) -> None:
    from agentic_security_harness.workspace_pydantic import run_local_document_agent

    generated = 0
    submitted = 0

    def generate() -> bytes:
        nonlocal generated
        generated += 1
        return raw

    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        def submit(value: bytes) -> dict[str, Any]:
            nonlocal submitted
            submitted += 1
            assert value == raw
            return workspace.submit(value)

        result = run_local_document_agent(generate, submit)

    assert generated == submitted == 1
    assert result["framework_requests"] == 2
    assert result["transport_unavailable"] is False
    assert result["decision"]["reason"] == reason
    assert result["decision"]["applied"] is created
    assert (tmp_path / "draft.md").exists() is created
    assert raw.decode("utf-8") not in json.dumps(result, ensure_ascii=False)


def test_no_transport_has_no_tool_call_or_effect(tmp_path: Path) -> None:
    from agentic_security_harness.workspace_pydantic import run_local_document_agent

    calls = 0

    def generate() -> None:
        nonlocal calls
        calls += 1
        return None

    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        result = run_local_document_agent(generate, workspace.submit)
    assert calls == 1
    assert result == {"decision": None, "framework_requests": 1,
                      "transport_unavailable": True}
    assert list(tmp_path.iterdir()) == []


def test_submit_fault_propagates_without_replay(tmp_path: Path) -> None:
    from agentic_security_harness.workspace_pydantic import run_local_document_agent

    generated = 0
    submitted = 0

    def generate() -> bytes:
        nonlocal generated
        generated += 1
        return _proposal()

    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        def submit(raw: bytes) -> dict[str, Any]:
            nonlocal submitted
            submitted += 1
            workspace.submit(raw)
            raise OSError("synthetic fault after write")

        with pytest.raises(OSError, match="synthetic fault after write"):
            run_local_document_agent(generate, submit)
    assert generated == submitted == 1
    assert (tmp_path / "draft.md").read_bytes() == b"# Document\n"


def test_factory_uses_host_selected_function_model(tmp_path: Path) -> None:
    from pydantic_ai import models
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import UsageLimits

    from agentic_security_harness.workspace_pydantic import make_document_agent

    async def model(messages: Any, info: Any) -> ModelResponse:
        if any(isinstance(part, ToolReturnPart) for message in messages for part in message.parts):
            return ModelResponse(parts=[TextPart(content="done")])
        return ModelResponse(parts=[ToolCallPart(tool_name="write_document",
            args={"proposal_json": _proposal().decode("utf-8")}, tool_call_id="one")])

    with GuardedWorkspace(_policy(tmp_path)) as workspace:
        agent = make_document_agent(FunctionModel(model), workspace.submit)
        with models.override_allow_model_requests(False):
            result = agent.run_sync("write", usage_limits=UsageLimits(
                request_limit=2, tool_calls_limit=1))
    assert result.usage.requests == 2
    assert (tmp_path / "draft.md").read_bytes() == b"# Document\n"


def test_base_module_import_does_not_import_optional_framework(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def reject_framework(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("pydantic_ai"):
            raise AssertionError("optional framework imported by base module")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_framework)
    sys.modules.pop("agentic_security_harness.workspace_pydantic", None)
    __import__("agentic_security_harness.workspace_pydantic")
