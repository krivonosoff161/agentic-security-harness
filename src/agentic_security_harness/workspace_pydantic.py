"""Optional Pydantic AI bridges for host-owned document tools.

The caller supplies both the model and the guarded tool. Prefer the content-only
tool for a host-selected destination; the legacy proposal interface remains available.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def make_document_agent(model: Any, submit: Callable[[bytes], dict[str, Any]]) -> Any:
    """Create one-tool agent without selecting a provider or importing it eagerly."""
    from pydantic_ai import Agent

    agent = Agent(model, retries=0, capabilities=[])
    agent.instrument = False

    @agent.tool_plain
    def write_document(proposal_json: str) -> dict[str, Any]:
        return submit(proposal_json.encode("utf-8"))

    return agent


def make_text_document_agent(model: Any, write_text: Callable[[str], dict[str, Any]]) -> Any:
    """Expose only document content; the host callback owns destination and policy.

    Pass ``writer.bind_text_tool(alias)`` rather than an unrestricted file writer.
    This factory selects no provider and imports the optional framework lazily.
    """
    from pydantic_ai import Agent

    agent = Agent(model, retries=0, capabilities=[])
    agent.instrument = False

    @agent.tool_plain
    def write_document(content: str) -> dict[str, Any]:
        return write_text(content)

    return agent


def run_local_document_agent(
    generate: Callable[[], bytes | None], submit: Callable[[bytes], dict[str, Any]]
) -> dict[str, Any]:
    """Use Pydantic AI's FunctionModel for one host-controlled generation call.

    ``generate`` owns any transport. A missing transport result has no write
    effect. An exception from ``submit`` propagates because a write may already
    have occurred and the caller must inspect its durable evidence.
    """
    return _run_local_document_agent(generate, submit, content_only=False)


def run_local_text_document_agent(
    generate: Callable[[], bytes | None], write_text: Callable[[str], dict[str, Any]]
) -> dict[str, Any]:
    """Deliver one UTF-8 generation through a host-bound content-only tool.

    Text that looks like a tool envelope remains text. No destination or authority
    is extracted from it. Submit exceptions propagate without generation replay.
    """
    def submit(raw: bytes) -> dict[str, Any]:
        return write_text(raw.decode("utf-8"))

    return _run_local_document_agent(generate, submit, content_only=True)


def _run_local_document_agent(
    generate: Callable[[], bytes | None], submit: Callable[[bytes], dict[str, Any]], *,
    content_only: bool,
) -> dict[str, Any]:
    from pydantic_ai import models
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import UsageLimits

    decision: dict[str, Any] | None = None
    calls = 0
    transport_unavailable = False

    def guarded_submit(raw: bytes) -> dict[str, Any]:
        nonlocal decision
        decision = submit(raw)
        return decision

    async def supplied_model(messages: Any, info: Any) -> ModelResponse:
        nonlocal calls, transport_unavailable
        if any(isinstance(part, ToolReturnPart) for message in messages for part in message.parts):
            return ModelResponse(parts=[TextPart(content="Document decision recorded.")])
        if calls:
            raise RuntimeError("document generator cannot be retried")
        calls += 1
        raw = generate()
        if raw is None:
            transport_unavailable = True
            return ModelResponse(parts=[TextPart(content="Document proposal unavailable.")])
        if type(raw) is not bytes:
            raise TypeError("document generator must return bytes or None")
        proposal_json = raw.decode("utf-8")
        return ModelResponse(parts=[ToolCallPart(
            tool_name="write_document",
            args={"content" if content_only else "proposal_json": proposal_json},
            tool_call_id="document-call-1",
        )])

    if content_only:
        agent = make_text_document_agent(
            FunctionModel(supplied_model), lambda text: guarded_submit(text.encode("utf-8")),
        )
    else:
        agent = make_document_agent(FunctionModel(supplied_model), guarded_submit)
    with models.override_allow_model_requests(False):
        result = agent.run_sync(
            "Submit the host-supplied document proposal.",
            usage_limits=UsageLimits(request_limit=2, tool_calls_limit=1),
        )
    return {
        "decision": decision,
        "framework_requests": result.usage.requests,
        "transport_unavailable": transport_unavailable,
    }
