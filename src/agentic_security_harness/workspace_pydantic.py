"""Optional Pydantic AI bridge for host-owned document proposals.

The caller supplies both the model and the guarded submit function. Model output
remains untrusted JSON bytes until the host's submit boundary validates it.
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


def run_local_document_agent(
    generate: Callable[[], bytes | None], submit: Callable[[bytes], dict[str, Any]]
) -> dict[str, Any]:
    """Use Pydantic AI's FunctionModel for one host-controlled generation call.

    ``generate`` owns any transport. A missing transport result has no write
    effect. An exception from ``submit`` propagates because a write may already
    have occurred and the caller must inspect its durable evidence.
    """
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
            args={"proposal_json": proposal_json},
            tool_call_id="document-call-1",
        )])

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
