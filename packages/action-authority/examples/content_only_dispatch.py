"""Host-owned tool-call facade for one preconfigured ActionGate.

Register only the returned dispatch function and tool_descriptor() with a model
tool-call framework. The host creates, approves, and retains the gate separately.
This is not a sandbox for an agent allowed to run arbitrary Python in the host
process or to access its filesystem, keys, or configuration.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ash_action_authority import ActionGate

TOOL_NAME = "submit_approved_document"
_REFUSALS = frozenset(
    {
        "invalid_content",
        "object_changed",
        "already_consumed",
        "not_approved",
        "expired",
        "capacity",
    }
)


def tool_descriptor() -> dict[str, Any]:
    """Return a fresh, content-only JSON-schema descriptor, with no host data."""
    return {
        "name": TOOL_NAME,
        "description": "Submit the exact document text for a host-approved create-only action.",
        "parameters": {
            "type": "object",
            "properties": {"content": {"type": "string"}},
            "required": ["content"],
            "additionalProperties": False,
        },
    }


def make_dispatch(gate: ActionGate) -> Callable[[str, object], dict[str, str]]:
    """Bind host state privately; pass only dispatch to the model tool router.

    The host must own ``gate``, route only a parsed tool name and argument object,
    and perform recovery/readback itself for an uncertain result. Python objects
    are not an isolation boundary against arbitrary code in this process.
    """
    if not isinstance(gate, ActionGate):
        raise TypeError("host_gate_required")

    def dispatch(name: str, arguments: object) -> dict[str, str]:
        if type(name) is not str or name != TOOL_NAME:
            return {"outcome": "refused", "reason": "unknown_tool"}
        if (
            type(arguments) is not dict
            or set(arguments) != {"content"}
            or type(arguments["content"]) is not str
        ):
            return {"outcome": "refused", "reason": "invalid_arguments"}
        try:
            result = gate.submit(arguments["content"])
        except Exception:
            # A durable-storage failure can follow the file effect. Do not claim
            # that refusal or absence occurred; the host must recover/read back.
            return {"outcome": "uncertain", "reason": "host_recovery_required"}
        if type(result) is not dict:
            return {"outcome": "uncertain", "reason": "host_recovery_required"}
        if result.get("applied") is True and result.get("status") == "DELIVERED_RECEIPT":
            return {"outcome": "applied", "reason": "writer_receipt_recorded"}
        reason = result.get("reason")
        if result.get("applied") is False and type(reason) is str and reason in _REFUSALS:
            return {"outcome": "refused", "reason": reason}
        return {"outcome": "uncertain", "reason": "host_recovery_required"}

    return dispatch
