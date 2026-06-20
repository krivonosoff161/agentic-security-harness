"""Fake local OpenAI-compatible server for demo/testing.

Start with:
    python examples/fake_openai_server.py

Then run:
    ash run-external --adapter openai-compatible \
      --base-url http://127.0.0.1:8766/v1 \
      --model fake-model \
      --scenario data-boundary \
      --out reports/external-demo

This server returns deterministic responses. No real model, no network beyond localhost.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

_HOST = "127.0.0.1"
_PORT = 8766
_FALLBACK_FAMILY_MAP = {
    "indirect_prompt_injection_via_tool_output": "provenance",
    "data_boundary_recipient_confusion": "data_boundary",
    "memory_poisoning_sanitized": "memory_governance",
    "data_boundary_classification_mutation": "data_boundary",
    "data_boundary_handoff_label_stripping": "data_boundary",
    "tool_permission_abuse_sanitized": "tool_selection",
    "provider_boundary_leakage_sanitized": "provider_boundary",
    "data_boundary_missing_envelope_recovery": "data_boundary",
    "data_boundary_memory_envelope_drift": "data_boundary",
    "sleeping_prompt.delayed_activation": "memory_governance",
    "audit.spam_label_abuse": "audit_completeness",
    "budget.loop_abuse": "budget_control",
    "capability.delegation_chain_drift": "capability_control",
    "mcp.tool_schema_deception": "tool_selection",
    "audit.hash_chain_tamper": "audit_completeness",
    "perception_boundary.sensor_command_confusion": "perception_boundary",
    "ambient_authority.environmental_privilege_escalation": "capability_control",
    "approval_laundering.underjustified_confirmation": "approval_context",
    "memory_governance.unscoped_memory_persistence": "memory_governance",
    "memory_governance.environment_injected_poisoning": "memory_governance",
    "memory_governance.unintentional_cross_user": "memory_governance",
    "budget.recursive_execution_amplification": "budget_control",
    "mcp.tool_selection_manipulation": "tool_selection",
    "indirect_instruction.multi_turn_escalation": "provenance",
}

def _extract_pattern_id(request: dict) -> str:
    return _extract_prompt_field(request, "Pattern") or "unknown"


def _extract_control_family(request: dict) -> str:
    pattern_id = _extract_pattern_id(request)
    return _FALLBACK_FAMILY_MAP.get(
        pattern_id, _extract_prompt_field(request, "Category") or "data_boundary"
    )


def _extract_prompt_field(request: dict, field: str) -> str:
    messages = request.get("messages") or []
    prefix = f"{field}: "
    for message in messages:
        content = str(message.get("content", ""))
        for line in content.splitlines():
            if line.startswith(prefix):
                return line.split(prefix, 1)[1].strip()
    return ""


def _response_block(model: str, pattern_id: str, control_family: str) -> dict:
    """Deterministic response: block with boundary preserved (PASS-like)."""
    return {
    "id": "chatcmpl-fake",
    "object": "chat.completion",
    "model": model,
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "pattern_id": pattern_id,
                    "decision": "block",
                    "boundary_assertion": "preserve_boundary",
                    "reason": "synthetic boundary evaluation: agent should preserve envelope",
                    "control_family": control_family,
                    "would_preserve_boundary": True,
                }),
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


class FakeHandler(BaseHTTPRequestHandler):
    """Handles POST /v1/chat/completions with a deterministic response."""

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/v1/chat/completions":
            self._handle_chat()
        else:
            self._respond(404, {"error": f"unknown path: {self.path}"})

    def _handle_chat(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        model = request.get("model", "unknown")
        response = _response_block(
            model,
            _extract_pattern_id(request),
            _extract_control_family(request),
        )
        self._respond(200, response)

    def _respond(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"[fake-server] {fmt % args}\n")


def main() -> None:
    server = HTTPServer((_HOST, _PORT), FakeHandler)
    print(f"Fake local OpenAI-compatible server running on http://{_HOST}:{_PORT}/v1")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
