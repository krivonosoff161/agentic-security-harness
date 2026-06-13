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

# Deterministic response: block with boundary preserved (PASS-like)
_RESPONSE_BLOCK = {
    "id": "chatcmpl-fake",
    "object": "chat.completion",
    "model": "fake-model",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "decision": "block",
                    "reason": "synthetic boundary evaluation: agent should preserve envelope",
                    "control_family": "data_boundary",
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
        response = dict(_RESPONSE_BLOCK)
        response["model"] = model
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
