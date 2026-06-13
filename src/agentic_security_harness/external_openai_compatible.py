"""Minimal OpenAI-compatible HTTP client for external benchmark runs.

Uses stdlib urllib only. No streaming, no tool calls in v0.13.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class ExternalAPIError(Exception):
    """Structured error from an external API call."""

    def __init__(self, message: str, status_code: int = 0, response: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response


def _get_api_key(env_name: str) -> str | None:
    """Read API key from environment variable. Never logs the value."""
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if not value:
        raise ExternalAPIError(
            f"API key environment variable '{env_name}' is not set. "
            f"Set it with: export {env_name}=your_key"
        )
    return value


def chat_completion(
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.0,
    timeout_seconds: int = 30,
    api_key_env: str = "",
) -> dict[str, Any]:
    """Send a chat completion request to an OpenAI-compatible endpoint.

    Returns the parsed JSON response. Raises ExternalAPIError on failure.
    """
    api_key = _get_api_key(api_key_env)

    url = base_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url = url + "/chat/completions"

    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        resp_body = ""
        try:
            resp_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise ExternalAPIError(
            f"HTTP {exc.code} from {base_url}: {exc.reason}",
            status_code=exc.code,
            response=resp_body,
        ) from exc
    except urllib.error.URLError as exc:
        raise ExternalAPIError(
            f"Network error connecting to {base_url}: {exc.reason}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ExternalAPIError(
            f"Invalid JSON response from {base_url}: {exc.msg}"
        ) from exc


def extract_content(response: dict[str, Any]) -> str:
    """Extract the assistant message content from an OpenAI-compatible response."""
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""
