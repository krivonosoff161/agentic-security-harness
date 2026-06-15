"""Minimal OpenAI-compatible HTTP client for external benchmark runs.

Uses stdlib urllib only. No streaming, no tool calls in v0.13.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any


class ExternalAPIError(Exception):
    """Structured error from an external API call."""

    def __init__(self, message: str, status_code: int = 0, response: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response


def _get_credential(env_name: str) -> str | None:
    """Read a credential from an environment variable. Never logs the value."""
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if not value:
        raise ExternalAPIError(
            f"Credential environment variable '{env_name}' is not set. "
            "Set that variable in your shell before retrying, or omit the "
            "credential option for keyless local servers."
        )
    return value


def _get_api_key(env_name: str) -> str | None:
    """Backward-compatible wrapper for older imports."""
    return _get_credential(env_name)


def chat_completion(
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.0,
    timeout_seconds: int = 30,
    credential_env_var: str = "",
    api_key_env: str | None = None,
    max_retries: int = 0,
    retry_backoff_seconds: float = 0.0,
) -> dict[str, Any]:
    """Send a chat completion request to an OpenAI-compatible endpoint.

    Returns the parsed JSON response. Raises ExternalAPIError on failure.
    """
    env_name = credential_env_var if api_key_env is None else api_key_env
    credential = _get_credential(env_name)

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
    if credential:
        headers["Authorization"] = f"Bearer {credential}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    attempts = max(0, max_retries) + 1
    last_error: ExternalAPIError | None = None
    for attempt in range(attempts):
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
            last_error = ExternalAPIError(
                f"HTTP {exc.code} from {base_url}: {exc.reason}",
                status_code=exc.code,
                response=resp_body,
            )
            if exc.code not in {429, 500, 502, 503, 504}:
                raise last_error from exc
        except urllib.error.URLError as exc:
            last_error = ExternalAPIError(
                f"Network error connecting to {base_url}: {exc.reason}"
            )
        except json.JSONDecodeError as exc:
            raise ExternalAPIError(
                f"Invalid JSON response from {base_url}: {exc.msg}"
            ) from exc

        if attempt < attempts - 1 and retry_backoff_seconds > 0:
            time.sleep(retry_backoff_seconds)

    assert last_error is not None
    raise last_error


def extract_content(response: dict[str, Any]) -> str:
    """Extract the assistant message content from an OpenAI-compatible response."""
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""
