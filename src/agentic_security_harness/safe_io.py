"""Safe artifact writing helpers.

Validation catches forbidden markers after artifacts exist. This module is the earlier
gate: artifact writers pass text through a conservative redactor before writing.
"""

from __future__ import annotations

import re
from pathlib import Path

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"), "sk-[REDACTED]"),
    (re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}"), "AKIA[REDACTED]"),
    (re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}"), "ghp_[REDACTED]"),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "-----BEGIN REDACTED PRIVATE KEY-----\n[REDACTED]\n-----END REDACTED PRIVATE KEY-----",
    ),
    (re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer [REDACTED]"),
]

_ENV_VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def redact_artifact_text(text: str) -> str:
    """Redact secret-shaped strings from artifact text before persistence."""
    redacted = text
    for pattern, replacement in _REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def safe_credential_env_var_name(value: object) -> str:
    """Return a safe credential env-var *name* for persisted metadata.

    The external path records the environment variable name that would hold a credential,
    never the credential value. If a caller accidentally passes a secret-shaped value or
    an invalid env-var label, persist a redacted/invalid marker instead of the raw string.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "[REDACTED]" in text:
        return text
    redacted = redact_artifact_text(text)
    if redacted != text:
        return redacted
    if not _ENV_VAR_NAME.fullmatch(text):
        return "[INVALID_CREDENTIAL_ENV_VAR_NAME]"
    return text


def write_text_artifact(path: Path, text: str) -> Path:
    """Write redacted UTF-8 LF text to an artifact path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = redact_artifact_text(text).replace("\r\n", "\n").replace("\r", "\n")
    # Central artifact sink: inputs are redacted above, then validated by artifact
    # contract tests. CodeQL cannot model this project-specific sanitizer.
    # codeql[py/clear-text-storage-sensitive-data]
    path.write_text(clean, encoding="utf-8", newline="\n")
    return path
