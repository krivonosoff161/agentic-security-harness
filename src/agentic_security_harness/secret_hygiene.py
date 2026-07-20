"""Shared secret-shape detection and redaction for public artifacts.

The patterns here are intentionally conservative and format-anchored. They are a
defense-in-depth guard for common credential shapes, not a claim that every possible
secret can be recognized.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    label: str
    pattern: re.Pattern[str]
    replacement: str


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "sk-",
        re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"),
        "sk-[REDACTED]",
    ),
    SecretPattern(
        "AKIA",
        re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}"),
        "AKIA[REDACTED]",
    ),
    SecretPattern(
        "Google API key",
        re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}"),
        "AIza[REDACTED]",
    ),
    SecretPattern(
        "GitHub token",
        re.compile(
            r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"
            r"|(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}"
        ),
        "github_[REDACTED]",
    ),
    SecretPattern(
        "Slack token",
        re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z-]{20,}"),
        "xox[REDACTED]",
    ),
    SecretPattern(
        "Slack webhook",
        re.compile(
            r"https://hooks\.slack\.com/services/[A-Za-z0-9_-]{8,}/"
            r"[A-Za-z0-9_-]{8,}/[A-Za-z0-9_-]{16,}"
        ),
        "https://hooks.slack.com/services/[REDACTED]",
    ),
    SecretPattern(
        "JWT",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"
        ),
        "eyJ[REDACTED].[REDACTED].[REDACTED]",
    ),
    SecretPattern(
        "private key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "-----BEGIN REDACTED PRIVATE KEY-----\n[REDACTED]\n-----END REDACTED PRIVATE KEY-----",
    ),
    SecretPattern(
        "BEGIN PRIVATE KEY",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY"),
        "-----BEGIN REDACTED PRIVATE KEY",
    ),
    SecretPattern(
        "Authorization bearer",
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
        "Bearer [REDACTED]",
    ),
    SecretPattern(
        "credential URI",
        re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@[^/\s]+"),
        "[REDACTED_CREDENTIAL_URI]",
    ),
    SecretPattern(
        "generic secret assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}['\"]?"
        ),
        "[REDACTED_SECRET_ASSIGNMENT]",
    ),
    SecretPattern(
        "Stripe-style key",
        re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
        "sk_[REDACTED]",
    ),
    SecretPattern(
        "ASH-CANARY",
        re.compile(r"ASH-CANARY-[A-F0-9]{8,}-[A-F0-9]{8,}"),
        "ASH-CANARY-[REDACTED]",
    ),
    SecretPattern(
        "ASH-SEMDRIFT",
        re.compile(r"ASH-SEMDRIFT-[A-F0-9]{8,}-[A-F0-9]{8,}"),
        "ASH-SEMDRIFT-[REDACTED]",
    ),
    SecretPattern(
        "ASH-SEMPROP",
        re.compile(r"ASH-SEMPROP-[A-F0-9]{8,}-[A-F0-9]{8,}"),
        "ASH-SEMPROP-[REDACTED]",
    ),
)


def redact_secret_shapes(text: str) -> str:
    """Return text with supported secret-shaped substrings redacted."""

    redacted = text
    for entry in SECRET_PATTERNS:
        redacted = entry.pattern.sub(entry.replacement, redacted)
    return redacted
