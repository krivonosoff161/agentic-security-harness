"""Context-specific Markdown encoders for untrusted artifact text.

Integrity and secret redaction do not make text safe to interpolate into CommonMark.
These helpers keep prose to one line, use safe code-span delimiters, escape GFM table
separators, and choose a fence longer than any content fence.
"""

from __future__ import annotations

import re
import unicodedata

from agentic_security_harness.safe_io import redact_artifact_text

_PROSE_META = re.compile(r"([\\`*[\]<!&])")
_ACTIVE_UNDERSCORE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")
_BACKTICK_RUN = re.compile(r"`+")


def _neutralize_controls(text: str) -> str:
    """Expose non-layout controls instead of persisting invisible active text."""

    rendered: list[str] = []
    for char in text:
        codepoint = ord(char)
        if char in {"\n", "\r", "\t"}:
            rendered.append(char)
        elif codepoint < 32 or 127 <= codepoint <= 159:
            rendered.append(f"\\x{codepoint:02x}")
        elif unicodedata.category(char) == "Cf":
            width = 4 if codepoint <= 0xFFFF else 8
            marker = "u" if width == 4 else "U"
            rendered.append(f"\\{marker}{codepoint:0{width}x}")
        else:
            rendered.append(char)
    return "".join(rendered)


def _visible_text(value: object, *, one_line: bool) -> str:
    text = redact_artifact_text("" if value is None else str(value))
    text = _neutralize_controls(text)
    if one_line:
        return " ".join(text.split())
    return text.replace("\r\n", "\n").replace("\r", "\n")


def markdown_prose(value: object) -> str:
    """Return inert one-line CommonMark prose."""

    escaped = _PROSE_META.sub(r"\\\1", _visible_text(value, one_line=True))
    return _ACTIVE_UNDERSCORE.sub(lambda match: "\\" + match.group(), escaped)


def markdown_table_cell(value: object) -> str:
    """Return inert one-line GFM table-cell text."""

    return markdown_prose(value).replace("|", r"\|")


def markdown_code_span(value: object) -> str:
    """Return a code span with a delimiter longer than any content backtick run."""

    text = _visible_text(value, one_line=True)
    longest = max((len(match.group()) for match in _BACKTICK_RUN.finditer(text)), default=0)
    fence = "`" * max(longest + 1, 1)
    if longest:
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def markdown_fenced_block(value: object, *, language: str = "") -> list[str]:
    """Return a fenced block whose closing delimiter cannot occur in its content."""

    text = _visible_text(value, one_line=False)
    longest = max((len(match.group()) for match in _BACKTICK_RUN.finditer(text)), default=0)
    fence = "`" * max(longest + 1, 3)
    safe_language = re.sub(r"[^A-Za-z0-9_-]", "", language)
    return [f"{fence}{safe_language}", *text.split("\n"), fence]
