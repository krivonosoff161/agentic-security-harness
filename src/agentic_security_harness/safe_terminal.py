"""Terminal-output hardening for untrusted report and adapter text."""

from __future__ import annotations

import unicodedata
from typing import TextIO


def terminal_text(value: object) -> str:
    """Make terminal controls visible while preserving ordinary line breaks."""

    rendered: list[str] = []
    for char in str(value):
        codepoint = ord(char)
        if char == "\n":
            rendered.append(char)
        elif codepoint < 32 or 127 <= codepoint <= 159:
            rendered.append(f"\\x{codepoint:02x}")
        elif unicodedata.category(char) == "Cf":
            rendered.append(f"\\u{codepoint:04x}")
        else:
            rendered.append(char)
    return "".join(rendered)


def terminal_field(value: object) -> str:
    """Neutralize controls and embedded line breaks in one scalar CLI field."""

    return terminal_text(value).replace("\n", r"\n")


class SafeTerminalStream:
    """Text-stream proxy that neutralizes ANSI/OSC and format controls."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, value: str) -> int:
        self._stream.write(terminal_text(value))
        return len(value)

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)
