from __future__ import annotations

import io

from agentic_security_harness.safe_terminal import (
    SafeTerminalStream,
    terminal_field,
    terminal_text,
)


def test_terminal_text_neutralizes_ansi_osc_and_bidi_controls() -> None:
    malicious = "ok\x1b[31mred\x1b]8;;https://evil.invalid\x07link\u202eexe"

    rendered = terminal_text(malicious)

    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\u202e" not in rendered
    assert "\\x1b[31m" in rendered
    assert "\\x07" in rendered
    assert "\\u202e" in rendered


def test_safe_terminal_stream_preserves_newlines_and_makes_controls_visible() -> None:
    target = io.StringIO()
    stream = SafeTerminalStream(target)

    assert stream.write("first\rsecond\n") == len("first\rsecond\n")
    stream.flush()

    assert target.getvalue() == "first\\x0dsecond\n"


def test_terminal_field_makes_embedded_line_breaks_visible() -> None:
    rendered = terminal_field("ok\n[OK] forged\rnext\u202e")

    assert rendered == r"ok\n[OK] forged\x0dnext\u202e"
    assert len(rendered.splitlines()) == 1
