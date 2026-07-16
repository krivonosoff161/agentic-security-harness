from agentic_security_harness.safe_markdown import (
    markdown_code_span,
    markdown_fenced_block,
    markdown_prose,
    markdown_table_cell,
)


def test_markdown_prose_collapses_blocks_and_escapes_active_inline_markup() -> None:
    rendered = markdown_prose(
        "evidence\n\n## forged\n![probe](https://example.invalid/p)\n"
        "<img src=x>\x1b[31m\u202efake.exe"
    )

    assert "\n" not in rendered
    assert "![probe](" not in rendered
    assert r"\!\[probe\]" in rendered
    assert r"\<img" in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert r"\\x1b" in rendered
    assert r"\\u202e" in rendered


def test_markdown_code_span_uses_longer_backtick_delimiter() -> None:
    rendered = markdown_code_span("model`name``tail\nnext")

    assert rendered.startswith("``` ")
    assert rendered.endswith(" ```")
    assert "\n" not in rendered


def test_markdown_table_cell_escapes_pipe_and_link_syntax() -> None:
    rendered = markdown_table_cell("left|right [link](https://example.invalid)")

    assert r"\|" in rendered
    assert "[link](" not in rendered


def test_markdown_fenced_block_uses_fence_longer_than_content() -> None:
    lines = markdown_fenced_block("before\n```\nafter", language="bash<script>")

    assert lines[0] == "````bashscript"
    assert lines[-1] == "````"
    assert lines[1:-1] == ["before", "```", "after"]
