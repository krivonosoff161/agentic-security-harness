"""Repository-wide static security contract for GitHub Actions dependencies and checkout."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


def _workflow_texts() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOWS.glob("*.yml"))
    }


def test_every_external_action_reference_is_pinned_to_a_full_commit() -> None:
    references: list[tuple[str, str]] = []
    for name, text in _workflow_texts().items():
        references.extend(
            (name, reference)
            for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text)
        )

    assert references
    for name, reference in references:
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), (name, reference)


def test_every_checkout_disables_persisted_credentials() -> None:
    checkout_steps = 0
    pattern = re.compile(
        r"(?m)^\s*uses:\s*actions/checkout@[0-9a-f]{40}[^\n]*\n"
        r"\s*with:\n"
        r"(?:\s+[^\n]+\n)*?"
        r"\s+persist-credentials:\s*false\s*$"
    )
    for name, text in _workflow_texts().items():
        expected = text.count("uses: actions/checkout@")
        observed = len(pattern.findall(text))
        assert observed == expected, name
        checkout_steps += observed

    assert checkout_steps == 5
