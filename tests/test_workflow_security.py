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


def _checkout_credentials_states(text: str) -> list[bool]:
    """Inspect checkout step mappings with one linear pass over workflow lines."""

    lines = text.splitlines()
    states: list[bool] = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith("uses: actions/checkout@"):
            continue
        uses_indent = len(line) - len(stripped)
        disabled = False
        for candidate in lines[index + 1 :]:
            candidate_stripped = candidate.lstrip()
            if not candidate_stripped:
                continue
            candidate_indent = len(candidate) - len(candidate_stripped)
            if candidate_indent < uses_indent or (
                candidate_indent == uses_indent and candidate_stripped.startswith("uses:")
            ):
                break
            if (
                candidate_indent > uses_indent
                and candidate_stripped == "persist-credentials: false"
            ):
                disabled = True
        states.append(disabled)
    return states


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
    for name, text in _workflow_texts().items():
        expected = text.count("uses: actions/checkout@")
        states = _checkout_credentials_states(text)
        assert len(states) == expected, name
        assert all(states), name
        checkout_steps += len(states)

    assert checkout_steps == 6


def test_checkout_contract_handles_large_malformed_step_without_regex_backtracking() -> None:
    malformed = (
        "      - name: Synthetic checkout\n"
        f"        uses: actions/checkout@{'a' * 40}\n"
        "        with:\n"
        + ("          \n" * 20_000)
        + "      - run: echo omitted\n"
    )

    assert _checkout_credentials_states(malformed) == [False]
