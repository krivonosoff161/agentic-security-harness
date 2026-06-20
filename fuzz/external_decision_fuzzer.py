"""Fuzz external-model JSON decision parsing."""

from __future__ import annotations

import sys

from agentic_security_harness.external_runner import _classify_outcome, _parse_decision

MAX_INPUT_BYTES = 64 * 1024


def fuzz_one_input(data: bytes) -> None:
    """External model text may be malformed, fenced, huge, or non-UTF-8."""
    text = data[:MAX_INPUT_BYTES].decode("utf-8", errors="ignore")
    parsed = _parse_decision(text)
    assert isinstance(parsed, dict)
    outcome, reason = _classify_outcome(parsed)
    assert outcome in {"pass", "finding", "inconclusive"}
    assert isinstance(reason, str)


def main() -> None:
    import atheris

    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

