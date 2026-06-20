"""Fuzz benchmark artifact validation entry points."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from agentic_security_harness.validation import validate_path

MAX_INPUT_BYTES = 64 * 1024


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data[:MAX_INPUT_BYTES])


def fuzz_one_input(data: bytes) -> None:
    """Exercise validation on malformed report, external, and run-diff directories."""
    mode = data[0] % 4 if data else 0
    payload = data[1:] if data else data
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if mode == 0:
            _write(root / "traces.json", payload)
            (root / "scorecard.json").write_text("{}", encoding="utf-8")
            (root / "summary.md").write_text("# fuzz\n", encoding="utf-8")
        elif mode == 1:
            _write(root / "run_diff.json", payload)
            (root / "run_diff.md").write_text("# fuzz\n", encoding="utf-8")
        elif mode == 2:
            _write(root / "run_config.json", payload)
            (root / "external_results.json").write_text("[]", encoding="utf-8")
            (root / "external_summary.json").write_text("{}", encoding="utf-8")
        else:
            _write(root / "run_index.json", payload)

        result = validate_path(root)
        assert isinstance(result.errors, list)
        assert isinstance(result.warnings, list)


def main() -> None:
    import atheris

    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

