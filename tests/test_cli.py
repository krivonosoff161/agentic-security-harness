from pathlib import Path

import pytest

from agentic_security_harness import cli


def test_cli_run_writes_reports(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    rc = cli.main(["run", "--target", "mock", "--out", str(out)])
    assert rc == 0
    for name in ("traces.json", "scorecard.json", "summary.md"):
        assert (out / name).exists()


def test_cli_requires_subcommand() -> None:
    with pytest.raises(SystemExit):
        cli.main([])
