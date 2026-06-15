import json
from pathlib import Path

import pytest

from agentic_security_harness import cli


def test_cli_run_writes_reports(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    rc = cli.main(["run", "--target", "mock", "--out", str(out)])
    assert rc == 0
    for name in ("traces.json", "scorecard.json", "summary.md", "executive.md"):
        assert (out / name).exists()


def test_cli_requires_subcommand() -> None:
    with pytest.raises(SystemExit):
        cli.main([])


def test_cli_validate_json(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out = tmp_path / "demo"
    assert cli.main(["run", "--target", "mock", "--out", str(out)]) == 0
    capsys.readouterr()

    assert cli.main(["validate", str(out), "--format", "json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["report_dirs"] == ["demo"]
