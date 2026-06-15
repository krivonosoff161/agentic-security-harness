import json
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.validation import ValidationResult


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


def test_cli_validate_redacts_messages_before_printing(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = ValidationResult(ok=False)
    result.errors.append("raw value sk-ABCDEFGHIJ0123456789 should not print")
    result.warnings.append("header Bearer abcdefghijklmnopqrstuvwxyz123456")
    monkeypatch.setattr(cli, "validate_path", lambda _path: result)

    assert cli.main(["validate", str(tmp_path)]) == 1
    out = capsys.readouterr().out

    assert "sk-ABCDEFGHIJ0123456789" not in out
    assert "Bearer abcdefghijklmnopqrstuvwxyz123456" not in out
    assert "sk-[REDACTED]" in out
    assert "Bearer [REDACTED]" in out


def test_cli_validate_json_redacts_messages_before_printing(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = ValidationResult(ok=False)
    result.errors.append("raw value sk-ABCDEFGHIJ0123456789 should not print")
    monkeypatch.setattr(cli, "validate_path", lambda _path: result)

    assert cli.main(["validate", str(tmp_path), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)

    assert "sk-ABCDEFGHIJ0123456789" not in json.dumps(payload)
    assert payload["errors"] == ["raw value sk-[REDACTED] should not print"]
