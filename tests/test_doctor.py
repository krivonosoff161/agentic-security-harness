"""Tests for `ash doctor` onboarding diagnostics."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.doctor import run_doctor


def test_doctor_default_no_live_check(tmp_path: Path) -> None:
    report = run_doctor(root=tmp_path)
    names = [c.name for c in report.checks]
    assert "python_version" in names
    assert "package_source" in names
    assert "cli_commands" in names
    assert "external_adapters" in names
    assert "external_presets" in names
    assert "reports_writable" in names
    assert "live_local" not in names  # no network by default


def test_doctor_reports_actual_package_source_without_network(tmp_path: Path) -> None:
    report = run_doctor(root=tmp_path)
    source = next(c for c in report.checks if c.name == "package_source")

    assert source.ok is None
    assert "agentic_security_harness" in source.detail
    assert "core sha256" in source.detail


def test_doctor_presets_check_ok(tmp_path: Path) -> None:
    report = run_doctor(root=tmp_path)
    presets = next(c for c in report.checks if c.name == "external_presets")
    assert presets.ok is True
    assert "ollama" in presets.detail


def test_doctor_reports_writable_ok(tmp_path: Path) -> None:
    reports_root = tmp_path / "myreports"
    report = run_doctor(root=tmp_path, reports_root=reports_root)
    rw = next(c for c in report.checks if c.name == "reports_writable")
    assert rw.ok is True
    assert not reports_root.exists()


def test_doctor_presets_check_no_network(tmp_path: Path) -> None:
    from unittest.mock import patch

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        run_doctor(root=tmp_path)
        mock_open.assert_not_called()


def test_doctor_python_check_ok(tmp_path: Path) -> None:
    report = run_doctor(root=tmp_path)
    py = next(c for c in report.checks if c.name == "python_version")
    assert py.ok is True


def test_doctor_api_key_value_never_printed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASH_DOCTOR_SECRET_ENV", "super-secret-value-123")
    report = run_doctor(root=tmp_path, credential_env_var="ASH_DOCTOR_SECRET_ENV")
    blob = json.dumps(report.model_dump(mode="json"))
    assert "super-secret-value-123" not in blob
    key_check = next(c for c in report.checks if c.name == "credential_env_var")
    assert "SET" in key_check.detail  # presence reported, value hidden


def test_doctor_examples_missing_flagged(tmp_path: Path) -> None:
    report = run_doctor(root=tmp_path)  # tmp has no examples/
    ex = next(c for c in report.checks if c.name == "examples_dir")
    assert ex.ok is False


def test_doctor_live_local_success(tmp_path: Path) -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"model": "doctor-probe", "choices": [{"message": {"content": "ok"}}]}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        return_value=mock_response,
    ):
        report = run_doctor(root=tmp_path, live_local=True)
    live = next(c for c in report.checks if c.name == "live_local")
    assert live.ok is True


def test_doctor_live_local_failure_sets_not_ok(tmp_path: Path) -> None:
    import urllib.error

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=urllib.error.URLError("refused"),
    ):
        report = run_doctor(root=tmp_path, live_local=True)
    assert report.ok is False
    live = next(c for c in report.checks if c.name == "live_local")
    assert live.ok is False


def test_cli_doctor_human_no_network(capsys: pytest.CaptureFixture[str]) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        rc = cli.main(["doctor"])
        mock_open.assert_not_called()
    out = capsys.readouterr().out
    assert "environment diagnostics" in out
    assert "Next:" in out
    assert rc in (0, 1)


def test_cli_doctor_json_is_valid(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["doctor", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "ok" in data and "checks" in data
    assert rc in (0, 1)
