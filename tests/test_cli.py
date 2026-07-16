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


@pytest.mark.parametrize(
    "args",
    [
        ["run", "--target", "mock"],
        ["compare", "--baseline", "mock", "--protected", "mock"],
        [
            "run-matrix",
            "--target",
            "mock",
            "--scenario",
            "data-boundary",
            "--max-variants",
            "1",
        ],
    ],
)
def test_core_evidence_commands_refuse_nonempty_output_without_mutation(
    args: list[str],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    out = tmp_path / "existing"
    out.mkdir()
    sentinel = out / "prior-generation.txt"
    sentinel.write_bytes(b"prior-generation\n")

    rc = cli.main([*args, "--out", str(out)])

    assert rc == 1
    assert "must be empty for a new evidence bundle" in capsys.readouterr().out
    assert sentinel.read_bytes() == b"prior-generation\n"
    assert [path.name for path in out.iterdir()] == [sentinel.name]


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


def test_cli_validates_evidence_status_registry_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = Path(__file__).resolve().parents[1]
    registry = root / "docs" / "evidence-status-registry.json"

    assert cli.main(["validate", str(registry), "--format", "json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["evidence_status_registry_files"] == [registry.name]


def test_cli_validate_surfaces_unverified_private_projection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = Path(__file__).resolve().parents[1]
    artifact = root / "examples" / "semantic-drift-sanitized"

    assert cli.main(["validate", str(artifact), "--format", "json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    statuses = {item["evidence_id"]: item for item in payload["evidence_statuses"]}
    assert statuses["semantic.drift-history"]["projection_verification"] == (
        "unverified-private-projection"
    )


def test_cli_validate_text_does_not_hide_projection_limitation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = Path(__file__).resolve().parents[1]
    artifact = root / "examples" / "semantic-drift-sanitized"

    assert cli.main(["validate", str(artifact)]) == 0

    output = capsys.readouterr().out
    assert "unverified private projections: 1" in output
    assert "EVIDENCE LIMITATION" in output
    assert "integrity OK does not reconcile" in output
    assert "legacy rule snapshots: 1" in output
    assert "does not bind those rows to the current executable corpus" in output


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
    assert "Validation message details are hidden in text output" in out
    assert "--format json" in out


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
