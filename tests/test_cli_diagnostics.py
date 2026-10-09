"""First-user diagnostics distinguish configuration from runtime availability."""

from pathlib import Path
from unittest.mock import patch

import pytest

from agentic_security_harness import cli


@pytest.mark.parametrize("contents", [None, "this is not valid TOML = [\n"])
def test_gateway_invalid_config_gives_fixed_actionable_hint_without_echo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], contents: str | None
) -> None:
    config = tmp_path / "gateway.toml"
    if contents is not None:
        config.write_text(contents, encoding="utf-8")

    assert cli.main(["gateway-check", "--config", str(config)]) == 1
    output = capsys.readouterr().out
    assert "Error: Runtime Gateway config is invalid or unsafe" in output
    assert "Next: verify --config names an existing readable V1 TOML file" in output
    assert "ash gateway-init --out <new-path>" in output
    assert str(config) not in output
    assert "this is not valid TOML" not in output


def test_offline_external_check_does_not_claim_model_availability(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch("agentic_security_harness.external_openai_compatible.chat_completion") as call,
        patch("agentic_security_harness.external_openai_compatible.urlopen_no_redirect") as network,
    ):
        assert cli.main([
            "external-check", "--base-url", "http://127.0.0.1:49999/v1",
            "--model", "unavailable-synthetic", "--scenario", "data-boundary",
        ]) == 0
    call.assert_not_called()
    network.assert_not_called()
    output = capsys.readouterr().out
    assert "Model: unavailable-synthetic -- configured; availability not checked" in output
    assert "Model: unavailable-synthetic -- OK" not in output
    assert "--live" in output
