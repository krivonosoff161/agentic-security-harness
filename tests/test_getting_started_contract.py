"""Keep the displayed installed-package first run executable without checkout assets."""

import re
import shlex
from pathlib import Path
from unittest.mock import patch

import pytest

from agentic_security_harness import cli

GUIDE = Path(__file__).resolve().parents[1] / "docs" / "getting-started.md"


def _bash_commands(section: str) -> list[str]:
    return [
        line.strip()
        for block in re.findall(r"```bash\n(.*?)\n```", section, flags=re.DOTALL)
        for line in block.splitlines()
        if line.strip().startswith("ash ")
    ]


def test_displayed_offline_first_route_runs_without_checkout_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    first_route = guide.split("## Optional: test your own model", maxsplit=1)[0]
    readiness = first_route.split("Confirm your environment is ready (no network):", 1)[1]
    readiness = readiness.split("To exercise the provider-neutral", 1)[0]
    commands = _bash_commands(readiness)
    commands.extend(_bash_commands(first_route.split("## 2. See what is available", 1)[1]))

    assert commands[:2] == [
        "ash quickstart --out reports/quickstart",
        "ash validate reports/quickstart",
    ]
    assert "ash validate examples/" not in commands
    assert all("gateway-serve" not in command for command in commands)

    monkeypatch.chdir(tmp_path)
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as network:
        for command in commands:
            argv = shlex.split(command, comments=True)
            assert argv[0] == "ash"
            assert cli.main(argv[1:]) == 0, command
    network.assert_not_called()

    for bundle in ("quickstart", "demo", "comparison", "matrix"):
        assert (tmp_path / "reports" / bundle / "run_index.json").is_file()
    assert (tmp_path / "reports" / "quickstart" / "report.html").is_file()
    assert (tmp_path / "reports" / "demo" / "report.html").is_file()


def test_checkout_only_and_long_running_examples_are_separate() -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    first_route, optional = guide.split("## Optional: test your own model", maxsplit=1)

    assert "python -m pip install agentic-security-harness==1.13.0" in first_route
    assert "ash validate examples/" not in first_route
    assert "python examples/fake_openai_server.py" not in first_route
    assert "ash gateway-serve" not in first_route
    assert "### Source-checkout fake-server example" in optional
    assert "repository checkout" in optional
    assert "separate\nterminal" in optional
    assert "## Optional: local synthetic Gateway" in optional
    assert "ash gateway-serve --config gateway.toml" in optional
