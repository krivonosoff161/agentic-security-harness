"""Example/control-plane checks; no package download, provider or real target."""

import importlib.util
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "installed-ecosystem" / "check.py"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("installed_example", EXAMPLE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "event",
    [
        "subprocess.Popen",
        "socket.connect",
        "socket.__new__",
        "os.system",
        "os.posix_spawn",
        "os.startfile",
    ],
)
def test_example_denies_effect_events(event: str) -> None:
    with pytest.raises(PermissionError):
        _module().deny_effects(event, ())


def test_example_version_set_matches_declared_extras() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    expected = dict(item.split("==") for item in project["optional-dependencies"]["all"])
    expected[project["name"]] = project["version"]
    assert _module().EXPECTED == expected


def test_example_fails_closed_on_contract_mismatch() -> None:
    with pytest.raises(ValueError):
        _module().require(False)


def test_current_onboarding_install_pin_matches_readme_published_baseline() -> None:
    pattern = r"python -m pip install agentic-security-harness==([0-9]+\.[0-9]+\.[0-9]+)"
    readme = re.search(pattern, (ROOT / "README.md").read_text(encoding="utf-8"))
    onboarding = re.search(pattern, (ROOT / "docs/getting-started.md").read_text(encoding="utf-8"))
    assert readme and onboarding and readme.group(1) == onboarding.group(1)


def test_example_configs_are_canonical_and_authority_free() -> None:
    for kind in ("transfer", "handoff"):
        data = EXAMPLE.with_name(kind + "-config.json").read_bytes()
        value = json.loads(data)
        assert value["operational_authority"] == "none"
        assert data == json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def test_installed_example_runs_in_existing_cross_platform_workflow() -> None:
    workflow = (ROOT / ".github/workflows/ecosystem-integration.yml").read_text(encoding="utf-8")
    assert "installed-ecosystem:" in workflow
    assert '"examples/installed-ecosystem/**"' in workflow
    assert "os: [ubuntu-latest, windows-latest]" in workflow
    assert "python -I -B examples/installed-ecosystem/check.py" in workflow
    assert "--only-binary=:all: --require-hashes" in workflow
    assert "--no-compile --only-binary=:all:" in workflow
    assert "python -m pip check" in workflow
    for file in ("publish-pypi.yml", "verify-published-release.yml"):
        text = (ROOT / ".github/workflows" / file).read_text(encoding="utf-8")
        assert "examples/installed-ecosystem/check.py" in text


def test_external_pilot_has_an_explicit_stop_and_feedback_contract() -> None:
    text = (ROOT / "docs/external-pilot.md").read_text(encoding="utf-8")
    for phrase in (
        "public synthetic",
        "negative control",
        "not independent validation",
        "Stop",
        "No credentials",
    ):
        assert phrase in text


def test_historical_release_verification_uses_its_own_optional_example() -> None:
    text = (ROOT / ".github/workflows/verify-published-release.yml").read_text(encoding="utf-8")
    checkout = text.split("Check out the selected release example", 1)[1].split("- name:", 1)[0]
    assert "ref: ${{ inputs.release_tag }}" in checkout
    assert "path: release-example" in checkout
    assert "persist-credentials: false" in checkout
    assert "if [ -f release-example/examples/installed-ecosystem/check.py ]; then" in text
    assert "-r release-example/requirements/companions.txt" in text
    assert "python -I -B release-example/examples/installed-ecosystem/check.py" in text
    assert "verification-policy/src/agentic_security_harness/attestation_policy.py" in text


def test_onboarding_reader_does_not_depend_on_windows_locale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_text = Path.read_text

    def locale_read(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
        return read_text(path, encoding=encoding or "cp1252", errors=errors)

    monkeypatch.setattr(Path, "read_text", locale_read)
    test_current_onboarding_install_pin_matches_readme_published_baseline()
