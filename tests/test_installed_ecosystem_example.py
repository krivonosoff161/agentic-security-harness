"""Example/control-plane checks; no package download, provider or real target."""

import ast
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
    # Historical published-wheel contour stays pinned independently of a candidate.
    expected[project["name"]] = "1.6.0"
    assert _module().EXPECTED == expected
    assert project["version"] == "1.10.1"


def test_example_fails_closed_on_contract_mismatch() -> None:
    with pytest.raises(ValueError):
        _module().require(False)


@pytest.mark.parametrize("name", [
    "check.py", "chain.py", "verify_chain.py", "check_supplied_input.py",
])
def test_all_example_version_gates_accept_current_release(name: str) -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    current = project["version"]
    source = EXAMPLE.with_name(name).read_text(encoding="utf-8")
    gates = re.findall(r"(?:choices=|core_version in )([({][^)}]+[)}])", source)
    assert gates, "example must declare its accepted versions"
    for gate in gates:
        assert {"1.6.0", "1.7.0", "1.7.1", current} <= set(ast.literal_eval(gate))


def test_versioned_onboarding_pin_matches_latest_published_version() -> None:
    pattern = r"python -m pip install agentic-security-harness==([0-9]+\.[0-9]+\.[0-9]+)"
    readme = re.search(pattern, (ROOT / "README.md").read_text(encoding="utf-8"))
    onboarding = re.search(pattern, (ROOT / "docs/getting-started.md").read_text(encoding="utf-8"))
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert readme and onboarding and readme.group(1) == onboarding.group(1) == "1.10.1"
    assert project["version"] == "1.10.1"
    notes = (ROOT / "docs/releases/v1.10.1.md").read_text(encoding="utf-8")
    assert "release candidate; not published" not in notes
    assert "https://pypi.org/project/agentic-security-harness/1.10.1/" in notes
    pilot = (ROOT / "docs/external-pilot.md").read_text(encoding="utf-8")
    assert "current published 1.10.1" in pilot
    assert pilot.count("--core-version 1.10.1") == 3
    assert "--core-version 1.7.1" not in pilot


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
    test_versioned_onboarding_pin_matches_latest_published_version()


def test_v160_pilot_lock_binds_one_exact_wheel_without_an_extra_index() -> None:
    lock = (EXAMPLE.parent / "core-release.txt").read_text(encoding="utf-8")
    rows = [line.strip() for line in lock.splitlines() if line and not line.startswith("#")]
    assert rows == [
        "agentic-security-harness @ https://files.pythonhosted.org/packages/1b/6d/"
        "81c8e38b6d596329c812f82e665f211f6311469bdafef77952175c7f2c4f/"
        "agentic_security_harness-1.6.0-py3-none-any.whl \\",
        "--hash=sha256:bf393cb3644520a20e9c56d760c0e1ab330ddf8a099e704035a2bdad728a4a45",
    ]
    assert "index-url" not in lock
    assert lock.count("https://files.pythonhosted.org/") == 1


def test_v160_publication_docs_retain_initial_failures_and_evidence_limits() -> None:
    notes = (ROOT / "docs/releases/v1.6.0.md").read_text(encoding="utf-8")
    for marker in (
        "0796fc60020ced318ad67fecb29de60234e707df",
        "35602050427", "35602400245", "35602644448", "35602999743",
        "bf393cb3644520a20e9c56d760c0e1ab330ddf8a099e704035a2bdad728a4a45",
        "workflow remains failed", "No upload or build was repeated",
        "not a production safety certification", "independent human review remain outstanding",
    ):
        assert marker in notes
    adapter = (ROOT / "docs/ollama-quarantine-adapter.md").read_text(encoding="utf-8")
    assert "**unreleased**" not in adapter
    assert "publication is not a new model experiment" in adapter
    example = (EXAMPLE.parent / "README.md").read_text(encoding="utf-8")
    assert "--no-compile --only-binary=:all: --require-hashes" in example
    assert "-r examples/installed-ecosystem/core-release.txt" in example


def test_v170_pilot_lock_binds_new_subject_without_rewriting_historical_lock() -> None:
    lock = (EXAMPLE.parent / "core-release-v1.7.0.txt").read_text(encoding="utf-8")
    rows = [line.strip() for line in lock.splitlines() if line and not line.startswith("#")]
    assert rows == [
        "agentic-security-harness @ https://files.pythonhosted.org/packages/95/44/"
        "213b49f6fd6a62223d05559373fb7f89f1bce8e45cb7f323c8a286f8b220/"
        "agentic_security_harness-1.7.0-py3-none-any.whl \\",
        "--hash=sha256:87210392f1596477008bd78fdc71229047b863f42b3a459c6f9222508043a6eb",
    ]
    assert "index-url" not in lock
    assert lock.count("https://files.pythonhosted.org/") == 1
    example = (EXAMPLE.parent / "README.md").read_text(encoding="utf-8")
    assert "-r examples/installed-ecosystem/core-release-v1.7.0.txt" in example
    assert "Historical published 1.6.0" in example
    assert "It expects two synthetic executions" in example


def test_v171_historical_pilot_lock_retains_exact_published_subject() -> None:
    lock = (EXAMPLE.parent / "core-release-v1.7.1.txt").read_text(encoding="utf-8")
    rows = [line.strip() for line in lock.splitlines() if line and not line.startswith("#")]
    assert rows == [
        "agentic-security-harness @ https://files.pythonhosted.org/packages/66/2c/"
        "7e38f10573ee8993dade577ac575a6eab9951850345ac4a76f4694225624/"
        "agentic_security_harness-1.7.1-py3-none-any.whl \\",
        "--hash=sha256:3cf26abd2adc79e860d77969112e47aaeb1a50c03a3aed459b2830116d6bc110",
    ]
    assert "index-url" not in lock
    assert lock.count("https://files.pythonhosted.org/") == 1
    example = (EXAMPLE.parent / "README.md").read_text(encoding="utf-8")
    assert "Historical published 1.7.1" in example
    assert "Historical published 1.7.0" in example
    assert "-r examples/installed-ecosystem/core-release-v1.7.1.txt" in example
