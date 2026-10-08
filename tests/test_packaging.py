"""Packaging / Docker / devcontainer static contracts (no image build)."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_is_safe_and_offline() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert text.startswith("#") or "FROM python:" in text
    assert "FROM python:" in text
    # Runs as a non-root user.
    assert "USER ash" in text
    # Default command is the offline doctor, not a live external run.
    assert 'CMD ["python", "-m", "agentic_security_harness.cli", "doctor"]' in text
    # No secrets anywhere.
    assert "sk-" not in text and "AKIA" not in text and "--api-key-env" not in text
    # No build/run step performs a live external call by default.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("RUN ", "CMD ", "ENTRYPOINT ")):
            assert "run-external" not in stripped
    # The clean base image can import the src-layout package at its build-time smoke step.
    assert text.index("ENV PYTHONPATH=/app/src") < text.index(
        'python -c "import agentic_security_harness'
    )


def test_runtime_gateway_container_is_hardened_and_synthetic_only() -> None:
    dockerfile = (ROOT / "Dockerfile.gateway").read_text(encoding="utf-8")
    compose = (ROOT / "compose.gateway.yml").read_text(encoding="utf-8")
    config = tomllib.loads(
        (ROOT / "examples" / "runtime-gateway" / "gateway.docker.toml").read_text(
            encoding="utf-8"
        )
    )

    assert "@sha256:" in dockerfile
    assert " AS builder" in dockerfile
    assert "python -m build --no-isolation --wheel" in dockerfile
    assert "--no-deps /tmp/wheel/*.whl" in dockerfile
    assert "USER ash" in dockerfile
    assert 'CMD ["ash", "gateway-serve"' in dockerfile
    assert "run-external" not in dockerfile
    assert "--credential" not in dockerfile.casefold()
    assert "api_key" not in dockerfile.casefold()
    assert '"127.0.0.1:8787:8787"' in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert config["host"] == "0.0.0.0"
    assert config["synthetic_container_mode"] is True
    assert config["audit_dir"] == "/data/audit"


def test_dockerignore_excludes_heavy_and_secret_paths() -> None:
    lines = [
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert lines[0] == "*"
    assert {
        "!Dockerfile.gateway",
        "!pyproject.toml",
        "!README.md",
        "!LICENSE",
        "!NOTICE",
        "!requirements/",
        "!requirements/runtime.txt",
        "!.clusterfuzzlite/",
        "!.clusterfuzzlite/**",
        "!fuzz/",
        "!fuzz/**",
        "!src/",
        "!src/**",
        "!examples/",
        "!examples/**",
    }.issubset(lines)
    assert not any(line in {"!docs/", "!tests/", "!./", "!**"} for line in lines)

    final_public_allow = max(lines.index("!src/**"), lines.index("!examples/**"))
    for pattern in (
        "**/.env",
        "**/.env.*",
        "**/.internal/**",
        "**/private-traces/**",
        "**/raw-model-responses/**",
        "**/reports/**",
        "**/*.db",
        "**/*.sqlite3",
    ):
        assert lines.index(pattern) > final_public_allow


def test_devcontainer_is_valid_json_no_secrets() -> None:
    data = json.loads((ROOT / ".devcontainer" / "devcontainer.json").read_text("utf-8"))
    assert "image" in data
    blob = json.dumps(data)
    assert "sk-" not in blob and "AKIA" not in blob


def test_pyproject_packaging_fields() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'ash = "agentic_security_harness.cli:main"' in text
    assert 'py.typed' in text
    assert 'license = "Apache-2.0"' in text
    assert 'requires-python = ">=3.11"' in text


def test_current_release_source_metadata_is_synchronized() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version_text = (ROOT / "src/agentic_security_harness/version.py").read_text("utf-8")
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_notes = (ROOT / f"docs/releases/v{project['version']}.md").read_text(encoding="utf-8")

    package_version = re.search(r'^__version__ = "([^"]+)"$', version_text, re.MULTILINE)
    assert package_version is not None
    assert project["version"] == package_version.group(1) == "1.13.0"
    assert 'Development Status :: 4 - Beta' in project["classifiers"]
    assert 'version: "1.13.0"' in citation
    assert "## [1.13.0] - 2026-10-08" in changelog
    assert "Agentic Security Harness v1.13.0" in release_notes
    assert "GuardedWorkspace" in release_notes
    assert "PACKAGE_README.md" in release_notes
    release_notes = (ROOT / "docs/releases/v1.10.1.md").read_text(encoding="utf-8")
    assert "Status: published on GitHub, TestPyPI and PyPI" in release_notes
    for receipt in ("37101792230", "37102048175", "37102205673", "37102316728"):
        assert receipt in release_notes
    assert "c52dc59f64dfef31efb2ba3ac4a28b220d90a5e475d1443f5a56cf04b26fed16" in release_notes
    assert "PACKAGE_README.md" in release_notes
    assert project["readme"] == "PACKAGE_README.md"
    failed_tag = (ROOT / "docs/releases/v1.10.0.md").read_text(encoding="utf-8")
    assert "## [1.10.0] - 2026-10-03" in changelog
    assert "immutable failed tag" in failed_tag
    assert "No TestPyPI or PyPI upload occurred" in failed_tag
    prior = (ROOT / "docs/releases/v1.9.1.md").read_text(encoding="utf-8")
    assert "## [1.9.1] - 2026-10-02" in changelog
    assert "Status: published on GitHub, TestPyPI and PyPI" in prior
    # The prior published immutable release retains its independent evidence.
    release_notes = (ROOT / "docs/releases/v1.8.0.md").read_text(encoding="utf-8")
    assert "## [1.8.0] - 2026-09-30" in changelog
    assert "Agentic Security Harness v1.8.0" in release_notes
    assert "published on GitHub, TestPyPI and PyPI" in release_notes
    assert "36813028115" in release_notes
    assert "no new model-success" in release_notes


def test_package_ci_requires_byte_reproducible_wheel_and_sdist() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for marker in (
        'export SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$GITHUB_SHA")"',
        "python tools/normalize_sdist.py",
        "cmp dist/*.tar.gz reproducibility-check/*.tar.gz",
        "cmp dist/*.whl reproducibility-check/*.whl",
    ):
        assert marker in text


def test_linux_installed_package_runs_agent_host_quickstart() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for marker in (
        "ash agent-host-quickstart --out agent-host-result",
        "test -f agent-host-result/run_index.json",
        "test -f agent-host-result/agent_host_summary.json",
        "ash validate agent-host-result",
        "ash gateway-init --out gateway.toml",
        "ash gateway-check --config gateway.toml",
        "test ! -e .internal/runtime-gateway",
    ):
        assert marker in text


def test_ci_builds_and_smokes_runtime_gateway_container() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for marker in (
        "runtime-gateway-container:",
        "docker compose -f compose.gateway.yml config --quiet",
        "docker build --file Dockerfile.gateway --tag ash-runtime-gateway:ci .",
        "--publish 127.0.0.1:8787:8787",
        "MCP-Protocol-Version: 2026-07-28",
        '"supportedVersions":["2026-07-28"]',
    ):
        assert marker in text
