"""Packaging / Docker / devcontainer static contracts (no image build)."""

import json
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


def test_dockerignore_excludes_heavy_and_secret_paths() -> None:
    lines = [
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert lines[0] == "*"
    assert {
        "!pyproject.toml",
        "!README.md",
        "!LICENSE",
        "!NOTICE",
        "!requirements/",
        "!requirements/runtime.txt",
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
