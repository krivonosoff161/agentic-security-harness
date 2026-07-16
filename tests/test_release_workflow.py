"""Static fail-closed contract for the release-facing GitHub Actions workflow."""

import re
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _identity_script() -> str:
    match = re.search(
        r"(?ms)^\s+python - <<'PY'\n(?P<body>.+?)^\s+PY$",
        _workflow(),
    )
    assert match is not None
    return textwrap.dedent(match.group("body"))


def test_release_workflow_is_tag_only_and_binds_version_identity() -> None:
    text = _workflow()

    assert "workflow_dispatch" not in text
    assert re.search(r"(?m)^  push:\n    tags:\n      - \"v\*\"$", text)
    assert "if: github.event_name == 'push' && github.ref_type == 'tag'" in text
    for marker in (
        're.fullmatch(r"v[0-9]+\\.[0-9]+\\.[0-9]+", tag)',
        'Path("pyproject.toml")',
        'Path("src/agentic_security_harness/version.py")',
        'f"## [{project_version}] - "',
        'tag != f"v{project_version}"',
    ):
        assert marker in text


def test_release_identity_script_accepts_current_canonical_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("RELEASE_TAG", "v0.14.0")

    exec(compile(_identity_script(), str(WORKFLOW), "exec"), {})


def test_release_identity_script_rejects_mismatched_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("RELEASE_TAG", "v9.9.9")

    with pytest.raises(SystemExit, match="release identity mismatch"):
        exec(compile(_identity_script(), str(WORKFLOW), "exec"), {})


def test_release_workflow_enforces_repository_and_built_package_gates() -> None:
    text = _workflow()

    for command in (
        "python -m pip install --require-hashes -r requirements/dev.txt",
        "python -m pip install --require-hashes -r requirements/build.txt",
        "python -m pytest",
        "python -m ruff check .",
        "python -m mypy src tests",
        "python -m agentic_security_harness.cli validate examples/",
        "python -m build --no-isolation",
        "--force-reinstall dist/*.tar.gz",
        "--force-reinstall dist/*.whl",
        "assert f'v{ash.__version__}' == os.environ['RELEASE_TAG']",
        "cd dist && sha256sum *.tar.gz *.whl > SHA256SUMS",
        "if-no-files-found: error",
    ):
        assert command in text


def test_release_workflow_keeps_credentials_and_signing_authority_out() -> None:
    text = _workflow()

    assert "persist-credentials: false" in text
    assert re.search(r"(?m)^permissions:\n  contents: read$", text)
    assert "contents: write" not in text
    assert "id-token: write" not in text
    assert "attestations: write" not in text
    for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text):
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), reference
