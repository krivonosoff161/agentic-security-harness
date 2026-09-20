"""Static fail-closed contract for published-release verification."""

import json
import re
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "verify-published-release.yml"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_verification_workflow_is_manual_main_only_and_read_only() -> None:
    text = _workflow()

    assert "workflow_dispatch:" in text
    assert "push:" not in text
    assert "pull_request:" not in text
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "permissions: {}" in text
    assert "contents: write" not in text
    assert "id-token: write" not in text
    assert "attestations: write" not in text
    assert "environment:" not in text
    assert "gh-action-pypi-publish" not in text
    assert "TWINE_PASSWORD" not in text
    assert "password:" not in text


def test_verification_workflow_binds_tag_release_run_and_assets() -> None:
    text = _workflow()

    for marker in (
        'test "$GITHUB_REF" = "refs/heads/main"',
        'git -C release-source rev-parse "$RELEASE_TAG^{}"',
        '"conclusion": "success"',
        '"event": "push"',
        '"path": ".github/workflows/release.yml"',
        '"status": "completed"',
        '"isDraft": False',
        '"isPrerelease": False',
        'gh release download "$RELEASE_TAG"',
        '"agentic-security-harness.cdx.json"',
        '"SHA256SUMS"',
        "sha256sum --check SHA256SUMS",
    ):
        assert marker in text


def test_verification_workflow_rechecks_attestations_and_both_indexes() -> None:
    text = _workflow()

    for marker in (
        "gh attestation verify",
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
        '--source-ref "refs/tags/$RELEASE_TAG"',
        '--source-digest "$release_sha"',
        '--cert-oidc-issuer "https://token.actions.githubusercontent.com"',
        '--predicate-type "https://slsa.dev/provenance/v1"',
        "--deny-self-hosted-runners",
        "python verification-policy/src/agentic_security_harness/attestation_policy.py",
        'for host in json.loads(os.environ["INDEX_HOSTS"]):',
        "INDEX_HOSTS: ${{ steps.scope.outputs.hosts }}",
        'if path.suffix == ".whl" or path.name.endswith(".tar.gz")',
        "if observed != expected:",
    ):
        assert marker in text


def test_verification_workflow_runs_bounded_cross_platform_smokes() -> None:
    text = _workflow()

    assert text.count('"index": "testpypi"') == 1
    assert text.count('"index": "pypi"') == 4
    assert '"os": "windows-latest"' in text
    for version in ('"python": "3.11"', '"python": "3.12"', '"python": "3.13"'):
        assert version in text
    exact_lines = {line.strip() for line in text.splitlines()}
    assert '"testpypi": ("test.pypi.org", "test-files.pythonhosted.org"),' in text
    assert '"pypi": ("pypi.org", "files.pythonhosted.org"),' in text
    assert 'if parsed.scheme != "https" or parsed.hostname != file_host:' in exact_lines
    assert "downloaded wheel digest mismatch" in text
    assert (
        "python -m pip install --require-hashes \\\n"
        "            -r verification-policy/requirements/runtime.txt"
    ) in text
    assert 'python -m pip install --require-hashes --no-deps -r "$requirement"' in text
    assert 'python -m pip install "pydantic' not in text
    assert 'python -m pip install "agentic-security-harness' not in text
    assert "--extra-index-url" not in text
    assert "wheel_path.as_uri()" in text
    assert "ash --help" in text
    assert "ash quickstart" in text
    assert "ash validate" in text
    for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text):
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), reference


def _scope_script() -> str:
    step = _workflow().split("- name: Select read-only verification scope", 1)[1]
    body = step.split("python - <<'PY'\n", 1)[1].split("          PY", 1)[0]
    return textwrap.dedent(body)


@pytest.mark.parametrize("target", ["both", "testpypi"])
def test_scope_selector_preserves_staging_and_production_matrix(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "outputs"
    monkeypatch.setenv("VERIFY_TARGET", target)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    exec(compile(_scope_script(), str(WORKFLOW), "exec"), {})
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    hosts = json.loads(values["hosts"])
    matrix = json.loads(values["matrix"])["include"]
    staging = {"index": "testpypi", "os": "ubuntu-latest", "python": "3.11"}
    if target == "testpypi":
        assert hosts == ["test.pypi.org"]
        assert matrix == [staging]
    else:
        assert hosts == ["test.pypi.org", "pypi.org"]
        assert matrix == [staging] + [
            {"index": "pypi", "os": "ubuntu-latest", "python": version}
            for version in ("3.11", "3.12", "3.13")
        ] + [{"index": "pypi", "os": "windows-latest", "python": "3.11"}]
    text = _workflow()
    assert "default: both" in text
    assert "matrix: ${{ fromJSON(needs.verify-subjects.outputs.matrix) }}" in text
    assert "matrix: ${{ steps.scope.outputs.matrix }}" in text


@pytest.mark.parametrize("target", ["", "pypi", "unknown", "https://example.invalid"])
def test_scope_selector_rejects_unknown_input_without_output(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "outputs"
    monkeypatch.setenv("VERIFY_TARGET", target)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    with pytest.raises(SystemExit, match="unsupported read-only verification scope"):
        exec(compile(_scope_script(), str(WORKFLOW), "exec"), {})
    assert not output.exists()
