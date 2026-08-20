"""Static fail-closed contract for published-release verification."""

import re
from pathlib import Path

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
        '("test.pypi.org", "pypi.org")',
        'if path.suffix == ".whl" or path.name.endswith(".tar.gz")',
        "if observed != expected:",
    ):
        assert marker in text


def test_verification_workflow_runs_bounded_cross_platform_smokes() -> None:
    text = _workflow()

    assert text.count("index: testpypi") == 1
    assert text.count("index: pypi") == 4
    assert "os: windows-latest" in text
    for version in ('python: "3.11"', 'python: "3.12"', 'python: "3.13"'):
        assert version in text
    exact_lines = {line.strip() for line in text.splitlines()}
    assert (
        'if parsed.scheme != "https" or parsed.hostname != "test-files.pythonhosted.org":'
        in exact_lines
    )
    assert "downloaded TestPyPI wheel digest mismatch" in text
    assert 'python -m pip install --no-deps "$wheel"' in text
    assert "--extra-index-url" not in text
    assert '"agentic-security-harness==$VERSION"' in text
    assert "ash --help" in text
    assert "ash quickstart" in text
    assert "ash validate" in text
    for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text):
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), reference
