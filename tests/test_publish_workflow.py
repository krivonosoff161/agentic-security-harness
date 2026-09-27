"""Static fail-closed contract for package-index promotion."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_publish_workflow_is_manual_tag_bound_and_environment_gated() -> None:
    text = _workflow()

    assert "workflow_dispatch:" in text
    assert "push:" not in text
    assert "pull_request:" not in text
    assert "if: startsWith(github.ref, 'refs/tags/v')" in text
    assert 'test "$GITHUB_REF" = "refs/tags/$RELEASE_TAG"' in text
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in text
    assert "environment: ${{ inputs.target }}" in text
    assert "cancel-in-progress: false" in text
    assert "id-token: write" in text
    assert "password:" not in text
    assert "TWINE_PASSWORD" not in text


def test_publish_workflow_reuses_only_successful_attested_release_subjects() -> None:
    text = _workflow()

    for marker in (
        '"conclusion": "success"',
        '"event": "push"',
        '"path": ".github/workflows/release.yml"',
        '"status": "completed"',
        "run-id: ${{ inputs.release_run_id }}",
        "name: release-dist-${{ inputs.release_tag }}",
        "sha256sum --check SHA256SUMS",
        "gh attestation verify",
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
        '--source-ref "refs/tags/$RELEASE_TAG"',
        '--source-digest "$GITHUB_SHA"',
        "cp dist/*.tar.gz dist/*.whl publish-dist/",
    ):
        assert marker in text


def test_production_promotion_requires_testpypi_hash_equality() -> None:
    text = _workflow()

    assert "https://test.pypi.org/pypi/agentic-security-harness/{version}/json" in text
    assert 'if observed != expected:' in text
    assert "TestPyPI subject mismatch" in text
    assert "if: inputs.target == 'pypi'" in text


def test_publish_action_is_commit_pinned_and_post_publish_smokes_are_bounded() -> None:
    text = _workflow()

    publish_ref = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
    assert text.count(publish_ref) == 2
    assert "repository-url: https://test.pypi.org/legacy/" in text
    assert "Verify published package-index subjects" in text
    assert 'host = "test.pypi.org"' in text
    assert 'else "pypi.org"' in text
    assert "published subject mismatch" in text
    assert text.count(
        'if path.suffix == ".whl" or path.name.endswith(".tar.gz")'
    ) == 2
    assert 'f"agentic-security-harness=={version} --hash=sha256:{digest}\\n"' in text
    assert text.count("python -m pip install --require-hashes -r requirements/runtime.txt") == 2
    assert text.count('--require-hashes --no-deps -r "$requirement_file"') == 2
    assert "--extra-index-url" not in text
    assert text.count("expected one universal wheel") == 2
    assert text.count("published wheel SHA-256 is missing") == 2
    assert "ash quickstart" in text
    assert "ash validate" in text
    assert "for attempt in 1 2 3 4 5" in text
    assert "sleep 15" in text
    for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text):
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), reference


def test_promotion_checks_pinned_garak_from_exact_index_wheels() -> None:
    text = _workflow()
    staging = text.split("  smoke-testpypi:\n", 1)[1].split("  smoke-pypi:\n", 1)[0]
    production = text.split("  smoke-pypi:\n", 1)[1]
    assert "os: [ubuntu-latest, windows-latest]" in staging
    assert "--index-url https://test.pypi.org/simple/" in staging
    assert "--require-hashes --no-deps -r \"$requirement_file\"" in staging
    assert "--extra-index-url" not in staging
    assert '--core-version "${RELEASE_TAG#v}"' in staging
    assert "os: windows-latest" in production
    assert "https://pypi.org/pypi/agentic-security-harness/{version}/json" in production
    assert '--core-version "${RELEASE_TAG#v}"' in production
    for smoke in (staging, production):
        assert "examples/garak-gateway/requirements-smoke.txt" in smoke
        assert "examples/garak-gateway/prepare_source.py" in smoke
        assert (
            "--garak-source upstream-source/garak-ac4c5567f0c17834aace52b14788c1ca3548738b"
            in smoke
        )
        assert "garak-observation.json --require-detector" in smoke
