"""Static fail-closed contract for the release-facing GitHub Actions workflow."""

import re
import runpy
import textwrap
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PROJECT_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
    "project"
]["version"]


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
        'Path("CITATION.cff")',
        'citation_match.group(1) != project_version',
        'Path(f"docs/releases/v{project_version}.md")',
    ):
        assert marker in text


def test_release_identity_script_accepts_current_canonical_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("RELEASE_TAG", f"v{PROJECT_VERSION}")

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
        "python -m mypy src tests tools",
        "python -m agentic_security_harness.cli validate examples/",
        "python -m build --no-isolation",
        'export SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$GITHUB_SHA")"',
        "python tools/normalize_sdist.py",
        "cmp dist/*.tar.gz reproducibility-check/*.tar.gz",
        "cmp dist/*.whl reproducibility-check/*.whl",
        "--force-reinstall dist/*.tar.gz",
        "--force-reinstall dist/*.whl",
        "assert f'v{ash.__version__}' == os.environ['RELEASE_TAG']",
        "python tools/release_sbom.py",
        "--runtime-lock requirements/runtime.txt",
        "--source-sha \"$GITHUB_SHA\"",
        "--source-ref \"$GITHUB_REF\"",
        "--output dist/agentic-security-harness.cdx.json",
        "cd dist && sha256sum *.tar.gz *.whl *.cdx.json > SHA256SUMS",
        "if-no-files-found: error",
    ):
        assert command in text


def test_release_runs_pinned_garak_detector_from_exact_wheel_on_both_platforms() -> None:
    text = _workflow()
    gate = text.split("  garak-exact-wheel:\n", 1)[1]
    assert "needs: build" in gate
    assert "os: [ubuntu-latest, windows-latest]" in gate
    assert "name: release-dist-${{ github.ref_name }}" in gate
    assert "sha256sum --check SHA256SUMS" in gate
    assert "pip --isolated install --no-compile --only-binary=:all: --require-hashes" in gate
    assert (
        "--no-index --no-deps --no-compile "
        f"dist/agentic_security_harness-{PROJECT_VERSION}-py3-none-any.whl" in gate
    )
    assert "--garak-source upstream-source/garak-ac4c5567f0c17834aace52b14788c1ca3548738b" in gate
    assert "garak-observation.json --require-detector" in gate
    assert (
        "examples/installed-ecosystem/check.py --out release-ecosystem-result.json "
        f"--core-version {PROJECT_VERSION}" in gate
    )


def test_candidate_workflows_install_the_current_source_version() -> None:
    for name in ("garak-connector.yml", "ecosystem-integration.yml"):
        workflow = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        candidate_wheels = re.findall(
            r"dist/agentic_security_harness-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl",
            workflow,
        )
        assert candidate_wheels and set(candidate_wheels) == {PROJECT_VERSION}, name
    ecosystem = (ROOT / ".github" / "workflows" / "ecosystem-integration.yml").read_text(
        encoding="utf-8"
    )
    candidate = ecosystem.split("  installed-ecosystem:\n", 1)[1]
    candidate_versions = re.findall(r"--core-version ([0-9]+\.[0-9]+\.[0-9]+)", candidate)
    assert candidate_versions and set(candidate_versions) == {PROJECT_VERSION}
    assert "core-release-v1.7.0.txt" in ecosystem.split("  installed-ecosystem:\n", 1)[0]


def test_ancestry_checks_cover_candidate_release_staging_and_published_wheels() -> None:
    directory = ROOT / ".github" / "workflows"
    command = "examples/installed-ecosystem/check_ancestry.py"
    for name in ("release.yml", "ecosystem-integration.yml"):
        text = (directory / name).read_text(encoding="utf-8")
        lines = [line for line in text.splitlines() if command in line]
        assert len(lines) == 1
        assert f"--core-version {PROJECT_VERSION}" in lines[0]
    promotion = (directory / "publish-pypi.yml").read_text(encoding="utf-8")
    lines = [line for line in promotion.splitlines() if command in line]
    assert len(lines) == 2
    assert all('--core-version "${RELEASE_TAG#v}"' in line for line in lines)
    verification = (directory / "verify-published-release.yml").read_text(encoding="utf-8")
    assert f'if [ -f release-example/{command} ]; then' in verification
    assert '--out verified-ancestry-result.json --core-version "$RELEASE_VERSION"' in verification


def test_optional_wheelhouse_uses_source_version_without_running_installer() -> None:
    # Loading declarations does not invoke main(), pip, or extension entry points.
    declarations = runpy.run_path(str(ROOT / "tools/optional_wheelhouse_smoke.py"))
    assert declarations["EXPECTED"]["agentic-security-harness"] == (
        PROJECT_VERSION,
        f"agentic_security_harness-{PROJECT_VERSION}-py3-none-any.whl",
    )


def test_release_workflow_scopes_attestation_authority_and_verifies_provenance() -> None:
    text = _workflow()

    assert "persist-credentials: false" in text
    assert re.search(r"(?m)^permissions:\n  contents: read$", text)
    assert "contents: write" not in text
    assert text.count("id-token: write") == 1
    assert text.count("attestations: write") == 1
    assert "attestations: read" in text
    assert "actions: read" in text
    for marker in (
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "dist/*.tar.gz",
        "dist/*.whl",
        "dist/*.cdx.json",
        "dist/SHA256SUMS",
        "verify-provenance:",
        "needs: build",
        "gh attestation verify",
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
        '--source-ref "$GITHUB_REF"',
        '--source-digest "$GITHUB_SHA"',
        '--cert-oidc-issuer "https://token.actions.githubusercontent.com"',
        '--predicate-type "https://slsa.dev/provenance/v1"',
        "--deny-self-hosted-runners",
        "python src/agentic_security_harness/attestation_policy.py",
    ):
        assert marker in text
    verify_job = text.split("  verify-provenance:", 1)[1]
    assert "PYTHONPATH=src" not in verify_job
    assert "python -m agentic_security_harness" not in verify_job
    for reference in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", text):
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), reference
