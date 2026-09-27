"""Static fail-closed contract for published-release verification."""

import hashlib
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

    assert text.count('"index": "testpypi"') == 2
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
    assert "release-example/examples/garak-gateway/check.py" in text
    assert "garak-observation.json --require-detector" in text
    assert 'if [ "$RELEASE_VERSION" = "1.6.0" ]; then' in text
    assert '--core-version "$RELEASE_VERSION"' in text
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
    staging = [
        {"index": "testpypi", "os": os, "python": "3.11"}
        for os in ("ubuntu-latest", "windows-latest")
    ]
    if target == "testpypi":
        assert hosts == ["test.pypi.org"]
        assert matrix == staging
    else:
        assert hosts == ["test.pypi.org", "pypi.org"]
        assert matrix == staging + [
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


def _garak_lock_script() -> str:
    step = _workflow().split("- name: Select version-bound garak smoke lock", 1)[1]
    body = step.split("python - <<'PY'\n", 1)[1].split("          PY", 1)[0]
    return textwrap.dedent(body)


def _garak_locks(tmp_path: Path) -> tuple[Path, Path]:
    corrected = tmp_path / "verification-policy/requirements/verification/garak-v1.7.0.txt"
    corrected.parent.mkdir(parents=True)
    data = (ROOT / "requirements/verification/garak-v1.7.0.txt").read_bytes()
    corrected.write_bytes(data)
    original = tmp_path / "release-example/examples/garak-gateway/requirements-smoke.txt"
    original.parent.mkdir(parents=True)
    lines = data.decode("utf-8").splitlines()
    lines[1] = "# Python 3.11, Linux x86_64 or Windows AMD64. Do not install GPU/model packages."
    lines = [line for line in lines if not any(digest in line for digest in (
        "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
        "0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6",
    ))]
    lines[6] = lines[6].removesuffix(" \\")
    original.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    assert hashlib.sha256(original.read_bytes()).hexdigest() == (
        "17ba5d65707a935fdf8f78b4321a7f1bd5b682b0cdde1f96bd9d190c97e9b6c9")
    return original, corrected


@pytest.mark.parametrize("mutation", [None, "original", "corrected", "missing"])
def test_v170_lock_correction_binds_both_byte_sequences(
    mutation: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, corrected = _garak_locks(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_VERSION", "1.7.0")
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    if mutation in {"original", "corrected"}:
        subject = original if mutation == "original" else corrected
        subject.write_bytes(subject.read_bytes() + b"# changed\n")
    elif mutation == "missing":
        corrected.unlink()
    if mutation is not None:
        with pytest.raises((SystemExit, FileNotFoundError)):
            exec(compile(_garak_lock_script(), str(WORKFLOW), "exec"), {})
        assert not output.exists()
    else:
        exec(compile(_garak_lock_script(), str(WORKFLOW), "exec"), {})
        assert output.read_text().strip() == (
            "path=verification-policy/requirements/verification/garak-v1.7.0.txt")


@pytest.mark.parametrize("version", ["1.6.0", "1.7.1", "2.0.0"])
def test_other_releases_do_not_inherit_v170_lock_correction(
    version: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_VERSION", version)
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    exec(compile(_garak_lock_script(), str(WORKFLOW), "exec"), {})
    assert output.read_text().strip() == (
        "path=release-example/examples/garak-gateway/requirements-smoke.txt")


def test_corrected_lock_and_ci_cover_declared_python_matrix() -> None:
    corrected = (ROOT / "requirements/verification/garak-v1.7.0.txt").read_bytes()
    assert hashlib.sha256(corrected).hexdigest() == (
        "9439032ca986b7b20f196507b92200fbb09a3af935457a2931af3561eb8b8ac1")
    assert corrected == (ROOT / "examples/garak-gateway/requirements-smoke.txt").read_bytes()
    text = (ROOT / ".github/workflows/garak-connector.yml").read_text()
    for version in ("3.11", "3.12", "3.13"):
        assert f'{{os: ubuntu-latest, python: "{version}"}}' in text
    assert '{os: windows-latest, python: "3.11"}' in text
    assert 'python-version: ${{ matrix.python }}' in text
    assert 'garak-observation-${{ matrix.os }}-${{ matrix.python }}' in text
    assert '--only-binary=:all: --require-hashes -r "$GARAK_SMOKE_LOCK"' in _workflow()
