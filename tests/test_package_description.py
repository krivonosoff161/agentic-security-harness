from __future__ import annotations

import io
import json
import tarfile
import textwrap
import urllib.request
import zipfile
from pathlib import Path

import pytest
from tools.check_package_description import (
    README,
    check_distribution,
    check_metadata,
    source_description,
)

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTION = """# Package
Distribution version: **1.2.3**.
python -m pip install agentic-security-harness==1.2.3
[Documentation](https://example.org/docs)
""".rstrip("\n")
NAME = "agentic-security-harness"


def _metadata(description: str = DESCRIPTION, version: str = "1.2.3") -> bytes:
    return (
        f"Metadata-Version: 2.4\nName: {NAME}\nVersion: {version}\n"
        f"Description-Content-Type: text/markdown\n\n{description}\n"
    ).encode()


def _source(tmp_path: Path, description: str = DESCRIPTION) -> None:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname="{NAME}"\nversion="1.2.3"\nreadme="{README}"\n', "utf-8"
    )
    (tmp_path / README).write_text(description, "utf-8")


def test_current_distribution_description_is_version_bound() -> None:
    name, version, description = source_description(ROOT)
    assert name == NAME
    assert version == "1.9.1"
    assert "not a measurement of this patch" in description


@pytest.mark.parametrize("description", [
    DESCRIPTION.replace("==1.2.3", "==1.2.2"),
    DESCRIPTION.replace("**1.2.3**", "**1.2.2**"),
    DESCRIPTION.replace("https://example.org/docs", "docs/guide.md"),
    DESCRIPTION + "\nIn development — current release\n",
    DESCRIPTION + "\nCurrent published package: 1.2.2\n",
])
def test_stale_source_description_is_rejected(tmp_path: Path, description: str) -> None:
    _source(tmp_path, description)
    with pytest.raises(ValueError):
        source_description(tmp_path)


def test_live_repository_readme_cannot_be_packaged(tmp_path: Path) -> None:
    _source(tmp_path)
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text("utf-8").replace(README, "README.md"), "utf-8")
    with pytest.raises(ValueError, match="must be PACKAGE_README"):
        source_description(tmp_path)


@pytest.mark.parametrize("raw", [
    _metadata("stale body"),
    _metadata(version="1.2.2"),
    _metadata().replace(b"text/markdown", b"text/plain"),
    _metadata().replace(b"Name: ", b"Name: wrong\nName: "),
])
def test_archive_metadata_mismatch_is_rejected(raw: bytes) -> None:
    with pytest.raises(ValueError):
        check_metadata(raw, name=NAME, version="1.2.3", description=DESCRIPTION)


def test_metadata_newline_conventions_do_not_change_description() -> None:
    check_metadata(
        _metadata().replace(b"\n", b"\r\n"), name=NAME, version="1.2.3", description=DESCRIPTION
    )


def _archives(tmp_path: Path, body: str, readme: str | None) -> tuple[Path, Path]:
    wheel = tmp_path / "package.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("package-1.2.3.dist-info/METADATA", _metadata(body))
    sdist = tmp_path / "package.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        entries = {"package-1.2.3/PKG-INFO": _metadata(body)}
        if readme is not None:
            entries[f"package-1.2.3/{README}"] = readme.encode("utf-8")
        for name, content in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return wheel, sdist


def test_both_archive_descriptions_are_checked_without_extraction(tmp_path: Path) -> None:
    for path in _archives(tmp_path, DESCRIPTION, DESCRIPTION):
        check_distribution(path, name=NAME, version="1.2.3", description=DESCRIPTION)
    assert not (tmp_path / "package-1.2.3").exists()


def test_stale_embedded_readme_is_rejected_even_if_source_is_current(tmp_path: Path) -> None:
    for path in _archives(tmp_path, "stale README snapshot", DESCRIPTION):
        with pytest.raises(ValueError, match="description differs"):
            check_distribution(path, name=NAME, version="1.2.3", description=DESCRIPTION)


@pytest.mark.parametrize("readme", [None, "stale sdist source"])
def test_sdist_must_retain_the_exact_description_source(tmp_path: Path, readme: str | None) -> None:
    _, sdist = _archives(tmp_path, DESCRIPTION, readme)
    with pytest.raises(ValueError):
        check_distribution(sdist, name=NAME, version="1.2.3", description=DESCRIPTION)


def test_archive_check_runs_before_release_upload_and_in_pr_ci() -> None:
    command = "python tools/check_package_description.py dist/*.whl dist/*.tar.gz"
    for name in ("ci.yml", "release.yml"):
        text = (ROOT / ".github/workflows" / name).read_text("utf-8")
        assert command in text
        assert text.index("python -m build --no-isolation") < text.index(command)
        if name == "release.yml":
            assert text.index(command) < text.index("- name: Attest exact release subjects")


def test_container_build_inputs_include_the_distribution_readme() -> None:
    for path in ("Dockerfile", "Dockerfile.gateway"):
        assert "COPY pyproject.toml README.md PACKAGE_README.md LICENSE NOTICE ./" in (
            ROOT / path
        ).read_text("utf-8")
    assert f"!{README}" in (ROOT / ".dockerignore").read_text("utf-8").splitlines()


@pytest.mark.parametrize("mismatch", [None, "description", "description_content_type", "version"])
def test_published_index_description_is_compared_to_the_attested_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str | None,
) -> None:
    import hashlib

    dist = tmp_path / "dist"
    dist.mkdir()
    wheel, sdist = _archives(dist, DESCRIPTION, DESCRIPTION)
    info = {
        "name": NAME, "version": "1.2.3", "description": DESCRIPTION,
        "description_content_type": "text/markdown",
    }
    if mismatch is not None:
        info[mismatch] = "stale"
    payload = {"info": info, "urls": [
        {"filename": path.name, "packagetype": kind,
         "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
        for path, kind in ((wheel, "bdist_wheel"), (sdist, "sdist"))
    ]}

    def fake_urlopen(url: str, timeout: int) -> io.BytesIO:
        assert url == "https://pypi.org/pypi/agentic-security-harness/1.2.3/json"
        assert timeout == 30
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_TAG", "v1.2.3")
    monkeypatch.setenv("INDEX_HOSTS", '["pypi.org"]')
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    text = (ROOT / ".github/workflows/verify-published-release.yml").read_text("utf-8")
    step = text.split("- name: Verify selected index filename/hash equality", 1)[1]
    script = textwrap.dedent(step.split("python - <<'PY'\n", 1)[1].split("          PY", 1)[0])
    if mismatch is None:
        exec(compile(script, "published-index-description", "exec"), {})
    else:
        with pytest.raises(SystemExit, match="description metadata differs"):
            exec(compile(script, "published-index-description", "exec"), {})
