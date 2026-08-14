from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from tools.release_sbom import build_release_sbom, encoded_sbom


def _metadata(version: str = "1.2.3", requirement: str = "pydantic>=2,<3") -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: agentic-security-harness\n"
        f"Version: {version}\n"
        f"Requires-Dist: {requirement}\n"
        'Requires-Dist: pytest>=8; extra == "dev"\n\n'
    ).encode()


def _subjects(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheel = tmp_path / "agentic_security_harness-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agentic_security_harness-1.2.3.dist-info/METADATA", _metadata())
    sdist = tmp_path / "agentic_security_harness-1.2.3.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        payload = _metadata()
        member = tarfile.TarInfo("agentic_security_harness-1.2.3/PKG-INFO")
        member.size = len(payload)
        member.mtime = 0
        archive.addfile(member, io.BytesIO(payload))
    lock = tmp_path / "runtime.txt"
    lock.write_text(
        "annotated-types==0.7.0 \\\n"
        "pydantic==2.13.4 \\\n"
        "pydantic-core==2.46.4 \\\n"
        "typing-extensions==4.15.0 \\\n"
        "typing-inspection==0.4.2 \\\n",
        encoding="utf-8",
    )
    return wheel, sdist, lock


def _build(tmp_path: Path) -> dict[str, object]:
    wheel, sdist, lock = _subjects(tmp_path)
    return _document(wheel, sdist, lock)


def _document(wheel: Path, sdist: Path, lock: Path) -> dict[str, object]:
    return build_release_sbom(
        wheel=wheel,
        sdist=sdist,
        runtime_lock=lock,
        source_sha="a" * 40,
        source_ref="refs/tags/v1.2.3",
    )


def test_sbom_is_deterministic_cyclonedx_and_binds_exact_subjects(tmp_path: Path) -> None:
    wheel, sdist, lock = _subjects(tmp_path)
    first = build_release_sbom(
        wheel=wheel,
        sdist=sdist,
        runtime_lock=lock,
        source_sha="a" * 40,
        source_ref="refs/tags/v1.2.3",
    )
    second = build_release_sbom(
        wheel=wheel,
        sdist=sdist,
        runtime_lock=lock,
        source_sha="a" * 40,
        source_ref="refs/tags/v1.2.3",
    )
    assert encoded_sbom(first) == encoded_sbom(second)
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.6"
    properties = {
        row["name"]: row["value"]
        for row in first["metadata"]["properties"]
    }
    assert properties["ash:release:wheel-sha256"] == hashlib.sha256(
        wheel.read_bytes()
    ).hexdigest()
    assert properties["ash:release:sdist-sha256"] == hashlib.sha256(
        sdist.read_bytes()
    ).hexdigest()
    assert properties["ash:release:runtime-lock-sha256"] == hashlib.sha256(
        lock.read_bytes()
    ).hexdigest()
    assert {component["name"] for component in first["components"]} == {
        "annotated-types",
        "pydantic",
        "pydantic-core",
        "typing-extensions",
        "typing-inspection",
    }
    json.loads(encoded_sbom(first))


def test_subject_or_lock_drift_changes_sbom(tmp_path: Path) -> None:
    wheel, sdist, lock = _subjects(tmp_path)
    baseline = encoded_sbom(_document(wheel, sdist, lock))
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("agentic_security_harness/synthetic.txt", "changed")
    changed_subject = encoded_sbom(_document(wheel, sdist, lock))
    assert baseline != changed_subject
    lock.write_text(lock.read_text(encoding="utf-8") + "extra==1.0.0\n", encoding="utf-8")
    assert changed_subject != encoded_sbom(_document(wheel, sdist, lock))


@pytest.mark.parametrize(
    ("source_sha", "source_ref", "message"),
    [
        ("A" * 40, "refs/tags/v1.2.3", "lowercase full Git SHA"),
        ("a" * 40, "refs/heads/main", "canonical refs/tags"),
        ("a" * 40, "refs/tags/v1.2.4", "does not match distribution version"),
    ],
)
def test_source_identity_drift_fails_closed(
    tmp_path: Path, source_sha: str, source_ref: str, message: str
) -> None:
    wheel, sdist, lock = _subjects(tmp_path)
    with pytest.raises(ValueError, match=message):
        build_release_sbom(
            wheel=wheel,
            sdist=sdist,
            runtime_lock=lock,
            source_sha=source_sha,
            source_ref=source_ref,
        )


def test_distribution_identity_and_dependency_closure_fail_closed(tmp_path: Path) -> None:
    wheel, sdist, lock = _subjects(tmp_path)
    with tarfile.open(sdist, "w:gz") as archive:
        payload = _metadata(version="9.9.9")
        member = tarfile.TarInfo("agentic_security_harness-9.9.9/PKG-INFO")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    with pytest.raises(ValueError, match="package identities differ"):
        build_release_sbom(
            wheel=wheel,
            sdist=sdist,
            runtime_lock=lock,
            source_sha="a" * 40,
            source_ref="refs/tags/v1.2.3",
        )

    wheel, sdist, lock = _subjects(tmp_path)
    lock.write_text("annotated-types==0.7.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not closed by the runtime lock"):
        build_release_sbom(
            wheel=wheel,
            sdist=sdist,
            runtime_lock=lock,
            source_sha="a" * 40,
            source_ref="refs/tags/v1.2.3",
        )


def test_returned_document_is_not_shared_between_calls(tmp_path: Path) -> None:
    first = _build(tmp_path)
    changed = copy.deepcopy(first)
    changed["version"] = 2
    assert changed != _build(tmp_path)
