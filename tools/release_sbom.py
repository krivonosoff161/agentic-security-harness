"""Build a deterministic CycloneDX SBOM bound to exact release subjects."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_TAG_REF = re.compile(r"^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _metadata_identity(raw: bytes) -> tuple[str, str, tuple[str, ...]]:
    metadata = BytesParser(policy=default).parsebytes(raw)
    name = str(metadata["Name"] or "")
    version = str(metadata["Version"] or "")
    if not name or not version:
        raise ValueError("distribution metadata is missing Name or Version")
    requirements = tuple(str(value) for value in metadata.get_all("Requires-Dist", []))
    return name, version, requirements


def _wheel_identity(path: Path) -> tuple[str, str, tuple[str, ...]]:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("wheel must contain exactly one METADATA file")
        return _metadata_identity(archive.read(names[0]))


def _sdist_identity(path: Path) -> tuple[str, str, tuple[str, ...]]:
    with tarfile.open(path, "r:gz") as archive:
        members = [
            member
            for member in archive.getmembers()
            if member.isfile() and member.name.count("/") == 1 and member.name.endswith("/PKG-INFO")
        ]
        if len(members) != 1:
            raise ValueError("sdist must contain exactly one root PKG-INFO file")
        stream = archive.extractfile(members[0])
        if stream is None:
            raise ValueError("sdist PKG-INFO is unreadable")
        return _metadata_identity(stream.read())


def _runtime_pins(path: Path) -> tuple[tuple[str, str], ...]:
    found: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _PIN.match(line.strip())
        if match is None:
            continue
        name = _normalize(match.group(1))
        version = match.group(2)
        if name in found:
            raise ValueError(f"duplicate runtime lock package: {name}")
        found[name] = version
    if not found:
        raise ValueError("runtime lock contains no exact package pins")
    return tuple(sorted(found.items()))


def _component(name: str, version: str) -> dict[str, Any]:
    normalized = _normalize(name)
    return {
        "type": "library",
        "bom-ref": f"pkg:pypi/{normalized}@{version}",
        "name": normalized,
        "version": version,
        "purl": f"pkg:pypi/{normalized}@{version}",
    }


def build_release_sbom(
    *,
    wheel: Path,
    sdist: Path,
    runtime_lock: Path,
    source_sha: str,
    source_ref: str,
) -> dict[str, Any]:
    """Return a deterministic CycloneDX document for the exact built subjects."""

    if _GIT_SHA.fullmatch(source_sha) is None:
        raise ValueError("source_sha must be a lowercase full Git SHA")
    if _TAG_REF.fullmatch(source_ref) is None:
        raise ValueError("source_ref must be a canonical refs/tags/vMAJOR.MINOR.PATCH ref")
    for label, path in (("wheel", wheel), ("sdist", sdist), ("runtime lock", runtime_lock)):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{label} must be a regular non-link file")

    wheel_identity = _wheel_identity(wheel)
    sdist_identity = _sdist_identity(sdist)
    if wheel_identity[:2] != sdist_identity[:2]:
        raise ValueError("wheel and sdist package identities differ")
    name, version = wheel_identity[:2]
    if source_ref != f"refs/tags/v{version}":
        raise ValueError("source tag does not match distribution version")
    if wheel_identity[2] != sdist_identity[2]:
        raise ValueError("wheel and sdist dependency metadata differ")

    pins = _runtime_pins(runtime_lock)
    pinned_names = {package for package, _ in pins}
    direct_dependencies: list[str] = []
    for requirement in wheel_identity[2]:
        marker = requirement.partition(";")[2]
        if marker and re.search(r"\bextra\s*==", marker):
            continue
        match = re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*", requirement)
        if match is None:
            raise ValueError("distribution contains an invalid dependency requirement")
        direct_dependencies.append(_normalize(match.group(0)))
    direct_dependencies = sorted(set(direct_dependencies))
    if not direct_dependencies or not set(direct_dependencies) <= pinned_names:
        raise ValueError("distribution dependencies are not closed by the runtime lock")

    root_ref = f"pkg:pypi/{_normalize(name)}@{version}"
    wheel_sha = _sha256(wheel)
    sdist_sha = _sha256(sdist)
    lock_sha = _sha256(runtime_lock)
    for digest in (wheel_sha, sdist_sha, lock_sha):
        if _SHA256.fullmatch(digest) is None:
            raise AssertionError("internal SHA-256 encoding failure")
    components = [_component(package, pin) for package, pin in pins]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": _normalize(name),
                "version": version,
                "purl": root_ref,
            },
            "properties": [
                {"name": "ash:release:source-ref", "value": source_ref},
                {"name": "ash:release:source-sha", "value": source_sha},
                {"name": "ash:release:wheel-filename", "value": wheel.name},
                {"name": "ash:release:wheel-sha256", "value": wheel_sha},
                {"name": "ash:release:sdist-filename", "value": sdist.name},
                {"name": "ash:release:sdist-sha256", "value": sdist_sha},
                {"name": "ash:release:runtime-lock-sha256", "value": lock_sha},
            ],
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": [
                    f"pkg:pypi/{package}@{dict(pins)[package]}"
                    for package in direct_dependencies
                ],
            },
            *({"ref": component["bom-ref"], "dependsOn": []} for component in components),
        ],
    }


def encoded_sbom(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = encoded_sbom(
        build_release_sbom(
            wheel=args.wheel,
            sdist=args.sdist,
            runtime_lock=args.runtime_lock,
            source_sha=args.source_sha,
            source_ref=args.source_ref,
        )
    )
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != content:
            raise RuntimeError("release SBOM is stale or does not match exact subjects")
    else:
        if args.output.exists():
            raise FileExistsError("refusing to overwrite release SBOM")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
