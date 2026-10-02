"""Check trusted local build descriptions without installing or extracting code."""

from __future__ import annotations

import argparse
import hashlib
import re
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

README = "PACKAGE_README.md"


def normalized(text: str) -> str:
    return text.replace("\r\n", "\n").rstrip("\n")


def source_description(root: Path) -> tuple[str, str, str]:
    project = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))["project"]
    if project.get("readme") != README:
        raise ValueError("distribution readme must be PACKAGE_README.md")
    name, version = project["name"], project["version"]
    description = normalized((root / README).read_text("utf-8"))
    if f"Distribution version: **{version}**." not in description:
        raise ValueError("package description version differs from project version")
    pins = re.findall(r"agentic-security-harness(?:\[[^\]]+\])?==([^\s`\"']+)", description)
    if not pins or set(pins) != {version}:
        raise ValueError("package install pins differ from project version")
    for phrase in (
        "in development", "current published package", "promotion pending",
        "not yet published", "publication pending",
    ):
        if phrase in description.casefold():
            raise ValueError("package description contains changing publication status")
    links = re.findall(r"\]\(([^\s)]+)\)", description)
    if not links or any(not link.startswith("https://") for link in links):
        raise ValueError("package description links must be absolute HTTPS URLs")
    return str(name), str(version), description


def check_metadata(raw: bytes, *, name: str, version: str, description: str) -> None:
    metadata = BytesParser(policy=default).parsebytes(raw)
    for key, expected in (
        ("Name", name), ("Version", version), ("Description-Content-Type", "text/markdown"),
    ):
        values = metadata.get_all(key, [])
        if len(values) != 1 or str(values[0]) != expected:
            raise ValueError(f"distribution metadata {key} differs from source")
    body = metadata.get_payload(decode=True)
    if not isinstance(body, bytes) or normalized(body.decode("utf-8")) != description:
        raise ValueError("distribution description differs from source")


def check_distribution(path: Path, *, name: str, version: str, description: str) -> None:
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            members = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
            if len(members) != 1:
                raise ValueError("wheel must have one METADATA")
            raw = archive.read(members[0])
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            roots = [m for m in archive.getmembers() if m.isfile() and m.name.count("/") == 1]
            metadata = [m for m in roots if m.name.endswith("/PKG-INFO")]
            readmes = [m for m in roots if m.name.endswith(f"/{README}")]
            if len(metadata) != 1 or len(readmes) != 1:
                raise ValueError("sdist must have one root PKG-INFO and package readme")
            stream = archive.extractfile(metadata[0])
            readme_stream = archive.extractfile(readmes[0])
            if stream is None or readme_stream is None:
                raise ValueError("sdist metadata is unreadable")
            raw = stream.read()
            if normalized(readme_stream.read().decode("utf-8")) != description:
                raise ValueError("sdist package readme differs from source")
    else:
        raise ValueError("expected a wheel or .tar.gz sdist")
    check_metadata(raw, name=name, version=version, description=description)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distributions", nargs="+", type=Path)
    args = parser.parse_args()
    name, version, description = source_description(Path(__file__).resolve().parents[1])
    paths = args.distributions
    if (len(paths) != 2 or sum(p.name.endswith(".whl") for p in paths) != 1
            or sum(p.name.endswith(".tar.gz") for p in paths) != 1):
        raise SystemExit("check requires exactly one wheel and one sdist")
    try:
        for path in paths:
            check_distribution(path, name=name, version=version, description=description)
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
    digest = hashlib.sha256(description.encode("utf-8")).hexdigest()
    print(f"PASS: {name} {version}; wheel/sdist description sha256={digest}")


if __name__ == "__main__":
    main()
