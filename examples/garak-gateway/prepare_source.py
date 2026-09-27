"""Explicit network/setup step: download one hash-pinned public garak source archive.

Does not install or import garak, run models, or discover any local configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import urllib.request
import zipfile
from pathlib import Path


def extract_checked(bundle: zipfile.ZipFile, destination: Path, inert_links: set[str]) -> None:
    members = bundle.infolist()
    if len(members) > 5000 or sum(member.file_size for member in members) > 50_000_000:
        raise ValueError("archive expansion limit")
    observed_links = set()
    for member in members:
        path = destination / member.filename
        if not path.resolve().is_relative_to(destination):
            raise ValueError("archive member rejected")
        if stat.S_ISLNK(member.external_attr >> 16):
            observed_links.add(member.filename)
    if observed_links != inert_links:
        raise ValueError("archive link inventory mismatch")
    destination.mkdir(parents=True)
    # ZipFile extracts link entries as ordinary byte files, never OS symlinks.
    # The one pinned calibration link is inert text, not used by this detector.
    bundle.extractall(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    destination = args.out.resolve()
    if destination.exists():
        raise SystemExit("source destination must be new")
    manifest = json.loads((Path(__file__).parent / "manifest.json").read_bytes())
    expected_url = "https://codeload.github.com/NVIDIA/garak/zip/" + manifest["garak_source_sha"]
    if manifest["garak_archive_url"] != expected_url:
        raise SystemExit("archive URL mismatch")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(expected_url, timeout=60) as response:
        if response.geturl() != expected_url:
            raise SystemExit("archive redirect rejected")
        archive = response.read(10_000_001)
    if len(archive) > 10_000_000 or hashlib.sha256(archive).hexdigest() != manifest[
        "garak_archive_sha256"
    ]:
        raise SystemExit("archive hash or size mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        extract_checked(bundle, destination, set(manifest["inert_archive_link_members"]))
    print("Verified source:", destination / ("garak-" + manifest["garak_source_sha"]))


if __name__ == "__main__":
    main()
