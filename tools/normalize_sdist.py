"""Normalize a trusted, freshly built Python sdist for byte reproducibility."""

from __future__ import annotations

import argparse
import copy
import gzip
import io
import os
import tarfile
import tempfile
from pathlib import Path

_MAX_MEMBERS = 10_000
_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024


def normalize_sdist(path: Path, *, epoch: int) -> None:
    """Rewrite one local ``.tar.gz`` with canonical order, owners, modes, and times."""

    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
    source = path.resolve(strict=True)
    if not source.is_file() or not source.name.endswith(".tar.gz"):
        raise ValueError("sdist path must name one existing .tar.gz file")

    entries: list[tuple[tarfile.TarInfo, bytes]] = []
    total_size = 0
    with tarfile.open(source, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > _MAX_MEMBERS:
            raise ValueError("sdist contains too many members")
        for member in members:
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"unsupported sdist member type: {member.name}")
            if Path(member.name).is_absolute() or ".." in Path(member.name).parts:
                raise ValueError(f"unsafe sdist member path: {member.name}")
            payload = b""
            if member.isfile():
                handle = archive.extractfile(member)
                if handle is None:
                    raise ValueError(f"sdist member is unreadable: {member.name}")
                payload = handle.read()
                total_size += len(payload)
                if total_size > _MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("sdist exceeds the normalization size limit")
            entries.append((copy.copy(member), payload))

    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix=".sdist-", suffix=".tmp", dir=source.parent, delete=False
        ) as temporary:
            temporary_name = temporary.name
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=temporary, compresslevel=9, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as output:
                    for member, payload in sorted(entries, key=lambda item: item[0].name):
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        member.mtime = epoch
                        member.mode = 0o755 if member.isdir() else 0o644
                        member.pax_headers = {}
                        output.addfile(member, io.BytesIO(payload) if member.isfile() else None)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, source)
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    try:
        normalize_sdist(args.sdist, epoch=args.epoch)
    except (OSError, tarfile.TarError, ValueError) as exc:
        print(f"sdist normalization failed: {type(exc).__name__}")
        return 1
    print(f"normalized reproducible sdist: {args.sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
