"""Independent fixtures for release sdist normalization."""

from __future__ import annotations

import gzip
import io
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import pytest
from tools.normalize_sdist import normalize_sdist

EPOCH = 1_700_000_000


def _write_sdist(path: Path, *, source_time: int, member_time: int) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename=path.name, mode="wb", fileobj=raw, mtime=source_time) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo("package-1.0")
                directory.type = tarfile.DIRTYPE
                directory.mtime = member_time
                directory.uid = 1000
                directory.gid = 1000
                archive.addfile(directory)
                payload = b"exact source bytes\n"
                source = tarfile.TarInfo("package-1.0/module.py")
                source.size = len(payload)
                source.mtime = member_time
                source.uid = 1000
                source.gid = 1000
                archive.addfile(source, io.BytesIO(payload))


def test_normalization_makes_metadata_different_sdists_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_sdist(first, source_time=10, member_time=20)
    _write_sdist(second, source_time=30, member_time=40)
    assert first.read_bytes() != second.read_bytes()

    normalize_sdist(first, epoch=EPOCH)
    normalize_sdist(second, epoch=EPOCH)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, "r:gz") as archive:
        assert [item.name for item in archive.getmembers()] == [
            "package-1.0",
            "package-1.0/module.py",
        ]
        assert all(item.mtime == EPOCH for item in archive.getmembers())
        assert all(item.uid == item.gid == 0 for item in archive.getmembers())


def test_normalization_uses_bounded_temporary_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}
    original_named_temporary_file = tempfile.NamedTemporaryFile

    def capture_named_temporary_file(*args: Any, **kwargs: Any) -> object:
        observed.update(kwargs)
        return original_named_temporary_file(*args, **kwargs)

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", capture_named_temporary_file)
    source = tmp_path / ("long-source-distribution-name-" * 3 + ".tar.gz")
    _write_sdist(source, source_time=10, member_time=20)

    normalize_sdist(source, epoch=EPOCH)

    assert observed["prefix"] == ".sdist-"


def test_normalization_rejects_link_members(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        link = tarfile.TarInfo("package-1.0/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(ValueError, match="unsupported sdist member type"):
        normalize_sdist(source, epoch=EPOCH)
