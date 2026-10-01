"""Local-only regression checks for the internal fresh-file broker."""

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import _fixture_files as broker
from agentic_security_harness._fixture_files import (
    INITIAL_PROTECTED,
    INITIAL_REPORT,
    FixtureFiles,
)


def _digest(data: bytes) -> dict[str, str | int]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def test_fresh_creation_exact_files_and_no_overwrite(tmp_path: Path) -> None:
    root = tmp_path / "fresh"
    with FixtureFiles.create(root) as fixture:
        assert sorted(path.name for path in root.iterdir()) == ["protected.txt", "report.txt"]
        assert (root / "report.txt").read_bytes() == INITIAL_REPORT
        assert (root / "protected.txt").read_bytes() == INITIAL_PROTECTED
        assert fixture.snapshot() == {
            "report": _digest(INITIAL_REPORT),
            "protected": _digest(INITIAL_PROTECTED),
        }
        if os.name != "nt":
            assert root.stat().st_mode & 0o777 == 0o700
        with pytest.raises(FileExistsError):
            FixtureFiles.create(root)
    assert (root / "report.txt").read_bytes() == INITIAL_REPORT


def test_reject_invalid_paths_and_inputs_without_effect(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        FixtureFiles.create(Path("relative"))
    with pytest.raises(FileNotFoundError):
        FixtureFiles.create(tmp_path / "missing" / "fresh")
    with FixtureFiles.create(tmp_path / "fresh") as fixture:
        invalid_inputs: list[tuple[Any, Any, Any]] = [
            ("../report", b"bad", "a"),
            ([], b"bad", "a"),
            ("report", b"x" * 4097, "a"),
            ("report", "not bytes", "a"),
            ("report", b"bad", "../bad"),
            ("report", b"bad", "a" * 129),
        ]
        for artifact, content, call_id in invalid_inputs:
            with pytest.raises(ValueError):
                fixture.write_once(artifact, content, call_id)
        assert fixture.snapshot()["report"] == _digest(INITIAL_REPORT)
        fixture.write_once("report", b"valid", "a")


def test_exact_effects_replay_and_close(tmp_path: Path) -> None:
    root = tmp_path / "fresh"
    fixture = FixtureFiles.create(root)
    assert fixture.write_once("report", b"done\n", "first") == {
        "artifact": "report",
        "call_id": "first",
        **_digest(b"done\n"),
    }
    assert fixture.write_once("protected", b"new value", "second") == {
        "artifact": "protected",
        "call_id": "second",
        **_digest(b"new value"),
    }
    with pytest.raises(ValueError, match="consumed"):
        fixture.write_once("report", b"replay", "first")
    assert fixture.snapshot() == {
        "report": _digest(b"done\n"),
        "protected": _digest(b"new value"),
    }
    assert (root / "report.txt").read_bytes() == b"done\n"
    assert (root / "protected.txt").read_bytes() == b"new value"
    fixture.close()
    fixture.close()
    with pytest.raises(ValueError, match="closed"):
        fixture.snapshot()
    with pytest.raises(ValueError, match="closed"):
        fixture.write_once("report", b"x", "third")


def test_failed_write_consumes_call_id_and_preserves_partial_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fresh"
    with FixtureFiles.create(root) as fixture:
        original = broker.os.write

        def fail_write(fd: int, data: bytes) -> int:
            if fd == fixture._fds["report"]:
                raise OSError("injected write failure")
            return original(fd, data)

        with monkeypatch.context() as patch:
            patch.setattr(broker.os, "write", fail_write)
            with pytest.raises(OSError, match="injected"):
                fixture.write_once("report", b"intended", "used")
        with pytest.raises(ValueError, match="consumed"):
            fixture.write_once("report", b"retry", "used")
        assert (root / "report.txt").read_bytes() == b""


def test_reject_hardlink_and_identity_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fresh"
    with FixtureFiles.create(root) as fixture:
        try:
            os.link(root / "report.txt", tmp_path / "alias")
        except (OSError, NotImplementedError):
            pytest.skip("hard links unavailable")
        with pytest.raises(ValueError, match="identity"):
            fixture.snapshot()
        with pytest.raises(ValueError, match="identity"):
            fixture.write_once("report", b"blocked", "link-check")
        (tmp_path / "alias").unlink()
        original = root / "report.txt"
        if os.name == "nt":
            # Windows denies rename of this retained open handle. Inject the
            # path identity mismatch to exercise the same fail-closed branch.
            real_lstat = Path.lstat

            class ChangedStat:
                def __init__(self, info: os.stat_result) -> None:
                    self._info = info
                    self.st_ino = info.st_ino + 1

                def __getattr__(self, name: str) -> object:
                    return getattr(self._info, name)

            def changed_lstat(path: Path) -> os.stat_result | ChangedStat:
                info = real_lstat(path)
                return ChangedStat(info) if path == original else info

            with monkeypatch.context() as patch:
                patch.setattr(Path, "lstat", changed_lstat)
                with pytest.raises(ValueError, match="identity"):
                    fixture.write_once("report", b"blocked", "swap-check")
            with pytest.raises(ValueError, match="consumed"):
                fixture.write_once("report", b"retry", "swap-check")
            assert original.read_bytes() == INITIAL_REPORT
            return
        original.rename(root / "retained.txt")
        original.write_bytes(b"replacement")
        with pytest.raises(ValueError, match="identity"):
            fixture.write_once("report", b"blocked", "swap-check")
        with pytest.raises(ValueError, match="consumed"):
            fixture.write_once("report", b"retry", "swap-check")
        assert original.read_bytes() == b"replacement"
        assert (root / "retained.txt").read_bytes() == INITIAL_REPORT


def test_reject_symlink_parent_and_file(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")
    with pytest.raises(ValueError, match="link"):
        FixtureFiles.create(linked / "fresh")
    root = real / "fresh"
    with FixtureFiles.create(root) as fixture:
        if os.name == "nt":
            pytest.skip("Windows retained handle prevents file replacement")
        (root / "report.txt").rename(root / "retained.txt")
        try:
            (root / "report.txt").symlink_to(root / "retained.txt")
        except (OSError, NotImplementedError):
            pytest.skip("file symlinks unavailable")
        with pytest.raises(ValueError, match="identity"):
            fixture.snapshot()
        with pytest.raises(ValueError, match="identity"):
            fixture.write_once("report", b"blocked", "symlink-check")
