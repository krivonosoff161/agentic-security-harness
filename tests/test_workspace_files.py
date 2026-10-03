"""Focused checks for host-configured, exclusive workspace file effects."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agentic_security_harness import _workspace_files as broker
from agentic_security_harness._workspace_files import WorkspaceFiles


def _receipt(alias: str, content: bytes) -> dict[str, str | int]:
    return {"artifact": alias, "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}


def test_open_is_effect_free_then_writes_exact_file_once(tmp_path: Path) -> None:
    with WorkspaceFiles.open(tmp_path, {"report": "answer.txt", "notes": "notes.md"}) as files:
        assert list(tmp_path.iterdir()) == []
        assert files.write_once("report", "Привет\n".encode()) == _receipt(
            "report", "Привет\n".encode()
        )
        assert files.readback_sha("report") == _receipt("report", "Привет\n".encode())
        with pytest.raises(ValueError, match="consumed"):
            files.write_once("report", b"again")
        assert files.write_once("notes", b"# Notes\n") == _receipt("notes", b"# Notes\n")
    assert (tmp_path / "answer.txt").read_bytes() == "Привет\n".encode()
    assert (tmp_path / "notes.md").read_bytes() == b"# Notes\n"


@pytest.mark.parametrize("targets", [
    {"../bad": "good.txt"}, {"bad/name": "good.txt"},
    {"good": "../bad"}, {"good": "sub/file"}, {"good": "sub\\file"},
    {"good": "C:ads"}, {"good": "CON.txt"}, {"good": "Lpt1.log"},
    {"good": "trail."}, {"good": "trail "}, {"good": "a?.txt"},
    {"one": "Report.txt", "two": "report.TXT"},
    {"Report": "one.txt", "report": "two.txt"},
])
def test_invalid_host_targets_rejected_without_effect(tmp_path: Path,
                                                      targets: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        WorkspaceFiles.open(tmp_path, targets)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("limit", [0, -1, 1_048_577, True, 1.0])
def test_invalid_byte_limit_rejected(tmp_path: Path, limit: object) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        WorkspaceFiles.open(tmp_path, {"report": "report.txt"}, limit)  # type: ignore[arg-type]


def test_invalid_proposal_and_oversize_do_not_create_file(tmp_path: Path) -> None:
    with WorkspaceFiles.open(tmp_path, {"report": "report.txt"}, max_bytes=4) as files:
        for alias, content in (("../report.txt", b"x"), ("report", b"12345"),
                               ("report", "text")):
            with pytest.raises(ValueError):
                files.write_once(alias, content)  # type: ignore[arg-type]
        assert list(tmp_path.iterdir()) == []
        assert files.write_once("report", b"1234") == _receipt("report", b"1234")


def test_existing_output_is_never_overwritten_and_failure_poisoned(tmp_path: Path) -> None:
    existing = tmp_path / "report.txt"
    existing.write_bytes(b"owner content")
    with WorkspaceFiles.open(tmp_path, {"report": "report.txt", "other": "other.txt"}) as files:
        with pytest.raises(FileExistsError):
            files.write_once("report", b"replacement")
        with pytest.raises(ValueError, match="failed"):
            files.write_once("other", b"new")
    assert existing.read_bytes() == b"owner content"
    assert not (tmp_path / "other.txt").exists()


def test_symlink_root_and_existing_symlink_target_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory links unavailable")
    with pytest.raises(ValueError, match="link"):
        WorkspaceFiles.open(linked, {"report": "report.txt"})
    source = tmp_path / "source.txt"
    source.write_bytes(b"unchanged")
    target = root / "report.txt"
    try:
        target.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("file links unavailable")
    with WorkspaceFiles.open(root, {"report": "report.txt"}) as files:
        with pytest.raises(FileExistsError):
            files.write_once("report", b"replacement")
    assert source.read_bytes() == b"unchanged"


def test_failed_partial_write_is_retained_and_no_retry(tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_after_prefix(fd: int, content: bytes) -> None:
        os.write(fd, content[:2])
        raise OSError("injected partial write")

    with WorkspaceFiles.open(tmp_path, {"report": "report.txt", "other": "other.txt"}) as files:
        with monkeypatch.context() as patch:
            patch.setattr(broker, "_write_all", fail_after_prefix)
            with pytest.raises(OSError, match="partial"):
                files.write_once("report", b"payload")
        with pytest.raises(ValueError, match="failed"):
            files.write_once("report", b"retry")
        with pytest.raises(ValueError, match="failed"):
            files.write_once("other", b"retry")
    assert (tmp_path / "report.txt").read_bytes() == b"pa"
    assert not (tmp_path / "other.txt").exists()


def test_concurrent_writes_to_one_alias_are_serialized(tmp_path: Path) -> None:
    with WorkspaceFiles.open(tmp_path, {"report": "report.txt"}) as files:
        def write(content: bytes) -> str:
            try:
                files.write_once("report", content)
                return "written"
            except ValueError as exc:
                assert "consumed" in str(exc)
                return "consumed"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(write, (b"one", b"two")))
        assert sorted(outcomes) == ["consumed", "written"]
    assert (tmp_path / "report.txt").read_bytes() in (b"one", b"two")


def test_readback_detects_hardlink_or_identity_change(tmp_path: Path) -> None:
    target = tmp_path / "report.txt"
    with WorkspaceFiles.open(tmp_path, {"report": "report.txt"}) as files:
        files.write_once("report", b"original")
        alias = tmp_path / "alias.txt"
        try:
            os.link(target, alias)
        except (OSError, NotImplementedError):
            pytest.skip("hard links unavailable")
        with pytest.raises(ValueError, match="identity"):
            files.readback_sha("report")
    assert target.read_bytes() == b"original"
