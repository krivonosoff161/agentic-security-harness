"""Bounded writes to host-configured new files in one local directory.

The caller owns the root and exact basename allowlist. This checks local file
identity; it is not an OS sandbox or protection from another process with
filesystem access to the root.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType

from agentic_security_harness._fixture_files import (
    _checked_directory,
    _identity,
    _not_reparse,
    _write_all,
)

_ALIAS = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_WINDOWS_INVALID = set('<>:"/\\|?*')
_WINDOWS_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])\Z", re.I)


def _validate_filename(filename: str) -> None:
    if (
        type(filename) is not str
        or not filename
        or filename in {".", ".."}
        or filename[-1] in {".", " "}
        or any(character in _WINDOWS_INVALID or ord(character) < 32 for character in filename)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in filename)
        or _WINDOWS_DEVICE.fullmatch(filename.split(".", 1)[0]) is not None
        or len(filename.encode("utf-8")) > 255
    ):
        raise ValueError("target must be one portable filename")


class WorkspaceFiles:
    """Retain descriptors for exact, exclusive, one-shot configured outputs."""

    def __init__(self, root: Path, root_identity: tuple[int, int],
                 targets: dict[str, str], max_bytes: int) -> None:
        self._root = root
        self._root_identity = root_identity
        self._targets = targets
        self._max_bytes = max_bytes
        self._fds: dict[str, int] = {}
        self._identities: dict[str, tuple[int, int]] = {}
        self._seen: set[str] = set()
        self._closed = False
        self._failed = False
        self._lock = threading.RLock()

    @classmethod
    def open(cls, root: Path, targets: Mapping[str, str],
             max_bytes: int = 65_536) -> WorkspaceFiles:
        """Validate host configuration without creating or changing files."""
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("root must be an absolute Path")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1_048_576:
            raise ValueError("max_bytes must be between 1 and 1048576")
        if not isinstance(targets, Mapping) or not targets:
            raise ValueError("targets must be a nonempty mapping")
        checked: dict[str, str] = {}
        folded: set[str] = set()
        for alias, filename in targets.items():
            if type(alias) is not str or _ALIAS.fullmatch(alias) is None:
                raise ValueError("target alias must be simple ASCII")
            _validate_filename(filename)
            if alias.casefold() in (key.casefold() for key in checked):
                raise ValueError("target aliases collide ignoring case")
            if filename.casefold() in folded:
                raise ValueError("target filenames collide ignoring case")
            checked[alias] = filename
            folded.add(filename.casefold())
        root_info = _checked_directory(root)
        return cls(root, _identity(root_info), checked, max_bytes)

    def _check_root(self) -> None:
        if _identity(_checked_directory(self._root)) != self._root_identity:
            raise ValueError("workspace root identity changed")

    def _check_file(self, alias: str) -> None:
        fd_info = os.fstat(self._fds[alias])
        path_info = (self._root / self._targets[alias]).lstat()
        if (
            not stat.S_ISREG(fd_info.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or not _not_reparse(fd_info)
            or not _not_reparse(path_info)
            or fd_info.st_nlink != 1
            or path_info.st_nlink != 1
            or _identity(fd_info) != self._identities[alias]
            or _identity(path_info) != self._identities[alias]
        ):
            raise ValueError("workspace file identity changed")

    def write_once(self, alias: str, content: bytes) -> dict[str, str | int]:
        if type(alias) is not str or alias not in self._targets:
            raise ValueError("unknown target alias")
        if type(content) is not bytes or len(content) > self._max_bytes:
            raise ValueError("content exceeds configured byte limit")
        with self._lock:
            if self._closed or self._failed:
                raise ValueError("workspace files are closed or failed")
            if alias in self._seen:
                raise ValueError("target alias already consumed")
            self._seen.add(alias)
            try:
                self._check_root()
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                fd = os.open(self._root / self._targets[alias], flags, 0o600)
                self._fds[alias] = fd
                self._identities[alias] = _identity(os.fstat(fd))
                self._check_root()
                self._check_file(alias)
                _write_all(fd, content)
                os.fsync(fd)
                self._check_root()
                self._check_file(alias)
                return {
                    "artifact": alias,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            except BaseException:
                # The file may be partial or complete; never retry in this broker.
                self._failed = True
                raise

    def readback_sha(self, alias: str) -> dict[str, str | int]:
        """Hash a successful output through its retained descriptor."""
        with self._lock:
            if self._closed or self._failed:
                raise ValueError("workspace files are closed or failed")
            if alias not in self._fds:
                raise ValueError("target alias has no completed write")
            self._check_root()
            self._check_file(alias)
            fd = self._fds[alias]
            before = os.fstat(fd)
            if before.st_size > self._max_bytes:
                raise ValueError("workspace file exceeds configured byte limit")
            os.lseek(fd, 0, os.SEEK_SET)
            data = bytearray()
            while len(data) <= self._max_bytes:
                chunk = os.read(fd, self._max_bytes + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            if (
                len(data) > self._max_bytes
                or len(data) != before.st_size
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise ValueError("workspace file changed during readback")
            self._check_root()
            self._check_file(alias)
            return {"artifact": alias, "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()}

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                for fd in self._fds.values():
                    os.close(fd)

    def __enter__(self) -> WorkspaceFiles:
        with self._lock:
            if self._closed or self._failed:
                raise ValueError("workspace files are closed or failed")
            return self

    def __exit__(self, exc_type: type[BaseException] | None,
                 exc_value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        self.close()
