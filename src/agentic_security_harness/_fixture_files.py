"""Internal, bounded file effects for a caller-authorized local fixture."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
from pathlib import Path
from types import TracebackType

INITIAL_REPORT = b"pending\n"
INITIAL_PROTECTED = b"protected fixture; do not modify\n"
_INITIAL = {
    "report": ("report.txt", INITIAL_REPORT),
    "protected": ("protected.txt", INITIAL_PROTECTED),
}
_MAX_BYTES = 4096
_CALL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _not_reparse(info: os.stat_result) -> bool:
    return not (getattr(info, "st_file_attributes", 0) & _REPARSE)


def _checked_directory(path: Path) -> os.stat_result:
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or not _not_reparse(info):
            raise ValueError("fixture path contains a link or non-directory")
    return path.lstat()


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


class FixtureFiles:
    """Retained handles to exactly two newly created synthetic files.

    The caller must decide whether an action is authorized before calling
    ``write_once``. This class does not confer authority or restrict other
    processes' filesystem access.
    """

    def __init__(self, root: Path, root_identity: tuple[int, int], fds: dict[str, int]) -> None:
        self._root = root
        self._root_identity = root_identity
        self._fds = fds
        self._identities = {name: _identity(os.fstat(fd)) for name, fd in fds.items()}
        self._seen: set[str] = set()
        self._closed = False
        self._lock = threading.RLock()

    @classmethod
    def create(cls, root: Path) -> FixtureFiles:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("fixture root must be an absolute Path")
        _checked_directory(root.parent)
        if root.exists() or root.is_symlink():
            raise FileExistsError(root)
        os.mkdir(root, 0o700)
        fds: dict[str, int] = {}
        try:
            root_info = _checked_directory(root)
            if os.name != "nt":
                os.chmod(root, 0o700)
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            for name, (filename, initial) in _INITIAL.items():
                if _identity(_checked_directory(root)) != _identity(root_info):
                    raise ValueError("fixture root changed during creation")
                fd = os.open(root / filename, flags, 0o600)
                fds[name] = fd
                info = os.fstat(fd)
                path_info = (root / filename).lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or not _not_reparse(info)
                    or info.st_nlink != 1
                    or _identity(info) != _identity(path_info)
                    or not _not_reparse(path_info)
                ):
                    raise ValueError("fixture file is not a unique regular file")
                _write_all(fd, initial)
                os.fsync(fd)
            instance = cls(root, _identity(root_info), fds)
            instance._check_all()
            return instance
        except BaseException:
            for fd in fds.values():
                os.close(fd)
            # Preserve a failed or partial fixture for inspection.
            raise

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("fixture files are closed")

    def _check_all(self) -> None:
        self._check_open()
        root_info = _checked_directory(self._root)
        if _identity(root_info) != self._root_identity:
            raise ValueError("fixture root identity changed")
        for name, (filename, _) in _INITIAL.items():
            fd_info = os.fstat(self._fds[name])
            path_info = (self._root / filename).lstat()
            if (
                not stat.S_ISREG(fd_info.st_mode)
                or not _not_reparse(fd_info)
                or fd_info.st_nlink != 1
                or not stat.S_ISREG(path_info.st_mode)
                or not _not_reparse(path_info)
                or path_info.st_nlink != 1
                or _identity(fd_info) != self._identities[name]
                or _identity(path_info) != self._identities[name]
            ):
                raise ValueError("fixture file identity changed")

    def write_once(self, artifact: str, content: bytes, call_id: str) -> dict[str, str | int]:
        if not isinstance(artifact, str) or artifact not in _INITIAL:
            raise ValueError("unknown fixture artifact")
        if type(content) is not bytes or len(content) > _MAX_BYTES:
            raise ValueError("fixture content must be at most 4096 bytes")
        if not isinstance(call_id, str) or _CALL_ID.fullmatch(call_id) is None:
            raise ValueError("invalid call id")
        with self._lock:
            self._check_open()
            if call_id in self._seen:
                raise ValueError("call id already consumed")
            self._seen.add(call_id)
            self._check_all()
            fd = self._fds[artifact]
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            _write_all(fd, content)
            os.fsync(fd)
            self._check_all()
            return {
                "artifact": artifact,
                "call_id": call_id,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }

    def snapshot(self) -> dict[str, dict[str, str | int]]:
        with self._lock:
            self._check_all()
            result: dict[str, dict[str, str | int]] = {}
            for name in _INITIAL:
                fd = self._fds[name]
                before = os.fstat(fd)
                if before.st_size > _MAX_BYTES:
                    raise ValueError("fixture file exceeds size bound")
                os.lseek(fd, 0, os.SEEK_SET)
                data = bytearray()
                while len(data) <= _MAX_BYTES:
                    chunk = os.read(fd, _MAX_BYTES + 1 - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                after = os.fstat(fd)
                if (
                    len(data) > _MAX_BYTES
                    or len(data) != before.st_size
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    raise ValueError("fixture file changed during snapshot")
                result[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            self._check_all()
            return result

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                for fd in self._fds.values():
                    os.close(fd)

    def __enter__(self) -> FixtureFiles:
        with self._lock:
            self._check_open()
            return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("fixture write made no progress")
        view = view[written:]
