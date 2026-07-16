"""Deterministic source identity helpers for evidence-producing code.

Public artifacts must distinguish materially different producer implementations
without leaking machine-specific absolute paths.  Fingerprints therefore commit to
an explicit, package-relative component set and its bytes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent


def component_fingerprint(relative_paths: Iterable[str]) -> str:
    """Hash an explicit package-relative component set and its file contents."""

    normalized = sorted(set(relative_paths))
    if not normalized:
        raise ValueError("at least one source component is required")
    digest = hashlib.sha256()
    for relative in normalized:
        candidate = (PACKAGE_ROOT / relative).resolve()
        try:
            candidate.relative_to(PACKAGE_ROOT)
        except ValueError as exc:
            raise ValueError(f"source component escapes package root: {relative}") from exc
        if not candidate.is_file():
            raise ValueError(f"source component is not a file: {relative}")
        data = candidate.read_bytes()
        encoded_name = Path(relative).as_posix().encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def package_source_root() -> Path:
    """Return the resolved directory from which the package was imported."""

    return PACKAGE_ROOT
