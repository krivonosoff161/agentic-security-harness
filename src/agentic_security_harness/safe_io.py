"""Safe artifact writing helpers.

Validation catches forbidden markers after artifacts exist. This module is the earlier
gate: artifact writers pass text through a conservative redactor before writing.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
from inspect import signature
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, cast

from agentic_security_harness.secret_hygiene import redact_secret_shapes

_ENV_VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_STAGING_MARKER = ".ash-staging-"
_STAGING_COMPONENT = re.compile(r"^\..+\.ash-staging-[0-9a-f]{32}$")

P = ParamSpec("P")
R = TypeVar("R")


class PublishedBundleDurabilityError(OSError):
    """The bundle is visible, but parent-directory durability could not be confirmed."""


def redact_artifact_text(text: str) -> str:
    """Redact secret-shaped strings from artifact text before persistence."""
    return redact_secret_shapes(text)


def canonical_persisted_text(text: str) -> str:
    """Return the exact scalar representation safe artifact sinks will persist.

    Producers must hash this representation rather than pre-redaction model text. The
    detector may inspect the original in memory, but public commitments describe retained
    bytes, not a value that the writer subsequently changes.
    """

    return redact_artifact_text(text)


def safe_credential_env_var_name(value: object) -> str:
    """Return a safe credential marker for persisted metadata.

    The external runner needs the real environment variable name only while making the
    request. Artifacts do not need that name, and persisting it creates needless static
    analysis noise. Keep metadata to a constant non-secret marker.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    return "[CREDENTIAL_ENV_VAR_CONFIGURED]"


def credential_env_var_lookup_name(value: object) -> str:
    """Return a valid env-var name for runtime lookup, or empty on unsafe input."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "[REDACTED]" in text:
        return ""
    if redact_artifact_text(text) != text:
        return ""
    if not _ENV_VAR_NAME.fullmatch(text):
        return ""
    return text


def require_fresh_output_dir(path: Path) -> None:
    """Refuse an output root that could mix two evidence generations."""

    _require_no_link_components(path)
    if not path.exists():
        return
    if not path.is_dir():
        raise ValueError("output path exists and is not a directory")
    if any(path.iterdir()):
        raise ValueError("output directory must be empty for a new evidence bundle")


def require_disjoint_output_dirs(*paths: Path) -> None:
    """Refuse equal or nested roots that could mix private and public artifacts."""

    for path in paths:
        _require_no_link_components(path)
    resolved = [path.resolve(strict=False) for path in paths]
    for index, left in enumerate(resolved):
        for right in resolved[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError("private and sanitized output directories must be disjoint")


def is_internal_output_dir(path: Path) -> bool:
    """Return whether the normalized output path is inside a ``.internal`` tree."""

    return any(part.casefold() == ".internal" for part in path.resolve(strict=False).parts)


def is_staging_path(path: Path) -> bool:
    """Return whether a path is inside an unpublished ASH staging generation."""

    return any(_STAGING_COMPONENT.fullmatch(part) for part in path.parts)


def is_link_or_reparse(path: Path) -> bool:
    """Return whether an existing path is a symlink or Windows reparse point."""

    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(reparse_flag and attributes & reparse_flag)


def iter_link_or_reparse_entries(root: Path) -> Iterator[Path]:
    """Yield link/reparse entries under ``root`` without recursing through them."""

    pending = [root]
    while pending:
        current = pending.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if is_link_or_reparse(child):
                yield child
                continue
            if child.is_dir():
                pending.append(child)


def _require_no_link_components(path: Path) -> None:
    for candidate in (path, *path.parents):
        if is_link_or_reparse(candidate):
            raise ValueError(f"output path must not traverse a link or reparse point: {candidate}")


def _require_real_staging_tree(path: Path) -> None:
    _require_no_link_components(path)
    if not path.is_dir():
        raise ValueError("staging path must remain a real directory")
    for candidate in path.rglob("*"):
        if is_link_or_reparse(candidate):
            raise ValueError(
                "staging tree must not contain links or reparse points: "
                f"{candidate.relative_to(path).as_posix()}"
            )


def require_atomic_output_destination(path: Path) -> None:
    """Preflight a final bundle path before any expensive or side-effecting work."""

    if not path.name or ".." in path.parts:
        raise ValueError("output directory must have a final path component")
    if is_staging_path(path):
        raise ValueError("output directory must not use the reserved ASH staging name")
    _require_no_link_components(path)
    if path.exists():
        raise ValueError(
            "output directory must be empty for a new evidence bundle and must not "
            "already exist for atomic publication"
        )


def _fsync_directory(path: Path) -> None:
    """Persist directory metadata where the platform exposes directory handles."""

    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_owned_staging_dir(path: Path) -> None:
    """Remove only the uniquely named staging path created by this transaction."""

    if not is_staging_path(path):
        raise ValueError("refusing to remove a path without the ASH staging marker")
    if is_link_or_reparse(path):
        try:
            path.unlink()
        except IsADirectoryError:
            path.rmdir()
    elif path.exists():
        shutil.rmtree(path)


def _validate_staged_bundle(path: Path) -> None:
    """Require one recognized, fully valid artifact contract before publication."""

    # Imported lazily to avoid a safe_io -> validation -> producer import cycle.
    from agentic_security_harness.validation import validate_artifact_path

    result = validate_artifact_path(path)
    recognized_root = any(
        path.name in values
        for field, values in result.model_dump(mode="python").items()
        if field.endswith("_dirs")
    )
    root_manifest = path / "run_index.json"
    has_root_manifest = root_manifest.is_file() and not root_manifest.is_symlink()
    # Behavioral expectation mismatches are evidence and must remain publishable.
    # Integrity failures (schema, semantics, hashes, projection, or secret scan) are not.
    if result.integrity_ok and recognized_root and has_root_manifest:
        return
    details = "; ".join(result.errors)
    if not recognized_root:
        details = f"no recognized root artifact contract{'; ' + details if details else ''}"
    if not has_root_manifest:
        details = f"missing root run_index.json{'; ' + details if details else ''}"
    raise ValueError(f"refusing to publish invalid evidence bundle: {details}")


@contextmanager
def staged_evidence_bundle(final_path: Path) -> Iterator[Path]:
    """Build, validate, and atomically publish one immutable evidence directory.

    Writers receive a unique sibling staging directory. The final path remains absent
    until the complete current-schema bundle validates, after which one same-filesystem
    directory rename publishes it. A failed or interrupted cooperative writer cannot
    expose a partial bundle at the requested final path.
    """

    require_atomic_output_destination(final_path)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path = final_path.with_name(f".{final_path.name}{_STAGING_MARKER}{uuid.uuid4().hex}")
    staging_path.mkdir(mode=0o700)
    published = False
    try:
        yield staging_path
        _require_real_staging_tree(staging_path)
        _validate_staged_bundle(staging_path)
        if final_path.exists() or final_path.is_symlink():
            raise ValueError("output directory appeared before atomic publication")
        _require_real_staging_tree(staging_path)
        _require_no_link_components(final_path)
        _fsync_directory(staging_path)
        staging_path.rename(final_path)
        published = True
        try:
            _fsync_directory(final_path.parent)
        except OSError as exc:
            raise PublishedBundleDurabilityError(
                "evidence bundle was published, but parent-directory durability "
                f"could not be confirmed: {final_path}"
            ) from exc
    finally:
        if not published:
            _remove_owned_staging_dir(staging_path)


@contextmanager
def staged_private_bundle(final_path: Path) -> Iterator[Path]:
    """Atomically publish one immutable private directory without public validation.

    Private transcripts intentionally fail public secret-marker rules, so this transaction
    checks filesystem confinement, a non-empty regular-file tree, and immutable publication
    but does not treat raw private bytes as public evidence.
    """

    if not is_internal_output_dir(final_path):
        raise ValueError("private bundle output must be under .internal/")
    require_atomic_output_destination(final_path)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path = final_path.with_name(f".{final_path.name}{_STAGING_MARKER}{uuid.uuid4().hex}")
    staging_path.mkdir(mode=0o700)
    published = False
    try:
        yield staging_path
        _require_real_staging_tree(staging_path)
        if not any(candidate.is_file() for candidate in staging_path.rglob("*")):
            raise ValueError("refusing to publish an empty private bundle")
        if final_path.exists() or final_path.is_symlink():
            raise ValueError("private output directory appeared before atomic publication")
        _require_real_staging_tree(staging_path)
        _require_no_link_components(final_path)
        _fsync_directory(staging_path)
        staging_path.rename(final_path)
        published = True
        try:
            _fsync_directory(final_path.parent)
        except OSError as exc:
            raise PublishedBundleDurabilityError(
                "private bundle was published, but parent-directory durability "
                f"could not be confirmed: {final_path}"
            ) from exc
    finally:
        if not published:
            _remove_owned_staging_dir(staging_path)


def _remap_staged_paths(value: Any, staging: Path, final: Path) -> Any:
    """Map writer return paths from the private staging name to the public name."""

    if isinstance(value, Path):
        try:
            return final / value.relative_to(staging)
        except ValueError:
            return value
    if isinstance(value, list):
        return [_remap_staged_paths(item, staging, final) for item in value]
    if isinstance(value, tuple):
        return tuple(_remap_staged_paths(item, staging, final) for item in value)
    if isinstance(value, dict):
        return {key: _remap_staged_paths(item, staging, final) for key, item in value.items()}
    return value


def atomic_evidence_bundle(
    output_parameter: str,
    *,
    skip_when: tuple[str, object] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Wrap a manifest-producing writer in :func:`staged_evidence_bundle`.

    ``skip_when`` is reserved for explicit non-writing modes such as an external
    runner dry run. The wrapped function keeps its original signature for callers.
    """

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        function_signature = signature(function)
        if output_parameter not in function_signature.parameters:
            raise ValueError(f"unknown output parameter: {output_parameter}")

        @wraps(function)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            bound = function_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            if skip_when is not None:
                parameter, expected = skip_when
                if bound.arguments.get(parameter) == expected:
                    return function(*args, **kwargs)
            final_path = Path(cast(Path | str, bound.arguments[output_parameter]))
            with staged_evidence_bundle(final_path) as staging_path:
                bound.arguments[output_parameter] = staging_path
                result = function(*bound.args, **bound.kwargs)
            return cast(R, _remap_staged_paths(result, staging_path, final_path))

        return wrapped

    return decorate


def atomic_private_bundle(
    output_parameter: str,
    *,
    skip_when: tuple[str, object] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Wrap a private-artifact writer in :func:`staged_private_bundle`.

    ``skip_when`` supports explicit non-writing modes. It has the same fail-closed
    semantics as :func:`atomic_evidence_bundle`: every writing call must still use a
    normalized ``.internal`` destination.
    """

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        function_signature = signature(function)
        if output_parameter not in function_signature.parameters:
            raise ValueError(f"unknown output parameter: {output_parameter}")

        @wraps(function)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            bound = function_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            if skip_when is not None:
                parameter, expected = skip_when
                if bound.arguments.get(parameter) == expected:
                    return function(*args, **kwargs)
            final_path = Path(cast(Path | str, bound.arguments[output_parameter]))
            with staged_private_bundle(final_path) as staging_path:
                bound.arguments[output_parameter] = staging_path
                result = function(*bound.args, **bound.kwargs)
            return cast(R, _remap_staged_paths(result, staging_path, final_path))

        return wrapped

    return decorate


def write_text_artifact(path: Path, text: str) -> Path:
    """Atomically write redacted UTF-8 LF text to an artifact path.

    The temporary file lives beside the destination so ``os.replace`` stays on the
    same filesystem.  A failed write therefore leaves an existing artifact intact
    instead of truncating it into a mixed or partial bundle.
    """
    _require_no_link_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _require_no_link_components(path.parent)
    if is_link_or_reparse(path):
        raise ValueError(f"artifact path must not be a link or reparse point: {path}")
    clean = redact_artifact_text(text).replace("\r\n", "\n").replace("\r", "\n")
    # Central artifact sink: inputs are redacted above, then validated by artifact
    # contract tests. CodeQL cannot model this project-specific sanitizer.
    # codeql[py/clear-text-storage-sensitive-data]
    file_descriptor, temporary_name = tempfile.mkstemp(
        # Keep the sibling name short. Deriving it from a long destination filename
        # needlessly exhausted the Windows path budget after model calls had completed.
        prefix=".ash-",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    descriptor_open = True
    try:
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            descriptor_open = False
            handle.write(clean)
            handle.flush()
            os.fsync(handle.fileno())
        _require_no_link_components(path.parent)
        if is_link_or_reparse(path):
            raise ValueError(f"artifact path must not be a link or reparse point: {path}")
        os.replace(temporary_path, path)
    finally:
        if descriptor_open:
            os.close(file_descriptor)
        temporary_path.unlink(missing_ok=True)
    return path
