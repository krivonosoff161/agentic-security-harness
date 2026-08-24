"""Verified, operator-selected Extension SDK V1 distribution metadata.

This module inspects one explicitly named installed distribution and binds its RECORD,
entry point, canonical extension manifest, implementation, and configuration digests.
It never imports or executes extension code.  After exact reinspection, it can issue an
authority-free approval receipt and bind an already operator-constructed ExtensionV1
object to that receipt.  This is neither a signature check nor a sandbox.
"""

from __future__ import annotations

import base64
import binascii
import configparser
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.extension_sdk import (
    MAX_EXTENSION_PAYLOAD_BYTES,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    ExtensionV1,
    decode_extension_manifest_v1,
)
from agentic_security_harness.portfolio_contract import SHA256_PATTERN
from agentic_security_harness.safe_io import is_link_or_reparse

EXTENSION_DISTRIBUTION_INSPECTION_V1: Final = (
    "harness-extension-distribution-inspection-v1.0"
)
EXTENSION_DISTRIBUTION_APPROVAL_V1: Final = "harness-extension-distribution-approval-v1.0"
EXTENSION_ENTRY_POINT_GROUP_V1: Final = "agentic_security_harness.extensions.v1"
EXTENSION_MANIFEST_FILENAME_V1: Final = "ash-extension-manifest.json"
MAX_DISTRIBUTION_FILES: Final = 4_096
MAX_DISTRIBUTION_FILE_BYTES: Final = 8 * 1024 * 1024
MAX_DISTRIBUTION_TOTAL_BYTES: Final = 32 * 1024 * 1024
MAX_DISTRIBUTION_JSON_DEPTH: Final = 32
MAX_DISTRIBUTION_INTEGER_DIGITS: Final = 10

_DISTRIBUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_ENTRY_POINT_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_ATTRIBUTE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_RECORD_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {"aux", "con", "nul", "prn"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)

DistributionFileRole = Literal[
    "implementation",
    "manifest",
    "metadata",
    "entry_points",
    "wheel_metadata",
    "distribution_support",
]


class ExtensionDistributionError(ValueError):
    """Raised when installed extension distribution evidence fails closed."""


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


class DistributionFileBindingV1(BaseModel):
    """One verified non-RECORD file owned by the selected distribution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(ge=0, le=MAX_DISTRIBUTION_FILE_BYTES)
    role: DistributionFileRole

    @model_validator(mode="after")
    def _validate_path(self) -> DistributionFileBindingV1:
        if _validated_record_path(self.path) != self.path:
            raise ValueError("distribution file path is not canonical")
        return self


class ExtensionDistributionInspectionV1(BaseModel):
    """Canonical, metadata-only receipt for one explicitly selected distribution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-distribution-inspection-v1.0"]
    inspection_id: str = Field(pattern=SHA256_PATTERN)
    distribution_name: str = Field(min_length=1, max_length=128)
    distribution_version: str = Field(min_length=1, max_length=64)
    requires_python: Literal[">=3.11,<3.14"]
    wheel_tag: Literal["py3-none-any"]
    metadata_sha256: str = Field(pattern=SHA256_PATTERN)
    entry_points_sha256: str = Field(pattern=SHA256_PATTERN)
    record_sha256: str = Field(pattern=SHA256_PATTERN)
    files_sha256: str = Field(pattern=SHA256_PATTERN)
    file_count: int = Field(ge=5, le=MAX_DISTRIBUTION_FILES)
    files: tuple[DistributionFileBindingV1, ...] = Field(
        min_length=4, max_length=MAX_DISTRIBUTION_FILES - 1
    )
    entry_point_group: Literal["agentic_security_harness.extensions.v1"]
    entry_point_name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    entry_point_value: str = Field(min_length=3, max_length=257)
    module_name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    module_path: str = Field(min_length=4, max_length=132)
    factory_attribute: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    manifest_path: str = Field(min_length=1, max_length=512)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    extension_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    extension_version: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
    harness_api: Literal["1"]
    code_loaded: Literal[False]
    record_verified: Literal[True]
    signature_verified: Literal[False]
    sandboxed: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_bindings(self) -> ExtensionDistributionInspectionV1:
        if _normalize_distribution_name(self.distribution_name) != self.distribution_name:
            raise ValueError("distribution name must use canonical normalization")
        if not _VERSION.fullmatch(self.distribution_version):
            raise ValueError("distribution version is outside the V1 grammar")
        if self.file_count != len(self.files) + 1:
            raise ValueError("file count must include the RECORD file")
        paths = tuple(binding.path for binding in self.files)
        if (
            paths != tuple(sorted(paths))
            or len(paths) != len(set(paths))
            or len(paths) != len({path.casefold() for path in paths})
        ):
            raise ValueError("distribution files must be unique and sorted")
        by_role: dict[str, list[DistributionFileBindingV1]] = {}
        for binding in self.files:
            by_role.setdefault(binding.role, []).append(binding)
        for role in ("implementation", "manifest", "metadata", "entry_points", "wheel_metadata"):
            if len(by_role.get(role, [])) != 1:
                raise ValueError(f"distribution must bind exactly one {role} file")
        if by_role["implementation"][0].path != self.module_path:
            raise ValueError("implementation binding does not match module path")
        if by_role["implementation"][0].sha256 != self.implementation_sha256:
            raise ValueError("implementation digest does not match module binding")
        if by_role["manifest"][0].path != self.manifest_path:
            raise ValueError("manifest binding does not match manifest path")
        if by_role["manifest"][0].sha256 != self.manifest_sha256:
            raise ValueError("manifest digest does not match manifest binding")
        if by_role["metadata"][0].sha256 != self.metadata_sha256:
            raise ValueError("metadata digest does not match metadata binding")
        if by_role["entry_points"][0].sha256 != self.entry_points_sha256:
            raise ValueError("entry-point digest does not match entry-point binding")
        if self.module_path != f"{self.module_name}.py":
            raise ValueError("V1 entry point must be one top-level source module")
        if self.entry_point_name != self.extension_id:
            raise ValueError("entry-point name must equal extension id")
        if self.entry_point_value != f"{self.module_name}:{self.factory_attribute}":
            raise ValueError("entry-point value does not match verified module and factory")
        if _files_identity(self.files) != self.files_sha256:
            raise ValueError("distribution files digest does not bind file entries")
        if _inspection_identity(self) != self.inspection_id:
            raise ValueError("inspection id does not bind the canonical receipt")
        return self


class ExtensionDistributionApprovalV1(BaseModel):
    """Exact operator approval of one unchanged metadata-only inspection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-distribution-approval-v1.0"]
    approval_id: str = Field(pattern=SHA256_PATTERN)
    inspection_id: str = Field(pattern=SHA256_PATTERN)
    distribution_name: str = Field(min_length=1, max_length=128)
    distribution_version: str = Field(min_length=1, max_length=64)
    extension_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    extension_version: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
    entry_point_value: str = Field(min_length=3, max_length=257)
    record_sha256: str = Field(pattern=SHA256_PATTERN)
    files_sha256: str = Field(pattern=SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    approval_semantics: Literal["explicit_exact_reinspection_no_code_load"]
    code_loaded: Literal[False]
    signature_verified: Literal[False]
    sandboxed: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_identity(self) -> ExtensionDistributionApprovalV1:
        if _approval_identity(self) != self.approval_id:
            raise ValueError("approval id does not bind the canonical receipt")
        return self


class OperatorApprovedExtensionV1:
    """ExtensionV1 wrapper retaining exact approval without claiming code origin."""

    def __init__(
        self,
        approval: ExtensionDistributionApprovalV1,
        extension: ExtensionV1,
        manifest: ExtensionManifestV1,
    ) -> None:
        self.approval = approval
        self._extension = extension
        self._manifest = manifest

    @property
    def manifest(self) -> ExtensionManifestV1:
        try:
            current = ExtensionManifestV1.model_validate(
                self._extension.manifest.model_dump(mode="python")
            )
        except (AttributeError, ValueError) as exc:
            raise ExtensionDistributionError(
                "operator-supplied extension manifest drifted after binding"
            ) from exc
        if current != self._manifest:
            raise ExtensionDistributionError(
                "operator-supplied extension manifest drifted after binding"
            )
        return self._manifest

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        _ = self.manifest
        try:
            result = self._extension.evaluate(envelope)
        finally:
            _ = self.manifest
        return result


@dataclass(frozen=True)
class _InspectedDistribution:
    receipt: ExtensionDistributionInspectionV1
    manifest: ExtensionManifestV1


def inspect_extension_distribution_v1(
    *,
    distribution_name: str,
    extension_id: str,
    search_paths: Sequence[Path],
    configuration_bytes: bytes,
) -> ExtensionDistributionInspectionV1:
    """Inspect one explicitly named installed distribution without importing its code."""

    return _inspect_distribution(
        distribution_name=distribution_name,
        extension_id=extension_id,
        search_paths=search_paths,
        configuration_bytes=configuration_bytes,
    ).receipt


def approve_extension_distribution_v1(
    *,
    approved_inspection: ExtensionDistributionInspectionV1,
    approved_inspection_id: str,
    search_paths: Sequence[Path],
    configuration_bytes: bytes,
) -> ExtensionDistributionApprovalV1:
    """Reinspect exact bytes and issue an authority-free, no-code-load approval receipt."""

    try:
        approved_inspection = ExtensionDistributionInspectionV1.model_validate(
            approved_inspection.model_dump(mode="python")
        )
    except (AttributeError, ValueError) as exc:
        raise ExtensionDistributionError("approved inspection violates V1") from exc
    if approved_inspection_id != approved_inspection.inspection_id:
        raise ExtensionDistributionError("operator approval does not match inspection id")
    reinspected = _inspect_distribution(
        distribution_name=approved_inspection.distribution_name,
        extension_id=approved_inspection.extension_id,
        search_paths=search_paths,
        configuration_bytes=configuration_bytes,
    ).receipt
    if reinspected != approved_inspection:
        raise ExtensionDistributionError("installed distribution drifted after inspection")
    provisional = ExtensionDistributionApprovalV1.model_construct(
        schema_version=EXTENSION_DISTRIBUTION_APPROVAL_V1,
        approval_id="0" * 64,
        inspection_id=reinspected.inspection_id,
        distribution_name=reinspected.distribution_name,
        distribution_version=reinspected.distribution_version,
        extension_id=reinspected.extension_id,
        extension_version=reinspected.extension_version,
        entry_point_value=reinspected.entry_point_value,
        record_sha256=reinspected.record_sha256,
        files_sha256=reinspected.files_sha256,
        manifest_sha256=reinspected.manifest_sha256,
        implementation_sha256=reinspected.implementation_sha256,
        configuration_sha256=reinspected.configuration_sha256,
        approval_semantics="explicit_exact_reinspection_no_code_load",
        code_loaded=False,
        signature_verified=False,
        sandboxed=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["approval_id"] = _approval_identity(provisional)
    return ExtensionDistributionApprovalV1.model_validate(payload)


def bind_operator_approved_extension_v1(
    approval: ExtensionDistributionApprovalV1,
    extension: ExtensionV1,
) -> OperatorApprovedExtensionV1:
    """Bind an already operator-constructed object to exact approved manifest pins."""

    try:
        approval = ExtensionDistributionApprovalV1.model_validate(
            approval.model_dump(mode="python")
        )
        manifest = extension.manifest
        if not isinstance(manifest, ExtensionManifestV1):
            raise TypeError("manifest is not ExtensionManifestV1")
        manifest = ExtensionManifestV1.model_validate(manifest.model_dump(mode="python"))
        if not callable(getattr(extension, "evaluate", None)):
            raise TypeError("extension has no evaluate method")
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExtensionDistributionError("operator-supplied extension violates V1") from exc
    if (
        manifest.extension_id != approval.extension_id
        or manifest.extension_version != approval.extension_version
        or manifest.implementation_sha256 != approval.implementation_sha256
        or manifest.configuration_sha256 != approval.configuration_sha256
    ):
        raise ExtensionDistributionError("operator-supplied extension differs from approval")
    if hashlib.sha256(_canonical_manifest_bytes(manifest)).hexdigest() != approval.manifest_sha256:
        raise ExtensionDistributionError("operator-supplied manifest differs from approval")
    return OperatorApprovedExtensionV1(approval, extension, manifest)


def encode_extension_distribution_inspection_v1(
    inspection: ExtensionDistributionInspectionV1,
) -> bytes:
    return _canonical_bytes(inspection.model_dump(mode="json"), "inspection")


def decode_extension_distribution_inspection_v1(
    payload: bytes,
) -> ExtensionDistributionInspectionV1:
    receipt = _decode_receipt(
        payload,
        ExtensionDistributionInspectionV1,
        "inspection",
    )
    return cast(ExtensionDistributionInspectionV1, receipt)


def encode_extension_distribution_approval_v1(
    approval: ExtensionDistributionApprovalV1,
) -> bytes:
    return _canonical_bytes(approval.model_dump(mode="json"), "approval")


def decode_extension_distribution_approval_v1(
    payload: bytes,
) -> ExtensionDistributionApprovalV1:
    receipt = _decode_receipt(payload, ExtensionDistributionApprovalV1, "approval")
    return cast(ExtensionDistributionApprovalV1, receipt)


def extension_distribution_v1_json_schemas() -> dict[str, dict[str, Any]]:
    return {
        "extension-distribution-inspection.v1.schema.json": (
            ExtensionDistributionInspectionV1.model_json_schema()
        ),
        "extension-distribution-approval.v1.schema.json": (
            ExtensionDistributionApprovalV1.model_json_schema()
        ),
    }


def _inspect_distribution(
    *,
    distribution_name: str,
    extension_id: str,
    search_paths: Sequence[Path],
    configuration_bytes: bytes,
) -> _InspectedDistribution:
    if not isinstance(distribution_name, str) or not _DISTRIBUTION_NAME.fullmatch(
        distribution_name
    ):
        raise ExtensionDistributionError("distribution name is outside the V1 grammar")
    normalized_name = _normalize_distribution_name(distribution_name)
    if not isinstance(extension_id, str) or not _ENTRY_POINT_NAME.fullmatch(extension_id):
        raise ExtensionDistributionError("extension id is outside the V1 grammar")
    if not isinstance(configuration_bytes, bytes):
        raise ExtensionDistributionError("configuration must be bytes")
    if len(configuration_bytes) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionDistributionError("configuration exceeds the V1 byte limit")
    roots = _validated_search_roots(search_paths)
    matches: list[tuple[importlib.metadata.Distribution, Path]] = []
    for root in roots:
        try:
            candidates = importlib.metadata.distributions(path=[str(root)])
            for distribution in candidates:
                name = distribution.metadata["Name"]
                if name and _normalize_distribution_name(name) == normalized_name:
                    matches.append((distribution, root))
        except (OSError, UnicodeError, ValueError) as exc:
            raise ExtensionDistributionError(
                "installed distribution metadata is unreadable"
            ) from exc
    if len(matches) != 1:
        raise ExtensionDistributionError("selected distribution must resolve exactly once")
    distribution, root = matches[0]
    metadata_name = distribution.metadata["Name"]
    metadata_version = distribution.metadata["Version"]
    if not metadata_name or not metadata_version:
        raise ExtensionDistributionError("distribution name or version metadata is missing")
    if _normalize_distribution_name(metadata_name) != normalized_name:
        raise ExtensionDistributionError("distribution name metadata drifted")
    if not _VERSION.fullmatch(metadata_version):
        raise ExtensionDistributionError("distribution version is outside the V1 grammar")

    metadata_directory = getattr(distribution, "_path", None)
    if not isinstance(metadata_directory, Path):
        raise ExtensionDistributionError("distribution metadata origin is unsupported")
    _require_no_link_components(metadata_directory, stop=root)
    if metadata_directory.parent.resolve(strict=True) != root:
        raise ExtensionDistributionError("distribution metadata directory is not a root child")
    dist_info = _validated_record_path(metadata_directory.name)
    if not dist_info.endswith(".dist-info") or "/" in dist_info:
        raise ExtensionDistributionError("distribution metadata directory is not a root child")
    record_path = f"{dist_info}/RECORD"
    record_bytes = _stable_read(root, record_path, MAX_DISTRIBUTION_FILE_BYTES)
    record_rows = _parse_record(record_bytes, record_path)
    declared_paths = tuple(path for path, _, _ in record_rows)
    if len(declared_paths) != len(set(declared_paths)):
        raise ExtensionDistributionError("distribution RECORD contains duplicate paths")
    if len(declared_paths) != len({path.casefold() for path in declared_paths}):
        raise ExtensionDistributionError("distribution RECORD has portable path collisions")
    record_candidates = [path for path in declared_paths if path.endswith(".dist-info/RECORD")]
    if record_candidates != [record_path]:
        raise ExtensionDistributionError("distribution must contain exactly one RECORD")

    expected_dist_info_files = {
        path for path, _, _ in record_rows if path.startswith(f"{dist_info}/")
    }
    actual_dist_info_files = _enumerate_regular_files(root, dist_info)
    if expected_dist_info_files != actual_dist_info_files:
        raise ExtensionDistributionError("distribution metadata directory contains extras or gaps")

    metadata_path = f"{dist_info}/METADATA"
    entry_points_path = f"{dist_info}/entry_points.txt"
    wheel_path = f"{dist_info}/WHEEL"
    manifest_path = f"{dist_info}/{EXTENSION_MANIFEST_FILENAME_V1}"
    required = {record_path, metadata_path, entry_points_path, wheel_path, manifest_path}
    if not required.issubset(set(declared_paths)):
        raise ExtensionDistributionError("distribution is missing required V1 metadata files")

    bindings: list[DistributionFileBindingV1] = []
    payloads: dict[str, bytes] = {}
    total_size = 0
    for relative_path, expected_sha256, expected_size in record_rows:
        if relative_path == record_path:
            continue
        if not (
            relative_path.startswith(f"{dist_info}/")
            or (relative_path.endswith(".py") and "/" not in relative_path)
        ):
            raise ExtensionDistributionError("distribution owns files outside the V1 boundary")
        payload = _stable_read(root, relative_path, MAX_DISTRIBUTION_FILE_BYTES)
        total_size += len(payload)
        if total_size > MAX_DISTRIBUTION_TOTAL_BYTES:
            raise ExtensionDistributionError("distribution exceeds the V1 total byte limit")
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if expected_sha256 != actual_sha256 or expected_size != len(payload):
            raise ExtensionDistributionError("distribution file does not match RECORD")
        payloads[relative_path] = payload
        role: DistributionFileRole = "distribution_support"
        if relative_path == metadata_path:
            role = "metadata"
        elif relative_path == entry_points_path:
            role = "entry_points"
        elif relative_path == wheel_path:
            role = "wheel_metadata"
        elif relative_path == manifest_path:
            role = "manifest"
        bindings.append(
            DistributionFileBindingV1(
                path=relative_path,
                sha256=actual_sha256,
                size=len(payload),
                role=role,
            )
        )

    _verify_core_metadata(payloads[metadata_path], normalized_name, metadata_version)
    _verify_wheel_metadata(payloads[wheel_path])
    entry_name, module_name, factory_attribute = _parse_entry_points(
        payloads[entry_points_path], extension_id
    )
    if module_name in sys.modules:
        raise ExtensionDistributionError("entry-point module collides with already loaded code")
    module_path = f"{module_name}.py"
    if module_path not in payloads:
        raise ExtensionDistributionError("entry-point module is not an owned source file")
    outside_metadata = {
        path for path in payloads if not path.startswith(f"{dist_info}/")
    }
    if outside_metadata != {module_path}:
        raise ExtensionDistributionError("distribution contains extra implementation files")
    bindings = [
        binding.model_copy(update={"role": "implementation"})
        if binding.path == module_path
        else binding
        for binding in bindings
    ]
    if sum(binding.role == "implementation" for binding in bindings) != 1:
        raise ExtensionDistributionError("distribution must bind exactly one implementation")

    try:
        manifest = decode_extension_manifest_v1(payloads[manifest_path])
    except ValueError as exc:
        raise ExtensionDistributionError("extension manifest violates canonical V1") from exc
    manifest_sha256 = hashlib.sha256(payloads[manifest_path]).hexdigest()
    implementation_sha256 = hashlib.sha256(payloads[module_path]).hexdigest()
    configuration_sha256 = hashlib.sha256(configuration_bytes).hexdigest()
    if manifest.extension_id != extension_id or manifest.extension_version != metadata_version:
        raise ExtensionDistributionError("extension manifest identity differs from distribution")
    if manifest.implementation_sha256 != implementation_sha256:
        raise ExtensionDistributionError("extension implementation digest differs from RECORD")
    if manifest.configuration_sha256 != configuration_sha256:
        raise ExtensionDistributionError("extension configuration digest differs from selection")
    if manifest.harness_api != "1":
        raise ExtensionDistributionError("extension Harness API is unsupported")

    sorted_bindings = tuple(sorted(bindings, key=lambda item: item.path))
    provisional = ExtensionDistributionInspectionV1.model_construct(
        schema_version=EXTENSION_DISTRIBUTION_INSPECTION_V1,
        inspection_id="0" * 64,
        distribution_name=normalized_name,
        distribution_version=metadata_version,
        requires_python=">=3.11,<3.14",
        wheel_tag="py3-none-any",
        metadata_sha256=hashlib.sha256(payloads[metadata_path]).hexdigest(),
        entry_points_sha256=hashlib.sha256(payloads[entry_points_path]).hexdigest(),
        record_sha256=hashlib.sha256(record_bytes).hexdigest(),
        files_sha256=_files_identity(sorted_bindings),
        file_count=len(record_rows),
        files=sorted_bindings,
        entry_point_group=EXTENSION_ENTRY_POINT_GROUP_V1,
        entry_point_name=entry_name,
        entry_point_value=f"{module_name}:{factory_attribute}",
        module_name=module_name,
        module_path=module_path,
        factory_attribute=factory_attribute,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        implementation_sha256=implementation_sha256,
        configuration_sha256=configuration_sha256,
        extension_id=manifest.extension_id,
        extension_version=manifest.extension_version,
        harness_api="1",
        code_loaded=False,
        record_verified=True,
        signature_verified=False,
        sandboxed=False,
        operational_authority="none",
    )
    values = provisional.model_dump(mode="python")
    values["inspection_id"] = _inspection_identity(provisional)
    return _InspectedDistribution(
        receipt=ExtensionDistributionInspectionV1.model_validate(values),
        manifest=manifest,
    )


def _normalize_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _validated_search_roots(search_paths: Sequence[Path]) -> tuple[Path, ...]:
    if not isinstance(search_paths, (list, tuple)) or not search_paths:
        raise ExtensionDistributionError("at least one explicit search path is required")
    if len(search_paths) > 16:
        raise ExtensionDistributionError("too many distribution search paths")
    roots: list[Path] = []
    for value in search_paths:
        if not isinstance(value, Path) or not value.is_absolute():
            raise ExtensionDistributionError("distribution search paths must be absolute Paths")
        _require_no_link_components(value)
        if not value.is_dir():
            raise ExtensionDistributionError("distribution search path is not a directory")
        root = value.resolve(strict=True)
        if root in roots:
            raise ExtensionDistributionError("distribution search paths must be unique")
        roots.append(root)
    return tuple(roots)


def _validated_record_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ExtensionDistributionError("RECORD path is outside the V1 limit")
    if "\\" in value or "\x00" in value or value.startswith("/") or "//" in value:
        raise ExtensionDistributionError("RECORD path is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ExtensionDistributionError("RECORD path is unsafe")
    if any(not _RECORD_COMPONENT.fullmatch(part) for part in path.parts):
        raise ExtensionDistributionError("RECORD path is outside the portable V1 grammar")
    for part in path.parts:
        basename = part.split(".", 1)[0].casefold()
        if part.endswith((".", " ")) or basename in _WINDOWS_RESERVED_BASENAMES:
            raise ExtensionDistributionError("RECORD path is not portable across V1 platforms")
    canonical = path.as_posix()
    if canonical != value:
        raise ExtensionDistributionError("RECORD path is not canonical")
    return canonical


def _parse_record(
    payload: bytes, record_path: str
) -> tuple[tuple[str, str | None, int | None], ...]:
    try:
        text = payload.decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ExtensionDistributionError("distribution RECORD is not valid UTF-8 CSV") from exc
    if not rows or len(rows) > MAX_DISTRIBUTION_FILES:
        raise ExtensionDistributionError("distribution RECORD row count is outside V1")
    parsed: list[tuple[str, str | None, int | None]] = []
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise ExtensionDistributionError("distribution RECORD rows must have three fields")
        path = _validated_record_path(row[0])
        if path in seen:
            raise ExtensionDistributionError("distribution RECORD contains duplicate paths")
        seen.add(path)
        if path == record_path:
            if row[1] or row[2]:
                raise ExtensionDistributionError("RECORD self-row must omit digest and size")
            parsed.append((path, None, None))
            continue
        if not row[1].startswith("sha256=") or re.fullmatch(
            rf"[0-9]{{1,{MAX_DISTRIBUTION_INTEGER_DIGITS}}}", row[2]
        ) is None:
            raise ExtensionDistributionError("distribution files require sha256 and size")
        encoded = row[1].removeprefix("sha256=")
        try:
            digest = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise ExtensionDistributionError("distribution RECORD digest is invalid") from exc
        if len(digest) != 32:
            raise ExtensionDistributionError("distribution RECORD digest is not sha256")
        try:
            size = int(row[2])
        except ValueError as exc:
            raise ExtensionDistributionError("distribution RECORD size is invalid") from exc
        if size > MAX_DISTRIBUTION_FILE_BYTES:
            raise ExtensionDistributionError("distribution file size exceeds V1")
        parsed.append((path, digest.hex(), size))
    if sum(path == record_path for path, _, _ in parsed) != 1:
        raise ExtensionDistributionError("distribution RECORD self-row is missing")
    return tuple(parsed)


def _stable_read(root: Path, relative_path: str, limit: int) -> bytes:
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    if os.name == "nt":
        return _stable_read_windows(root, path, limit)
    return _stable_read_posix(root, path, limit)


def _stable_read_posix(root: Path, path: Path, limit: int) -> bytes:
    _require_no_link_components(path, stop=root)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ExtensionDistributionError("distribution file metadata is unavailable") from exc
    _validate_distribution_file_state(before, limit)
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    first_descriptor: int | None = None
    second_descriptor: int | None = None
    try:
        first_descriptor = os.open(path, flags)
        first_opened = os.fstat(first_descriptor)
        _validate_distribution_file_state(first_opened, limit)
        if _descriptor_identity(first_opened) != _path_identity(before):
            raise ExtensionDistributionError("distribution file changed before it was read")
        first = _read_descriptor_contents(first_descriptor, limit)
        first_between = os.fstat(first_descriptor)
        if _descriptor_identity(first_between) != _descriptor_identity(first_opened):
            raise ExtensionDistributionError("distribution file changed while it was read")
        os.lseek(first_descriptor, 0, os.SEEK_SET)
        first_repeat = _read_descriptor_contents(first_descriptor, limit)
        first_closed = os.fstat(first_descriptor)
        if (
            _descriptor_identity(first_closed) != _descriptor_identity(first_opened)
            or first != first_repeat
        ):
            raise ExtensionDistributionError("distribution file changed while it was read")

        _require_no_link_components(path, stop=root)
        second_descriptor = os.open(path, flags)
        second_opened = os.fstat(second_descriptor)
        _validate_distribution_file_state(second_opened, limit)
        if _descriptor_identity(second_opened) != _descriptor_identity(first_opened):
            raise ExtensionDistributionError("distribution file changed between stable reads")
        second = _read_descriptor_contents(second_descriptor, limit)
        second_closed = os.fstat(second_descriptor)
        if (
            _descriptor_identity(second_closed) != _descriptor_identity(second_opened)
            or first != second
        ):
            raise ExtensionDistributionError("distribution file changed between stable reads")
    except ExtensionDistributionError:
        raise
    except OSError as exc:
        raise ExtensionDistributionError("distribution file is unreadable") from exc
    finally:
        if second_descriptor is not None:
            os.close(second_descriptor)
        if first_descriptor is not None:
            os.close(first_descriptor)
    _require_no_link_components(path, stop=root)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ExtensionDistributionError("distribution file metadata is unavailable") from exc
    _validate_distribution_file_state(after, limit)
    if _path_identity(after) != _path_identity(before):
        raise ExtensionDistributionError("distribution file changed while it was read")
    return first


def _stable_read_windows(root: Path, path: Path, limit: int) -> bytes:
    _require_no_link_components(path, stop=root)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ExtensionDistributionError("distribution file metadata is unavailable") from exc
    _validate_distribution_file_state(before, limit)
    guard_descriptors: tuple[
        tuple[int, tuple[int, int, int, int, int, int, int]], ...
    ] = ()
    first_descriptor: int | None = None
    second_descriptor: int | None = None
    final_descriptor: int | None = None
    try:
        guard_descriptors = _open_windows_ancestor_guards(root, path)
        first_descriptor = _open_windows_distribution_descriptor(path)
        first_opened = os.fstat(first_descriptor)
        _validate_distribution_file_state(first_opened, limit)
        first_native = _windows_descriptor_identity(first_descriptor, limit)
        first = _read_descriptor_contents(first_descriptor, limit)
        first_between = os.fstat(first_descriptor)
        if _descriptor_identity(first_between) != _descriptor_identity(first_opened):
            raise ExtensionDistributionError("distribution file changed while it was read")
        os.lseek(first_descriptor, 0, os.SEEK_SET)
        first_repeat = _read_descriptor_contents(first_descriptor, limit)
        first_closed = os.fstat(first_descriptor)
        if (
            _descriptor_identity(first_closed) != _descriptor_identity(first_opened)
            or _windows_descriptor_identity(first_descriptor, limit) != first_native
            or first != first_repeat
        ):
            raise ExtensionDistributionError("distribution file changed while it was read")

        _require_no_link_components(path, stop=root)
        second_descriptor = _open_windows_distribution_descriptor(path)
        second_opened = os.fstat(second_descriptor)
        _validate_distribution_file_state(second_opened, limit)
        second_native = _windows_descriptor_identity(second_descriptor, limit)
        if second_native != first_native:
            raise ExtensionDistributionError("distribution file changed between stable reads")
        second = _read_descriptor_contents(second_descriptor, limit)
        second_closed = os.fstat(second_descriptor)
        if (
            _descriptor_identity(second_closed) != _descriptor_identity(second_opened)
            or _windows_descriptor_identity(second_descriptor, limit) != second_native
            or first != second
        ):
            raise ExtensionDistributionError("distribution file changed between stable reads")

        _require_no_link_components(path, stop=root)
        final_descriptor = _open_windows_distribution_descriptor(path)
        final_opened = os.fstat(final_descriptor)
        _validate_distribution_file_state(final_opened, limit)
        final_native = _windows_descriptor_identity(final_descriptor, limit)
        if final_native != first_native:
            raise ExtensionDistributionError("distribution file changed before final validation")
        final = _read_descriptor_contents(final_descriptor, limit)
        if (
            _windows_descriptor_identity(final_descriptor, limit) != final_native
            or first != final
        ):
            raise ExtensionDistributionError("distribution file changed before final validation")
        for descriptor, opened_identity in guard_descriptors:
            if _windows_directory_identity(descriptor) != opened_identity:
                raise ExtensionDistributionError(
                    "distribution path directory changed while it was read"
                )
        _require_no_link_components(path, stop=root)
        try:
            after = path.lstat()
        except OSError as exc:
            raise ExtensionDistributionError(
                "distribution file metadata is unavailable"
            ) from exc
        _validate_distribution_file_state(after, limit)
        if _path_identity(after) != _path_identity(before):
            raise ExtensionDistributionError("distribution file changed while it was read")
        return first
    except ExtensionDistributionError:
        raise
    except OSError as exc:
        raise ExtensionDistributionError("distribution file is unreadable") from exc
    finally:
        if final_descriptor is not None:
            os.close(final_descriptor)
        if second_descriptor is not None:
            os.close(second_descriptor)
        if first_descriptor is not None:
            os.close(first_descriptor)
        for descriptor, _identity in reversed(guard_descriptors):
            os.close(descriptor)


def _open_windows_ancestor_guards(
    root: Path, path: Path
) -> tuple[tuple[int, tuple[int, int, int, int, int, int, int]], ...]:
    try:
        relative_parent = path.parent.relative_to(root)
    except ValueError as exc:
        raise ExtensionDistributionError("distribution path escapes its search root") from exc
    candidates = [root]
    current = root
    for part in relative_parent.parts:
        current = current / part
        candidates.append(current)
    descriptors: list[tuple[int, tuple[int, int, int, int, int, int, int]]] = []
    try:
        for candidate in candidates:
            descriptor = _open_windows_directory_descriptor(candidate)
            try:
                identity = _windows_directory_identity(descriptor)
            except (ExtensionDistributionError, OSError):
                os.close(descriptor)
                raise
            descriptors.append((descriptor, identity))
    except (ExtensionDistributionError, OSError):
        for descriptor, _identity in reversed(descriptors):
            os.close(descriptor)
        raise
    return tuple(descriptors)


def _open_windows_distribution_descriptor(path: Path) -> int:
    return _open_windows_native_descriptor(path, directory=False)


def _open_windows_directory_descriptor(path: Path) -> int:
    return _open_windows_native_descriptor(path, directory=True)


def _open_windows_native_descriptor(path: Path, *, directory: bool) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x00000080 if directory else 0x80000000,  # FILE_READ_ATTRIBUTES / GENERIC_READ
        0x00000001,  # FILE_SHARE_READ; deny concurrent write/delete/rename
        None,
        3,  # OPEN_EXISTING
        0x00200000 | (0x02000000 if directory else 0),
        # FILE_FLAG_OPEN_REPARSE_POINT | optional FILE_FLAG_BACKUP_SEMANTICS
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    try:
        return msvcrt.open_osfhandle(int(handle), os.O_RDONLY | int(getattr(os, "O_BINARY", 0)))
    except (OSError, OverflowError):
        close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        close_handle(handle)
        raise


def _windows_descriptor_identity(
    descriptor: int, limit: int
) -> tuple[int, int, int, int, int, int, int]:
    information = _windows_descriptor_information(descriptor)
    attributes = information[2]
    link_count = information[3]
    size = information[4]
    if attributes & (0x00000010 | 0x00000400):
        raise ExtensionDistributionError(
            "distribution files must be regular non-reparse files"
        )
    if link_count != 1:
        raise ExtensionDistributionError("distribution files must be regular single-link files")
    if size < 0 or size > limit:
        raise ExtensionDistributionError("distribution file size is outside V1")
    return information


def _windows_directory_identity(
    descriptor: int,
) -> tuple[int, int, int, int, int, int, int]:
    information = _windows_descriptor_information(descriptor)
    attributes = information[2]
    if not attributes & 0x00000010 or attributes & 0x00000400:
        raise ExtensionDistributionError(
            "distribution path directories must be non-reparse directories"
        )
    return information


def _windows_descriptor_information(
    descriptor: int,
) -> tuple[int, int, int, int, int, int, int]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))

    class _FileInformation(ctypes.Structure):
        _fields_ = (
            ("attributes", wintypes.DWORD),
            ("creation_time", _FileTime),
            ("last_access_time", _FileTime),
            ("last_write_time", _FileTime),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("link_count", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        )

    get_information = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetFileInformationByHandle
    get_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(_FileInformation))
    get_information.restype = wintypes.BOOL
    information = _FileInformation()
    handle = msvcrt.get_osfhandle(descriptor)
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
    size = (information.size_high << 32) | information.size_low
    file_index = (information.file_index_high << 32) | information.file_index_low
    creation_time = (information.creation_time.high << 32) | information.creation_time.low
    last_write_time = (
        information.last_write_time.high << 32
    ) | information.last_write_time.low
    return (
        information.volume_serial,
        file_index,
        information.attributes,
        information.link_count,
        size,
        creation_time,
        last_write_time,
    )


def _read_descriptor_contents(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise ExtensionDistributionError("distribution file size is outside V1")
    return payload


def _validate_distribution_file_state(info: os.stat_result, limit: int) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExtensionDistributionError("distribution files must be regular single-link files")
    if info.st_size < 0 or info.st_size > limit:
        raise ExtensionDistributionError("distribution file size is outside V1")


def _descriptor_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return _portable_file_identity(info)


def _path_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return _portable_file_identity(info)


def _portable_file_identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_no_link_components(path: Path, *, stop: Path | None = None) -> None:
    current = path
    while True:
        if is_link_or_reparse(current):
            raise ExtensionDistributionError("distribution path traverses a link or reparse point")
        if stop is not None and current == stop:
            break
        if current.parent == current:
            break
        current = current.parent


def _enumerate_regular_files(root: Path, relative_dir: str) -> set[str]:
    directory = root.joinpath(*PurePosixPath(relative_dir).parts)
    _require_no_link_components(directory, stop=root)
    if not directory.is_dir():
        raise ExtensionDistributionError("distribution metadata directory is missing")
    files: set[str] = set()
    entry_count = 0
    for candidate in directory.iterdir():
        entry_count += 1
        if entry_count > MAX_DISTRIBUTION_FILES:
            raise ExtensionDistributionError("distribution metadata entry count exceeds V1")
        _require_no_link_components(candidate, stop=root)
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise ExtensionDistributionError(
                "distribution metadata entry is unavailable"
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise ExtensionDistributionError(
                "distribution metadata contains an extra directory or non-file"
            )
        files.add(candidate.relative_to(root).as_posix())
    return files


def _verify_core_metadata(payload: bytes, normalized_name: str, version: str) -> None:
    try:
        message = BytesParser(policy=policy.default).parsebytes(payload)
    except (TypeError, ValueError) as exc:
        raise ExtensionDistributionError("distribution METADATA is invalid") from exc
    names = message.get_all("Name", [])
    versions = message.get_all("Version", [])
    requires_python = message.get_all("Requires-Python", [])
    dependencies = message.get_all("Requires-Dist", [])
    if len(names) != 1 or _normalize_distribution_name(str(names[0])) != normalized_name:
        raise ExtensionDistributionError("distribution METADATA name is ambiguous")
    if len(versions) != 1 or str(versions[0]) != version:
        raise ExtensionDistributionError("distribution METADATA version is ambiguous")
    if len(requires_python) != 1 or str(requires_python[0]) != ">=3.11,<3.14":
        raise ExtensionDistributionError("distribution Python compatibility is unsupported")
    if dependencies:
        raise ExtensionDistributionError("V1 extension distributions must have no dependencies")


def _verify_wheel_metadata(payload: bytes) -> None:
    try:
        message = BytesParser(policy=policy.default).parsebytes(payload)
    except (TypeError, ValueError) as exc:
        raise ExtensionDistributionError("distribution WHEEL metadata is invalid") from exc
    versions = message.get_all("Wheel-Version", [])
    purelib = message.get_all("Root-Is-Purelib", [])
    tags = message.get_all("Tag", [])
    if versions != ["1.0"] or [str(value).lower() for value in purelib] != ["true"]:
        raise ExtensionDistributionError("distribution WHEEL must be pure Python V1")
    if tags != ["py3-none-any"]:
        raise ExtensionDistributionError("distribution WHEEL tag is unsupported")


def _parse_entry_points(payload: bytes, extension_id: str) -> tuple[str, str, str]:
    try:
        text = payload.decode("utf-8")
        parser = _CaseSensitiveConfigParser(interpolation=None, strict=True)
        parser.read_string(text)
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise ExtensionDistributionError("distribution entry points are invalid") from exc
    if parser.defaults():
        raise ExtensionDistributionError("distribution entry-point defaults are forbidden")
    if parser.sections() != [EXTENSION_ENTRY_POINT_GROUP_V1]:
        raise ExtensionDistributionError("distribution entry-point groups contain extras or gaps")
    entries = list(parser.items(EXTENSION_ENTRY_POINT_GROUP_V1, raw=True))
    if len(entries) != 1 or entries[0][0] != extension_id:
        raise ExtensionDistributionError("selected entry point must resolve exactly once")
    entry_name, value = entries[0]
    if "[" in value or "]" in value or value.count(":") != 1:
        raise ExtensionDistributionError("entry-point value is outside the V1 grammar")
    module_name, factory_attribute = (part.strip() for part in value.split(":", 1))
    if not _MODULE.fullmatch(module_name) or not _ATTRIBUTE.fullmatch(factory_attribute):
        raise ExtensionDistributionError("entry-point module or factory is unsafe")
    return entry_name, module_name, factory_attribute


def _canonical_manifest_bytes(manifest: ExtensionManifestV1) -> bytes:
    from agentic_security_harness.extension_sdk import encode_extension_manifest_v1

    return encode_extension_manifest_v1(manifest)


def _canonical_bytes(payload: object, label: str) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise ExtensionDistributionError(f"distribution {label} is not canonical JSON") from exc
    if len(encoded) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionDistributionError(f"distribution {label} exceeds the V1 byte limit")
    return encoded


def _decode_receipt(
    payload: bytes,
    model: type[ExtensionDistributionInspectionV1] | type[ExtensionDistributionApprovalV1],
    label: str,
) -> ExtensionDistributionInspectionV1 | ExtensionDistributionApprovalV1:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionDistributionError(f"distribution {label} size is outside V1")
    try:
        text = payload.decode("utf-8")
        _require_bounded_json_nesting(text)
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_int=_bounded_json_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except ExtensionDistributionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ExtensionDistributionError(
            f"distribution {label} is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict) or set(value) != set(model.model_fields):
        raise ExtensionDistributionError(f"distribution {label} fields do not match V1")
    try:
        receipt = model.model_validate(value)
    except ValueError as exc:
        raise ExtensionDistributionError(f"distribution {label} values violate V1") from exc
    if _canonical_bytes(receipt.model_dump(mode="json"), label) != payload:
        raise ExtensionDistributionError(f"distribution {label} JSON is not canonical V1")
    return receipt


def _require_bounded_json_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DISTRIBUTION_JSON_DEPTH:
                raise ExtensionDistributionError(
                    "distribution receipt JSON nesting exceeds V1"
                )
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ExtensionDistributionError("distribution receipt JSON nesting is invalid")


def _bounded_json_integer(token: str) -> int:
    if len(token.removeprefix("-")) > MAX_DISTRIBUTION_INTEGER_DIGITS:
        raise ExtensionDistributionError("distribution receipt JSON integer exceeds V1")
    return int(token)


def _reject_json_float(_token: str) -> float:
    raise ExtensionDistributionError("distribution receipt JSON floats are forbidden")


def _reject_json_constant(_token: str) -> None:
    raise ExtensionDistributionError("distribution receipt JSON constants are forbidden")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ExtensionDistributionError("duplicate distribution JSON field")
        value[key] = item
    return value


def _digest_payload(domain: str, payload: object) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _canonical_bytes(payload, "identity")
    ).hexdigest()


def _files_identity(files: tuple[DistributionFileBindingV1, ...]) -> str:
    return _digest_payload(
        "agentic-security-harness/extension-distribution-files/v1.0",
        [item.model_dump(mode="json") for item in files],
    )


def _inspection_identity(inspection: ExtensionDistributionInspectionV1) -> str:
    return _digest_payload(
        "agentic-security-harness/extension-distribution-inspection/v1.0",
        inspection.model_dump(mode="json", exclude={"inspection_id"}),
    )


def _approval_identity(approval: ExtensionDistributionApprovalV1) -> str:
    return _digest_payload(
        "agentic-security-harness/extension-distribution-approval/v1.0",
        approval.model_dump(mode="json", exclude={"approval_id"}),
    )
