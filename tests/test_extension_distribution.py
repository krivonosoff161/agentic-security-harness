from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
from pydantic import ValidationError
from tools.extension_distribution_contracts import generated_contracts

from agentic_security_harness.extension_distribution import (
    EXTENSION_ENTRY_POINT_GROUP_V1,
    ExtensionDistributionApprovalV1,
    ExtensionDistributionError,
    ExtensionDistributionInspectionV1,
    approve_extension_distribution_v1,
    bind_operator_approved_extension_v1,
    decode_extension_distribution_approval_v1,
    decode_extension_distribution_inspection_v1,
    encode_extension_distribution_approval_v1,
    encode_extension_distribution_inspection_v1,
    extension_distribution_v1_json_schemas,
    inspect_extension_distribution_v1,
)
from agentic_security_harness.extension_sdk import (
    ExtensionContractRefV1,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    encode_extension_manifest_v1,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIGURATION = b'{"mode":"synthetic","network":"off"}\n'
MODULE_NAME = "ash_demo_extension"
EXTENSION_ID = "example.demo-extension"
DIST_NAME = "demo-extension"
DIST_VERSION = "1.0.0"


class _SyntheticExtension:
    def __init__(self, manifest: ExtensionManifestV1) -> None:
        self.manifest = manifest

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        return (
            ExtensionFindingV1(
                check_id="example.demo-extension.checked",
                outcome="inconclusive",
                severity="none",
                reason_code="synthetic.fixture",
                evidence_event_ids=(envelope.events[0].event_id,),
            ),
        )


def _manifest(module_bytes: bytes) -> ExtensionManifestV1:
    return ExtensionManifestV1(
        schema_version="harness-extension-manifest-v1.0",
        extension_id=EXTENSION_ID,
        extension_version=DIST_VERSION,
        component_id="agentic-security-harness",
        implementation_sha256=hashlib.sha256(module_bytes).hexdigest(),
        configuration_sha256=hashlib.sha256(CONFIGURATION).hexdigest(),
        harness_api="1",
        kind="check_extension",
        capabilities=("observation.read", "finding.emit"),
        consumes=(
            ExtensionContractRefV1(
                contract_id="portfolio-observation", version="1.0", required=True
            ),
        ),
        produces=(
            ExtensionContractRefV1(
                contract_id="extension-finding", version="1.0", required=True
            ),
        ),
        deterministic=True,
        evidence_provenance="deterministic_rule",
        network_mode="off",
        raw_data_policy="digests_only",
        execution_model="in_process_operator_approved_not_sandboxed",
        operational_authority="none",
    )


def _record_digest(payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode("ascii")
    return f"sha256={digest.rstrip('=')}"


def _build_and_install_wheel(
    tmp_path: Path,
    *,
    suffix: str = "one",
    entry_point_value: str | None = None,
    extra_entry_group: bool = False,
    extra_module: bool = False,
    dependency: bool = False,
    entry_points_text: str | None = None,
    module_name: str = MODULE_NAME,
    record_size_override: str | None = None,
) -> tuple[Path, Path, ExtensionManifestV1]:
    module_bytes = (
        b'"""Synthetic inert extension wheel fixture; never imported by discovery."""\n'
        b"MARKER = 'fixture-only'\n"
    )
    manifest = _manifest(module_bytes)
    dist_info = "demo_extension-1.0.0.dist-info"
    entry_value = entry_point_value or f"{module_name}:build_extension"
    entry_points = entry_points_text or (
        f"[{EXTENSION_ENTRY_POINT_GROUP_V1}]\n{EXTENSION_ID} = {entry_value}\n"
    )
    if extra_entry_group:
        entry_points += "\n[console_scripts]\nunsafe-extra = example:main\n"
    dependency_line = "Requires-Dist: unsafe-dependency>=1\n" if dependency else ""
    files: dict[str, bytes] = {
        f"{module_name}.py": module_bytes,
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {DIST_NAME}\n"
            f"Version: {DIST_VERSION}\n"
            "Requires-Python: >=3.11,<3.14\n"
            f"{dependency_line}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: agentic-security-harness-test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": entry_points.encode(),
        f"{dist_info}/ash-extension-manifest.json": encode_extension_manifest_v1(manifest),
    }
    if extra_module:
        files["unapproved_helper.py"] = b"UNAPPROVED = True\n"
    record_path = f"{dist_info}/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for index, (path, payload) in enumerate(files.items()):
        size: str | int = len(payload)
        if index == 0 and record_size_override is not None:
            size = record_size_override
        writer.writerow((path, _record_digest(payload), size))
    writer.writerow((record_path, "", ""))
    files[record_path] = output.getvalue().encode()

    fixture_root = tmp_path / suffix
    fixture_root.mkdir()
    wheel = fixture_root / "demo_extension-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, payload in files.items():
            archive.writestr(path, payload)
    install_root = fixture_root / "installed"
    install_root.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        assert all(".." not in PurePath.parts for PurePath in map(Path, archive.namelist()))
        archive.extractall(install_root)
    return wheel, install_root, manifest


def _inspect(root: Path) -> ExtensionDistributionInspectionV1:
    return inspect_extension_distribution_v1(
        distribution_name="Demo_Extension",
        extension_id=EXTENSION_ID,
        search_paths=(root,),
        configuration_bytes=CONFIGURATION,
    )


def test_synthetic_wheel_inspection_approval_and_binding_are_explicit(tmp_path: Path) -> None:
    wheel, installed, manifest = _build_and_install_wheel(tmp_path)
    assert wheel.suffix == ".whl"
    assert MODULE_NAME not in sys.modules

    inspection = _inspect(installed)
    assert inspection.distribution_name == DIST_NAME
    assert inspection.requires_python == ">=3.11,<3.14"
    assert inspection.wheel_tag == "py3-none-any"
    assert inspection.file_count == 6
    assert inspection.module_path == f"{MODULE_NAME}.py"
    assert inspection.manifest_sha256 == hashlib.sha256(
        encode_extension_manifest_v1(manifest)
    ).hexdigest()
    assert inspection.code_loaded is False
    assert inspection.signature_verified is False
    assert inspection.sandboxed is False
    assert MODULE_NAME not in sys.modules
    assert decode_extension_distribution_inspection_v1(
        encode_extension_distribution_inspection_v1(inspection)
    ) == inspection

    approval = approve_extension_distribution_v1(
        approved_inspection=inspection,
        approved_inspection_id=inspection.inspection_id,
        search_paths=(installed,),
        configuration_bytes=CONFIGURATION,
    )
    assert approval.inspection_id == inspection.inspection_id
    assert approval.code_loaded is False
    assert decode_extension_distribution_approval_v1(
        encode_extension_distribution_approval_v1(approval)
    ) == approval

    wrapped = bind_operator_approved_extension_v1(
        approval, _SyntheticExtension(manifest)
    )
    assert wrapped.approval == approval
    assert wrapped.manifest == manifest
    assert MODULE_NAME not in sys.modules


def test_approval_rejects_wrong_id_and_post_inspection_drift(tmp_path: Path) -> None:
    _, installed, _ = _build_and_install_wheel(tmp_path)
    inspection = _inspect(installed)
    with pytest.raises(ExtensionDistributionError, match="does not match"):
        approve_extension_distribution_v1(
            approved_inspection=inspection,
            approved_inspection_id="0" * 64,
            search_paths=(installed,),
            configuration_bytes=CONFIGURATION,
        )

    (installed / f"{MODULE_NAME}.py").write_text("drift = True\n", encoding="utf-8")
    with pytest.raises(ExtensionDistributionError, match="does not match RECORD"):
        approve_extension_distribution_v1(
            approved_inspection=inspection,
            approved_inspection_id=inspection.inspection_id,
            search_paths=(installed,),
            configuration_bytes=CONFIGURATION,
        )


def test_configuration_and_constructed_manifest_drift_fail_closed(tmp_path: Path) -> None:
    _, installed, manifest = _build_and_install_wheel(tmp_path)
    with pytest.raises(ExtensionDistributionError, match="configuration digest"):
        inspect_extension_distribution_v1(
            distribution_name=DIST_NAME,
            extension_id=EXTENSION_ID,
            search_paths=(installed,),
            configuration_bytes=b"different",
        )
    inspection = _inspect(installed)
    approval = approve_extension_distribution_v1(
        approved_inspection=inspection,
        approved_inspection_id=inspection.inspection_id,
        search_paths=(installed,),
        configuration_bytes=CONFIGURATION,
    )
    drifted = manifest.model_copy(update={"configuration_sha256": "0" * 64})
    with pytest.raises(ExtensionDistributionError, match="differs from approval"):
        bind_operator_approved_extension_v1(approval, _SyntheticExtension(drifted))

    mutable = _SyntheticExtension(manifest)
    wrapped = bind_operator_approved_extension_v1(approval, mutable)
    mutable.manifest = drifted
    with pytest.raises(ExtensionDistributionError, match="drifted after binding"):
        _ = wrapped.manifest
    with pytest.raises(ExtensionDistributionError, match="drifted after binding"):
        wrapped.evaluate(cast(ExtensionObservationEnvelopeV1, object()))

    class _MutatingExtension(_SyntheticExtension):
        def evaluate(
            self, envelope: ExtensionObservationEnvelopeV1
        ) -> tuple[ExtensionFindingV1, ...]:
            self.manifest = drifted
            return ()

    mutating = bind_operator_approved_extension_v1(
        approval, _MutatingExtension(manifest)
    )
    with pytest.raises(ExtensionDistributionError, match="drifted after binding"):
        mutating.evaluate(cast(ExtensionObservationEnvelopeV1, object()))


def test_collision_extra_metadata_and_entry_point_groups_are_rejected(tmp_path: Path) -> None:
    _, first, _ = _build_and_install_wheel(tmp_path, suffix="one")
    _, second, _ = _build_and_install_wheel(tmp_path, suffix="two")
    with pytest.raises(ExtensionDistributionError, match="resolve exactly once"):
        inspect_extension_distribution_v1(
            distribution_name=DIST_NAME,
            extension_id=EXTENSION_ID,
            search_paths=(first, second),
            configuration_bytes=CONFIGURATION,
        )

    dist_info = first / "demo_extension-1.0.0.dist-info"
    (dist_info / "unrecorded.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(ExtensionDistributionError, match="extras or gaps"):
        _inspect(first)

    _, extra_group, _ = _build_and_install_wheel(
        tmp_path, suffix="extra-group", extra_entry_group=True
    )
    with pytest.raises(ExtensionDistributionError, match="groups contain extras"):
        _inspect(extra_group)

    _, extra_code, _ = _build_and_install_wheel(
        tmp_path, suffix="extra-code", extra_module=True
    )
    with pytest.raises(ExtensionDistributionError, match="extra implementation"):
        _inspect(extra_code)

    _, dependency, _ = _build_and_install_wheel(
        tmp_path, suffix="dependency", dependency=True
    )
    with pytest.raises(ExtensionDistributionError, match="must have no dependencies"):
        _inspect(dependency)

    _, inherited, _ = _build_and_install_wheel(
        tmp_path,
        suffix="inherited-entry",
        entry_points_text=(
            f"[DEFAULT]\n{EXTENSION_ID} = {MODULE_NAME}:build_extension\n\n"
            f"[{EXTENSION_ENTRY_POINT_GROUP_V1}]\n"
        ),
    )
    with pytest.raises(ExtensionDistributionError, match="defaults are forbidden"):
        _inspect(inherited)

    _, nested_metadata, _ = _build_and_install_wheel(
        tmp_path, suffix="nested-metadata"
    )
    (nested_metadata / "demo_extension-1.0.0.dist-info" / "unrecorded").mkdir()
    with pytest.raises(ExtensionDistributionError, match="extra directory"):
        _inspect(nested_metadata)


def test_unsafe_module_origin_and_loaded_name_collisions_are_rejected(tmp_path: Path) -> None:
    _, dotted, _ = _build_and_install_wheel(
        tmp_path,
        suffix="dotted",
        entry_point_value="unsafe.package:factory",
    )
    with pytest.raises(ExtensionDistributionError, match="module or factory is unsafe"):
        _inspect(dotted)

    _, installed, _ = _build_and_install_wheel(tmp_path, suffix="loaded")
    sys.modules[MODULE_NAME] = ModuleType(MODULE_NAME)
    try:
        with pytest.raises(ExtensionDistributionError, match="already loaded"):
            _inspect(installed)
    finally:
        sys.modules.pop(MODULE_NAME, None)

    _, reserved, _ = _build_and_install_wheel(
        tmp_path, suffix="reserved", module_name="con"
    )
    with pytest.raises(ExtensionDistributionError, match="not portable"):
        _inspect(reserved)


def test_stable_read_rejects_transient_same_identity_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    baseline = b"original-bytes"
    transient = b"transient-byte"
    assert len(transient) == len(baseline)
    path = tmp_path / "sample.bin"
    path.write_bytes(baseline)
    reads = iter((transient, b"", baseline, b""))
    monkeypatch.setattr(module.os, "read", lambda _descriptor, _size: next(reads))
    monkeypatch.setattr(
        module, "_descriptor_identity", lambda _info: (1, 1, 1, 1, 1, 1, 1)
    )

    with pytest.raises(ExtensionDistributionError, match="changed while it was read"):
        module._stable_read(tmp_path, path.name, len(baseline))


@pytest.mark.skipif(os.name == "nt", reason="POSIX identity binding regression")
def test_posix_stable_read_retains_path_descriptor_identity_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    payload = b"portable-windows-stat"
    path = tmp_path / "sample.bin"
    path.write_bytes(payload)
    monkeypatch.setattr(
        module, "_path_identity", lambda _info: (1, 1, 1, 1, 1, 1, 1)
    )
    monkeypatch.setattr(
        module, "_descriptor_identity", lambda _info: (2, 2, 2, 2, 2, 2, 2)
    )

    with pytest.raises(ExtensionDistributionError, match="changed before"):
        module._stable_read(tmp_path, path.name, len(payload))


@pytest.mark.skipif(os.name != "nt", reason="Windows native reader regression")
def test_windows_native_stable_read_accepts_unchanged_file(tmp_path: Path) -> None:
    import agentic_security_harness.extension_distribution as module

    payload = b"portable-windows-stat"
    path = tmp_path / "sample.bin"
    path.write_bytes(payload)

    assert module._stable_read(tmp_path, path.name, len(payload)) == payload


def test_stable_read_rejects_target_swap_between_descriptor_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    baseline = b"approved-content"
    replacement = b"attacker-content"
    assert len(replacement) == len(baseline)
    path = tmp_path / "sample.bin"
    alternate = tmp_path / "alternate.bin"
    path.write_bytes(baseline)
    alternate.write_bytes(replacement)
    real_open = (
        module._open_windows_distribution_descriptor
        if os.name == "nt"
        else module.os.open
    )
    calls = 0

    def _open_with_swapped_second_target(candidate: Path, *args: int) -> int:
        nonlocal calls
        calls += 1
        if calls == 2:
            return real_open(alternate, *args)
        return real_open(candidate, *args)

    if os.name == "nt":
        monkeypatch.setattr(
            module, "_open_windows_distribution_descriptor", _open_with_swapped_second_target
        )
    else:
        monkeypatch.setattr(module.os, "open", _open_with_swapped_second_target)
    with pytest.raises(ExtensionDistributionError, match="between stable reads"):
        module._stable_read(tmp_path, path.name, len(baseline))


def test_stable_read_rejects_pre_open_path_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    baseline = b"approved-content"
    replacement = b"attacker-content"
    assert len(replacement) == len(baseline)
    path = tmp_path / "sample.bin"
    saved = tmp_path / "saved.bin"
    alternate = tmp_path / "alternate.bin"
    path.write_bytes(baseline)
    alternate.write_bytes(replacement)
    real_open = (
        module._open_windows_distribution_descriptor
        if os.name == "nt"
        else module.os.open
    )
    swapped = False

    def _open_after_swap(candidate: Path, *args: int) -> int:
        nonlocal swapped
        if not swapped:
            os.replace(path, saved)
            os.replace(alternate, path)
            swapped = True
        return real_open(candidate, *args)

    if os.name == "nt":
        monkeypatch.setattr(module, "_open_windows_distribution_descriptor", _open_after_swap)
        expected = "changed while"
    else:
        monkeypatch.setattr(module.os, "open", _open_after_swap)
        expected = "changed before"
    with pytest.raises(ExtensionDistributionError, match=expected):
        module._stable_read(tmp_path, path.name, len(baseline))


@pytest.mark.skipif(os.name != "nt", reason="Windows close-order ABA regression")
def test_windows_native_reader_validates_before_unlocking_first_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    baseline = b"approved-content"
    replacement = b"attacker-content"
    assert len(replacement) == len(baseline)
    path = tmp_path / "sample.bin"
    saved = tmp_path / "saved.bin"
    displaced = tmp_path / "displaced.bin"
    alternate = tmp_path / "alternate.bin"
    path.write_bytes(baseline)
    alternate.write_bytes(replacement)
    real_open = module._open_windows_distribution_descriptor
    real_close = module.os.close
    target_descriptors: list[int] = []
    denied_while_first_locked: list[int] = []
    restored_after_first_close = False

    def _open_after_swap(candidate: Path) -> int:
        if not target_descriptors:
            os.replace(path, saved)
            os.replace(alternate, path)
        descriptor = real_open(candidate)
        target_descriptors.append(descriptor)
        return descriptor

    def _close_with_restore(descriptor: int) -> None:
        nonlocal restored_after_first_close
        real_close(descriptor)
        if descriptor in target_descriptors[1:]:
            try:
                os.replace(path, displaced)
            except OSError:
                denied_while_first_locked.append(descriptor)
        elif target_descriptors and descriptor == target_descriptors[0]:
            os.replace(path, displaced)
            os.replace(saved, path)
            restored_after_first_close = True

    monkeypatch.setattr(module, "_open_windows_ancestor_guards", lambda _root, _path: ())
    monkeypatch.setattr(module, "_open_windows_distribution_descriptor", _open_after_swap)
    monkeypatch.setattr(module.os, "close", _close_with_restore)

    with pytest.raises(ExtensionDistributionError, match="changed while"):
        module._stable_read(tmp_path, path.name, len(baseline))

    assert len(target_descriptors) == 3
    assert len(denied_while_first_locked) == 2
    assert restored_after_first_close is True
    assert path.read_bytes() == baseline


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode regression")
def test_windows_native_reader_denies_mutation_while_handle_is_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    payload = b"approved-content"
    path = tmp_path / "sample.bin"
    replacement = tmp_path / "replacement.bin"
    path.write_bytes(payload)
    replacement.write_bytes(b"attacker-content")
    real_read = module._read_descriptor_contents
    checked = False

    def _read_while_attacking(descriptor: int, limit: int) -> bytes:
        nonlocal checked
        if not checked:
            checked = True
            for action in (
                lambda: path.write_bytes(b"attacker-content"),
                path.unlink,
                lambda: os.replace(replacement, path),
            ):
                with pytest.raises(OSError):
                    action()
        return real_read(descriptor, limit)

    monkeypatch.setattr(module, "_read_descriptor_contents", _read_while_attacking)
    assert module._stable_read(tmp_path, path.name, len(payload)) == payload
    assert checked is True


@pytest.mark.skipif(os.name != "nt", reason="Windows ancestor-lock regression")
def test_windows_native_reader_denies_ancestor_rename_while_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    root = tmp_path / "root"
    parent = root / "parent"
    parent.mkdir(parents=True)
    path = parent / "sample.bin"
    path.write_bytes(b"approved-content")
    moved = root / "moved"
    real_read = module._read_descriptor_contents
    checked = False

    def _read_while_attacking(descriptor: int, limit: int) -> bytes:
        nonlocal checked
        if not checked:
            checked = True
            with pytest.raises(OSError):
                os.replace(parent, moved)
        return real_read(descriptor, limit)

    monkeypatch.setattr(module, "_read_descriptor_contents", _read_while_attacking)
    assert module._stable_read(root, "parent/sample.bin", len(b"approved-content")) == (
        b"approved-content"
    )
    assert checked is True


def test_stable_read_rejects_reparse_signal_and_oversize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.extension_distribution as module

    path = tmp_path / "sample.bin"
    path.write_bytes(b"12345")
    real_link_check = module.is_link_or_reparse
    monkeypatch.setattr(
        module,
        "is_link_or_reparse",
        lambda candidate: candidate == path or real_link_check(candidate),
    )
    with pytest.raises(ExtensionDistributionError, match="link or reparse"):
        module._stable_read(tmp_path, path.name, 5)

    monkeypatch.setattr(module, "is_link_or_reparse", real_link_check)
    with pytest.raises(ExtensionDistributionError, match="size is outside"):
        module._stable_read(tmp_path, path.name, 4)


@pytest.mark.parametrize("size", ("9" * 5_000, "\u0661"))
def test_record_size_requires_bounded_ascii_digits(tmp_path: Path, size: str) -> None:
    _, installed, _ = _build_and_install_wheel(
        tmp_path, suffix=f"size-{len(size)}", record_size_override=size
    )
    with pytest.raises(ExtensionDistributionError, match="require sha256 and size"):
        _inspect(installed)


def test_hardlinked_distribution_file_and_noncanonical_receipts_are_rejected(
    tmp_path: Path,
) -> None:
    _, installed, _ = _build_and_install_wheel(tmp_path)
    module = installed / f"{MODULE_NAME}.py"
    os.link(module, installed / "second-link.py")
    with pytest.raises(ExtensionDistributionError, match="single-link"):
        _inspect(installed)

    second_root = tmp_path / "clean"
    second_root.mkdir()
    _, clean, _ = _build_and_install_wheel(second_root)
    inspection = _inspect(clean)
    values = inspection.model_dump(mode="python")
    with pytest.raises(ValidationError, match="inspection id"):
        ExtensionDistributionInspectionV1.model_validate(
            {**values, "record_sha256": "0" * 64}
        )
    approval = approve_extension_distribution_v1(
        approved_inspection=inspection,
        approved_inspection_id=inspection.inspection_id,
        search_paths=(clean,),
        configuration_bytes=CONFIGURATION,
    )
    with pytest.raises(ValidationError, match="approval id"):
        ExtensionDistributionApprovalV1.model_validate(
            {**approval.model_dump(mode="python"), "files_sha256": "0" * 64}
        )

    with pytest.raises(ExtensionDistributionError, match="integer exceeds"):
        decode_extension_distribution_inspection_v1(
            b'{"file_count":' + b"9" * 5_000 + b"}\n"
        )


def test_schemas_are_closed_generated_and_source_has_no_loader_surface() -> None:
    schemas = extension_distribution_v1_json_schemas()
    assert set(schemas) == {
        "extension-distribution-inspection.v1.schema.json",
        "extension-distribution-approval.v1.schema.json",
    }
    for name, schema in schemas.items():
        assert schema["additionalProperties"] is False
        assert json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")) == schema
    for path, expected in generated_contracts().items():
        assert path.read_bytes() == expected

    contract = json.loads(
        (ROOT / "schemas" / "extension-distribution.v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert {binding["path"] for binding in contract["runtime_closure"]} == {
        "src/agentic_security_harness/__init__.py",
        "src/agentic_security_harness/extension_sdk.py",
        "src/agentic_security_harness/portfolio_contract.py",
        "src/agentic_security_harness/safe_io.py",
    }
    for binding in (
        contract["runtime_closure"]
        + [
            contract["implementation"],
            contract["generator"],
            contract["tests"],
            contract["documentation"],
            contract["workflow"],
        ]
    ):
        path = ROOT / binding["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == binding["sha256"]

    source = (
        ROOT / "src" / "agentic_security_harness" / "extension_distribution.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        "import socket",
        "import subprocess",
        "import requests",
        "import httpx",
        "import_module(",
        "entry_point.load(",
        "urlopen(",
        "exec(",
    )
    assert all(token not in source for token in forbidden)
