from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

from agentic_security_harness.cli import main
from agentic_security_harness.extension_distribution import (
    EXTENSION_ENTRY_POINT_GROUP_V1,
    ExtensionDistributionApprovalV1,
    ExtensionDistributionError,
    approve_extension_distribution_v1,
    encode_extension_distribution_approval_v1,
    inspect_extension_distribution_v1,
)
from agentic_security_harness.extension_lifecycle import (
    ExtensionLifecycleError,
    ExtensionLifecycleItemV1,
    bind_active_operator_extension_v1,
    decode_extension_disable_receipt_v1,
    decode_extension_lifecycle_projection_v1,
    decode_extension_rollback_plan_v1,
    disable_extension_approval_v1,
    encode_extension_disable_receipt_v1,
    encode_extension_lifecycle_projection_v1,
    encode_extension_rollback_plan_v1,
    plan_extension_rollback_v1,
    project_extension_lifecycle_v1,
    read_extension_approval_file_v1,
)
from agentic_security_harness.extension_sdk import (
    ExtensionContractRefV1,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    encode_extension_manifest_v1,
)

CONFIGURATION = b'{"mode":"synthetic","network":"off"}\n'
EXTENSION_ID = "example.lifecycle-extension"
DIST_NAME = "lifecycle-extension"
MODULE_NAME = "ash_lifecycle_extension"


class _SyntheticExtension:
    def __init__(self, manifest: ExtensionManifestV1) -> None:
        self.manifest = manifest

    def evaluate(
        self, _envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        return ()


def _manifest(module_bytes: bytes, version: str) -> ExtensionManifestV1:
    return ExtensionManifestV1(
        schema_version="harness-extension-manifest-v1.0",
        extension_id=EXTENSION_ID,
        extension_version=version,
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


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _install_fixture(root: Path, version: str) -> tuple[Path, ExtensionManifestV1]:
    root.mkdir(parents=True)
    module_bytes = f"VERSION = {version!r}\n".encode()
    manifest = _manifest(module_bytes, version)
    normalized_version = version.replace("-", "_")
    dist_info = f"lifecycle_extension-{normalized_version}.dist-info"
    files = {
        f"{MODULE_NAME}.py": module_bytes,
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {DIST_NAME}\n"
            f"Version: {version}\n"
            "Requires-Python: >=3.11,<3.14\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": (
            f"[{EXTENSION_ENTRY_POINT_GROUP_V1}]\n"
            f"{EXTENSION_ID} = {MODULE_NAME}:build_extension\n"
        ).encode(),
        f"{dist_info}/ash-extension-manifest.json": encode_extension_manifest_v1(manifest),
    }
    record_path = f"{dist_info}/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path, payload in files.items():
        writer.writerow((path, _record_digest(payload), len(payload)))
    writer.writerow((record_path, "", ""))
    files[record_path] = output.getvalue().encode()
    wheel = root / f"lifecycle_extension-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, payload in files.items():
            archive.writestr(path, payload)
    installed = root / "installed"
    installed.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(installed)
    return installed, manifest


def _approval(root: Path) -> tuple[ExtensionDistributionApprovalV1, ExtensionManifestV1]:
    inspection = inspect_extension_distribution_v1(
        distribution_name=DIST_NAME,
        extension_id=EXTENSION_ID,
        search_paths=(root,),
        configuration_bytes=CONFIGURATION,
    )
    return (
        approve_extension_distribution_v1(
            approved_inspection=inspection,
            approved_inspection_id=inspection.inspection_id,
            search_paths=(root,),
            configuration_bytes=CONFIGURATION,
        ),
        _manifest((root / f"{MODULE_NAME}.py").read_bytes(), inspection.extension_version),
    )


def test_metadata_lifecycle_receipts_and_binding_are_closed(tmp_path: Path) -> None:
    current_root, current_manifest = _install_fixture(tmp_path / "current", "2.0.0")
    target_root, _ = _install_fixture(tmp_path / "target", "1.0.0")
    current, _ = _approval(current_root)
    target, _ = _approval(target_root)

    disabled = disable_extension_approval_v1(current, operator_action_id="disable:ticket-1")
    assert decode_extension_disable_receipt_v1(
        encode_extension_disable_receipt_v1(disabled)
    ) == disabled
    assert disabled.executable_state_changed is False
    assert disabled.operator_authenticated is False

    plan = plan_extension_rollback_v1(
        current_approval=current,
        disable_receipt=disabled,
        target_approval=target,
        known_disable_receipts=(),
        operator_action_id="rollback:ticket-2",
    )
    assert decode_extension_rollback_plan_v1(encode_extension_rollback_plan_v1(plan)) == plan
    assert plan.state == "rollback_planned_non_executable"
    assert plan.version_direction_verified is False
    assert plan.automatic_import is False

    projection = project_extension_lifecycle_v1(
        approvals=(target, current), disable_receipts=(disabled,), rollback_plans=(plan,)
    )
    assert decode_extension_lifecycle_projection_v1(
        encode_extension_lifecycle_projection_v1(projection)
    ) == projection
    assert projection.item_count == 2
    assert encode_extension_lifecycle_projection_v1(projection).endswith(b"\n")
    assert [item.approval_id for item in projection.items] == sorted(
        item.approval_id for item in projection.items
    )
    current_state = next(
        item for item in projection.items if item.approval_id == current.approval_id
    )
    assert current_state.state == "rollback_planned_non_executable"

    wrapped = bind_active_operator_extension_v1(current, _SyntheticExtension(current_manifest))
    assert wrapped.approval == current
    with pytest.raises(ExtensionLifecycleError, match="approval is disabled"):
        bind_active_operator_extension_v1(
            current, _SyntheticExtension(current_manifest), disable_receipts=(disabled,)
        )
    assert MODULE_NAME not in sys.modules


def test_receipt_chain_rejects_drift_duplicates_and_parser_bombs(tmp_path: Path) -> None:
    root, _ = _install_fixture(tmp_path / "one", "1.0.0")
    approval, _ = _approval(root)
    disabled = disable_extension_approval_v1(approval, operator_action_id="disable:one")
    drifted = disabled.model_copy(update={"manifest_sha256": "0" * 64})
    with pytest.raises(ExtensionLifecycleError):
        encode_extension_disable_receipt_v1(drifted)
    with pytest.raises(ExtensionLifecycleError, match="multiple disable"):
        project_extension_lifecycle_v1(
            approvals=(approval,), disable_receipts=(disabled, disabled)
        )
    with pytest.raises(ExtensionLifecycleError):
        decode_extension_disable_receipt_v1(b"[" * 2_000 + b"]" * 2_000)
    with pytest.raises(ExtensionLifecycleError):
        decode_extension_disable_receipt_v1(b'{"schema_version":' + b"9" * 5_000 + b"}\n")


def test_operator_file_requires_expected_bytes_after_persistent_equal_length_swap(
    tmp_path: Path,
) -> None:
    first_root, _ = _install_fixture(tmp_path / "first", "1.0.0")
    second_root, _ = _install_fixture(tmp_path / "second", "2.0.0")
    first, _ = _approval(first_root)
    second, _ = _approval(second_root)
    first_bytes = encode_extension_distribution_approval_v1(first)
    second_bytes = encode_extension_distribution_approval_v1(second)
    assert len(first_bytes) == len(second_bytes)
    receipt_path = tmp_path / "approval.json"
    receipt_path.write_bytes(first_bytes)
    expected = _file_sha256(receipt_path)
    receipt_path.write_bytes(second_bytes)

    with pytest.raises(ExtensionLifecycleError, match="expected SHA-256"):
        read_extension_approval_file_v1(receipt_path, expected_sha256=expected)


def test_projection_state_sentinels_and_disabled_rollback_targets_fail_closed(
    tmp_path: Path,
) -> None:
    current_root, _ = _install_fixture(tmp_path / "current", "2.0.0")
    target_root, _ = _install_fixture(tmp_path / "target", "1.0.0")
    current, _ = _approval(current_root)
    target, _ = _approval(target_root)
    current_disabled = disable_extension_approval_v1(current, operator_action_id="disable:a")
    target_disabled = disable_extension_approval_v1(target, operator_action_id="disable:b")

    with pytest.raises(ValueError, match="sentinels"):
        ExtensionLifecycleItemV1.model_validate(
            {
                "approval_id": current.approval_id,
                "inspection_id": current.inspection_id,
                "distribution_name": current.distribution_name,
                "distribution_version": current.distribution_version,
                "extension_id": current.extension_id,
                "extension_version": current.extension_version,
                "state": "approved_metadata_only",
                "disable_id": current_disabled.disable_id,
                "rollback_plan_id": "0" * 64,
                "code_loaded": False,
                "executable_state_observed": False,
                "operational_authority": "none",
            }
        )

    with pytest.raises(ExtensionLifecycleError, match="target approval is disabled"):
        plan_extension_rollback_v1(
            current_approval=current,
            disable_receipt=current_disabled,
            target_approval=target,
            known_disable_receipts=(target_disabled,),
            operator_action_id="rollback:blocked",
        )

    plan = plan_extension_rollback_v1(
        current_approval=current,
        disable_receipt=current_disabled,
        target_approval=target,
        known_disable_receipts=(),
        operator_action_id="rollback:before-target-disable",
    )
    with pytest.raises(ExtensionLifecycleError, match="target approval is disabled"):
        project_extension_lifecycle_v1(
            approvals=(current, target),
            disable_receipts=(current_disabled, target_disabled),
            rollback_plans=(plan,),
        )


def test_cli_inspect_approve_disable_and_list_never_load_code_or_echo_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    installed, _ = _install_fixture(tmp_path / "fixture", "1.0.0")
    configuration = tmp_path / "configuration.json"
    configuration.write_bytes(CONFIGURATION)

    assert main(
        [
            "extension-distribution-inspect",
            "--distribution-name",
            DIST_NAME,
            "--extension-id",
            EXTENSION_ID,
            "--search-path",
            str(installed),
            "--configuration",
            str(configuration),
            "--configuration-sha256",
            _file_sha256(configuration),
            "--format",
            "json",
        ]
    ) == 0
    inspection_text = capsys.readouterr().out
    inspection = json.loads(inspection_text)
    inspection_path = tmp_path / "inspection.json"
    inspection_path.write_text(inspection_text, encoding="utf-8", newline="")
    assert str(installed) not in inspection_text
    assert str(configuration) not in inspection_text

    assert main(
        [
            "extension-distribution-approve",
            "--inspection",
            str(inspection_path),
            "--inspection-sha256",
            _file_sha256(inspection_path),
            "--inspection-id",
            inspection["inspection_id"],
            "--search-path",
            str(installed),
            "--configuration",
            str(configuration),
            "--configuration-sha256",
            _file_sha256(configuration),
            "--format",
            "json",
        ]
    ) == 0
    approval_text = capsys.readouterr().out
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(approval_text, encoding="utf-8", newline="")

    assert main(
        [
            "extension-lifecycle-disable",
            "--approval",
            str(approval_path),
            "--approval-sha256",
            _file_sha256(approval_path),
            "--operator-action-id",
            "disable:cli",
            "--format",
            "json",
        ]
    ) == 0
    disable_text = capsys.readouterr().out
    disable_path = tmp_path / "disable.json"
    disable_path.write_text(disable_text, encoding="utf-8", newline="")
    assert "disable:cli" not in disable_text

    assert main(
        [
            "extension-lifecycle-list",
            "--approval",
            str(approval_path),
            "--approval-sha256",
            _file_sha256(approval_path),
            "--disable",
            str(disable_path),
            "--disable-sha256",
            _file_sha256(disable_path),
            "--format",
            "json",
        ]
    ) == 0
    projection = json.loads(capsys.readouterr().out)
    assert projection["items"][0]["state"] == "disabled_metadata_only"
    assert projection["installed_state_discovered"] is False
    assert MODULE_NAME not in sys.modules


def test_cli_failures_are_sanitized(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    private_path = tmp_path / "private-machine-path" / "missing.json"
    assert main(
        [
            "extension-lifecycle-disable",
            "--approval",
            str(private_path),
            "--approval-sha256",
            "0" * 64,
            "--operator-action-id",
            "action",
        ]
    ) == 1
    output = capsys.readouterr().out
    assert "private-machine-path" not in output
    assert output == "Error: extension lifecycle disable receipt failed\n"


def test_cli_rollback_plan_is_non_executable_and_path_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    current_root, _ = _install_fixture(tmp_path / "current", "2.0.0")
    target_root, _ = _install_fixture(tmp_path / "target", "1.0.0")
    current, _ = _approval(current_root)
    target, _ = _approval(target_root)
    disabled = disable_extension_approval_v1(current, operator_action_id="disable")
    current_path = tmp_path / "current-approval.json"
    target_path = tmp_path / "target-approval.json"
    disable_path = tmp_path / "disable.json"
    current_path.write_bytes(encode_extension_distribution_approval_v1(current))
    target_path.write_bytes(encode_extension_distribution_approval_v1(target))
    disable_path.write_bytes(encode_extension_disable_receipt_v1(disabled))

    assert main(
        [
            "extension-lifecycle-rollback-plan",
            "--current-approval",
            str(current_path),
            "--current-approval-sha256",
            _file_sha256(current_path),
            "--disable",
            str(disable_path),
            "--disable-sha256",
            _file_sha256(disable_path),
            "--target-approval",
            str(target_path),
            "--target-approval-sha256",
            _file_sha256(target_path),
            "--operator-action-id",
            "rollback:cli",
            "--format",
            "json",
        ]
    ) == 0
    output = capsys.readouterr().out
    plan = json.loads(output)
    assert plan["state"] == "rollback_planned_non_executable"
    assert plan["version_direction_verified"] is False
    assert plan["executable_state_changed"] is False
    assert plan["automatic_import"] is False
    assert "rollback:cli" not in output
    assert str(tmp_path) not in output
    assert MODULE_NAME not in sys.modules


def test_rollback_requires_distinct_target(tmp_path: Path) -> None:
    root, _ = _install_fixture(tmp_path / "one", "1.0.0")
    approval, _ = _approval(root)
    disabled = disable_extension_approval_v1(approval, operator_action_id="disable")
    with pytest.raises((ExtensionLifecycleError, ValueError), match="target must differ"):
        plan_extension_rollback_v1(
            current_approval=approval,
            disable_receipt=disabled,
            target_approval=approval,
            known_disable_receipts=(),
            operator_action_id="rollback",
        )


def test_source_approval_remains_no_code_load(tmp_path: Path) -> None:
    installed, _ = _install_fixture(tmp_path / "fixture", "1.0.0")
    approval, _ = _approval(installed)
    assert approval.code_loaded is False
    assert approval.operational_authority == "none"
    assert MODULE_NAME not in sys.modules
    with pytest.raises(ExtensionDistributionError):
        inspect_extension_distribution_v1(
            distribution_name=DIST_NAME,
            extension_id=EXTENSION_ID,
            search_paths=(),
            configuration_bytes=CONFIGURATION,
        )
