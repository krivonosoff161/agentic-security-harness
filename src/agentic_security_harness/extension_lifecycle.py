"""Metadata-only operator lifecycle for verified Extension SDK distributions.

The lifecycle is deliberately split at the application embedding boundary.  Harness can
inspect installed distribution metadata, issue exact no-code-load approval/disable/rollback
receipts, and bind an object that the operator already constructed.  It never imports,
downloads, discovers, starts, disables, or rolls back extension code by itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.extension_distribution import (
    ExtensionDistributionApprovalV1,
    ExtensionDistributionError,
    ExtensionDistributionInspectionV1,
    OperatorApprovedExtensionV1,
    bind_operator_approved_extension_v1,
    decode_extension_distribution_approval_v1,
    decode_extension_distribution_inspection_v1,
)
from agentic_security_harness.extension_sdk import MAX_EXTENSION_PAYLOAD_BYTES, ExtensionV1
from agentic_security_harness.portfolio_contract import SHA256_PATTERN
from agentic_security_harness.safe_io import is_link_or_reparse

EXTENSION_DISABLE_V1: Final = "harness-extension-distribution-disable-v1.0"
EXTENSION_ROLLBACK_PLAN_V1: Final = "harness-extension-distribution-rollback-plan-v1.0"
EXTENSION_LIFECYCLE_PROJECTION_V1: Final = "harness-extension-lifecycle-projection-v1.0"
MAX_LIFECYCLE_RECEIPTS: Final = 256
MAX_OPERATOR_ACTION_BYTES: Final = 256
MAX_LIFECYCLE_JSON_DEPTH: Final = 32
MAX_LIFECYCLE_INTEGER_DIGITS: Final = 10
ZERO_SHA256: Final = "0" * 64
LifecycleState = Literal[
    "approved_metadata_only",
    "disabled_metadata_only",
    "rollback_planned_non_executable",
]
ModelT = TypeVar("ModelT", bound=BaseModel)


class ExtensionLifecycleError(ExtensionDistributionError):
    """Raised when an operator lifecycle artifact fails its closed V1 contract."""


class ExtensionDisableReceiptV1(BaseModel):
    """Metadata-only instruction to stop using one exact approval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-distribution-disable-v1.0"]
    disable_id: str = Field(pattern=SHA256_PATTERN)
    approval_id: str = Field(pattern=SHA256_PATTERN)
    inspection_id: str = Field(pattern=SHA256_PATTERN)
    distribution_name: str = Field(min_length=1, max_length=128)
    distribution_version: str = Field(min_length=1, max_length=64)
    extension_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    extension_version: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    operator_action_sha256: str = Field(pattern=SHA256_PATTERN)
    state: Literal["disabled_metadata_only"]
    reason_code: Literal["operator_disabled"]
    executable_state_changed: Literal[False]
    operator_authenticated: Literal[False]
    code_loaded: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _identity_matches(self) -> ExtensionDisableReceiptV1:
        if _receipt_identity("disable", self, "disable_id") != self.disable_id:
            raise ValueError("disable id does not bind the canonical receipt")
        return self


class ExtensionRollbackPlanV1(BaseModel):
    """Non-executable plan from one disabled approval to one approved target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-distribution-rollback-plan-v1.0"]
    rollback_plan_id: str = Field(pattern=SHA256_PATTERN)
    disable_id: str = Field(pattern=SHA256_PATTERN)
    current_approval_id: str = Field(pattern=SHA256_PATTERN)
    target_approval_id: str = Field(pattern=SHA256_PATTERN)
    distribution_name: str = Field(min_length=1, max_length=128)
    extension_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    from_distribution_version: str = Field(min_length=1, max_length=64)
    to_distribution_version: str = Field(min_length=1, max_length=64)
    from_extension_version: str = Field(min_length=1, max_length=64)
    to_extension_version: str = Field(min_length=1, max_length=64)
    current_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    target_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    target_implementation_sha256: str = Field(pattern=SHA256_PATTERN)
    target_configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    operator_action_sha256: str = Field(pattern=SHA256_PATTERN)
    state: Literal["rollback_planned_non_executable"]
    version_direction_verified: Literal[False]
    application_action_required: Literal["construct_and_bind_target_object"]
    executable_state_changed: Literal[False]
    automatic_import: Literal[False]
    automatic_download: Literal[False]
    code_loaded: Literal[False]
    operator_authenticated: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _identity_matches(self) -> ExtensionRollbackPlanV1:
        if self.current_approval_id == self.target_approval_id:
            raise ValueError("rollback target must differ from the disabled approval")
        if (
            _receipt_identity("rollback-plan", self, "rollback_plan_id")
            != self.rollback_plan_id
        ):
            raise ValueError("rollback plan id does not bind the canonical receipt")
        return self


class ExtensionLifecycleItemV1(BaseModel):
    """Safe state projection for one supplied approval receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=SHA256_PATTERN)
    inspection_id: str = Field(pattern=SHA256_PATTERN)
    distribution_name: str = Field(min_length=1, max_length=128)
    distribution_version: str = Field(min_length=1, max_length=64)
    extension_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    extension_version: str = Field(min_length=1, max_length=64)
    state: LifecycleState
    disable_id: str = Field(pattern=SHA256_PATTERN)
    rollback_plan_id: str = Field(pattern=SHA256_PATTERN)
    code_loaded: Literal[False]
    executable_state_observed: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _state_matches_sentinels(self) -> ExtensionLifecycleItemV1:
        disable_present = self.disable_id != ZERO_SHA256
        rollback_present = self.rollback_plan_id != ZERO_SHA256
        expected = {
            "approved_metadata_only": (False, False),
            "disabled_metadata_only": (True, False),
            "rollback_planned_non_executable": (True, True),
        }[self.state]
        if (disable_present, rollback_present) != expected:
            raise ValueError("lifecycle state and receipt sentinels disagree")
        return self


class ExtensionLifecycleProjectionV1(BaseModel):
    """Deterministic list assembled only from explicitly supplied canonical receipts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-extension-lifecycle-projection-v1.0"]
    projection_sha256: str = Field(pattern=SHA256_PATTERN)
    item_count: int = Field(ge=0, le=MAX_LIFECYCLE_RECEIPTS)
    items: tuple[ExtensionLifecycleItemV1, ...] = Field(max_length=MAX_LIFECYCLE_RECEIPTS)
    source: Literal["explicit_canonical_receipts_only"]
    installed_state_discovered: Literal[False]
    code_loaded: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _coherent(self) -> ExtensionLifecycleProjectionV1:
        if self.item_count != len(self.items):
            raise ValueError("lifecycle item count does not match items")
        ids = tuple(item.approval_id for item in self.items)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("lifecycle approvals must be unique and sorted")
        if _receipt_identity("projection", self, "projection_sha256") != self.projection_sha256:
            raise ValueError("lifecycle projection digest mismatch")
        return self


def disable_extension_approval_v1(
    approval: ExtensionDistributionApprovalV1,
    *,
    operator_action_id: str,
) -> ExtensionDisableReceiptV1:
    """Issue a no-code-load receipt; the embedding application must enforce it."""

    checked = _checked_approval(approval)
    action_sha256 = _operator_action_sha256(operator_action_id)
    provisional = ExtensionDisableReceiptV1.model_construct(
        schema_version=EXTENSION_DISABLE_V1,
        disable_id=ZERO_SHA256,
        approval_id=checked.approval_id,
        inspection_id=checked.inspection_id,
        distribution_name=checked.distribution_name,
        distribution_version=checked.distribution_version,
        extension_id=checked.extension_id,
        extension_version=checked.extension_version,
        manifest_sha256=checked.manifest_sha256,
        implementation_sha256=checked.implementation_sha256,
        configuration_sha256=checked.configuration_sha256,
        operator_action_sha256=action_sha256,
        state="disabled_metadata_only",
        reason_code="operator_disabled",
        executable_state_changed=False,
        operator_authenticated=False,
        code_loaded=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["disable_id"] = _receipt_identity("disable", provisional, "disable_id")
    return ExtensionDisableReceiptV1.model_validate(payload)


def plan_extension_rollback_v1(
    *,
    current_approval: ExtensionDistributionApprovalV1,
    disable_receipt: ExtensionDisableReceiptV1,
    target_approval: ExtensionDistributionApprovalV1,
    known_disable_receipts: Sequence[ExtensionDisableReceiptV1],
    operator_action_id: str,
) -> ExtensionRollbackPlanV1:
    """Bind a disabled current approval to an approved target without changing code state."""

    current = _checked_approval(current_approval)
    target = _checked_approval(target_approval)
    disabled = _checked_model(disable_receipt, ExtensionDisableReceiptV1, "disable")
    if not _disable_matches_approval(disabled, current):
        raise ExtensionLifecycleError("disable receipt does not match current approval")
    if (
        current.distribution_name != target.distribution_name
        or current.extension_id != target.extension_id
    ):
        raise ExtensionLifecycleError("rollback approvals refer to different extensions")
    if len(known_disable_receipts) > MAX_LIFECYCLE_RECEIPTS:
        raise ExtensionLifecycleError("too many known disable receipts")
    seen_disable_ids = {disabled.disable_id}
    for known_item in known_disable_receipts:
        known = _checked_model(known_item, ExtensionDisableReceiptV1, "known disable")
        if known.disable_id in seen_disable_ids:
            raise ExtensionLifecycleError("duplicate known disable receipt")
        seen_disable_ids.add(known.disable_id)
        if known.approval_id == target.approval_id:
            if not _disable_matches_approval(known, target):
                raise ExtensionLifecycleError("known disable conflicts with rollback target")
            raise ExtensionLifecycleError("rollback target approval is disabled")
    action_sha256 = _operator_action_sha256(operator_action_id)
    provisional = ExtensionRollbackPlanV1.model_construct(
        schema_version=EXTENSION_ROLLBACK_PLAN_V1,
        rollback_plan_id=ZERO_SHA256,
        disable_id=disabled.disable_id,
        current_approval_id=current.approval_id,
        target_approval_id=target.approval_id,
        distribution_name=current.distribution_name,
        extension_id=current.extension_id,
        from_distribution_version=current.distribution_version,
        to_distribution_version=target.distribution_version,
        from_extension_version=current.extension_version,
        to_extension_version=target.extension_version,
        current_manifest_sha256=current.manifest_sha256,
        target_manifest_sha256=target.manifest_sha256,
        target_implementation_sha256=target.implementation_sha256,
        target_configuration_sha256=target.configuration_sha256,
        operator_action_sha256=action_sha256,
        state="rollback_planned_non_executable",
        version_direction_verified=False,
        application_action_required="construct_and_bind_target_object",
        executable_state_changed=False,
        automatic_import=False,
        automatic_download=False,
        code_loaded=False,
        operator_authenticated=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["rollback_plan_id"] = _receipt_identity(
        "rollback-plan", provisional, "rollback_plan_id"
    )
    return ExtensionRollbackPlanV1.model_validate(payload)


def bind_active_operator_extension_v1(
    approval: ExtensionDistributionApprovalV1,
    extension: ExtensionV1,
    *,
    disable_receipts: Sequence[ExtensionDisableReceiptV1] = (),
) -> OperatorApprovedExtensionV1:
    """Bind an already constructed object only while its exact approval is not disabled."""

    checked = _checked_approval(approval)
    if len(disable_receipts) > MAX_LIFECYCLE_RECEIPTS:
        raise ExtensionLifecycleError("too many disable receipts")
    seen: set[str] = set()
    for item in disable_receipts:
        disabled = _checked_model(item, ExtensionDisableReceiptV1, "disable")
        if disabled.disable_id in seen:
            raise ExtensionLifecycleError("duplicate disable receipt")
        seen.add(disabled.disable_id)
        if disabled.approval_id == checked.approval_id:
            if not _disable_matches_approval(disabled, checked):
                raise ExtensionLifecycleError("disable receipt conflicts with approval")
            raise ExtensionLifecycleError("extension approval is disabled")
    return bind_operator_approved_extension_v1(checked, extension)


def project_extension_lifecycle_v1(
    *,
    approvals: Sequence[ExtensionDistributionApprovalV1],
    disable_receipts: Sequence[ExtensionDisableReceiptV1] = (),
    rollback_plans: Sequence[ExtensionRollbackPlanV1] = (),
) -> ExtensionLifecycleProjectionV1:
    """List state derived from supplied receipts; no environment discovery occurs."""

    receipt_groups = (approvals, disable_receipts, rollback_plans)
    if any(len(values) > MAX_LIFECYCLE_RECEIPTS for values in receipt_groups):
        raise ExtensionLifecycleError("too many lifecycle receipts")
    approval_by_id: dict[str, ExtensionDistributionApprovalV1] = {}
    for approval_item in approvals:
        approval = _checked_approval(approval_item)
        if approval.approval_id in approval_by_id:
            raise ExtensionLifecycleError("duplicate approval receipt")
        approval_by_id[approval.approval_id] = approval
    disable_by_approval: dict[str, ExtensionDisableReceiptV1] = {}
    for disable_item in disable_receipts:
        disabled = _checked_model(disable_item, ExtensionDisableReceiptV1, "disable")
        matched_approval = approval_by_id.get(disabled.approval_id)
        if matched_approval is None or not _disable_matches_approval(
            disabled, matched_approval
        ):
            raise ExtensionLifecycleError("disable receipt has no exact supplied approval")
        if disabled.approval_id in disable_by_approval:
            raise ExtensionLifecycleError("approval has multiple disable receipts")
        disable_by_approval[disabled.approval_id] = disabled
    plan_by_current: dict[str, ExtensionRollbackPlanV1] = {}
    for plan_item in rollback_plans:
        plan = _checked_model(plan_item, ExtensionRollbackPlanV1, "rollback plan")
        current = approval_by_id.get(plan.current_approval_id)
        target = approval_by_id.get(plan.target_approval_id)
        plan_disabled = disable_by_approval.get(plan.current_approval_id)
        if current is None or target is None or plan_disabled is None:
            raise ExtensionLifecycleError("rollback plan lacks its supplied receipt chain")
        if plan.target_approval_id in disable_by_approval:
            raise ExtensionLifecycleError("rollback target approval is disabled")
        if not _rollback_matches(plan, current, plan_disabled, target):
            raise ExtensionLifecycleError("rollback plan conflicts with supplied receipt chain")
        if plan.current_approval_id in plan_by_current:
            raise ExtensionLifecycleError("disabled approval has multiple rollback plans")
        plan_by_current[plan.current_approval_id] = plan
    _reject_rollback_cycles(plan_by_current)
    items: list[ExtensionLifecycleItemV1] = []
    for approval_id, approval in sorted(approval_by_id.items()):
        item_disabled = disable_by_approval.get(approval_id)
        item_plan = plan_by_current.get(approval_id)
        state: LifecycleState = "approved_metadata_only"
        if item_disabled is not None:
            state = "disabled_metadata_only"
        if item_plan is not None:
            state = "rollback_planned_non_executable"
        items.append(
            ExtensionLifecycleItemV1(
                approval_id=approval_id,
                inspection_id=approval.inspection_id,
                distribution_name=approval.distribution_name,
                distribution_version=approval.distribution_version,
                extension_id=approval.extension_id,
                extension_version=approval.extension_version,
                state=state,
                disable_id=item_disabled.disable_id if item_disabled else ZERO_SHA256,
                rollback_plan_id=item_plan.rollback_plan_id if item_plan else ZERO_SHA256,
                code_loaded=False,
                executable_state_observed=False,
                operational_authority="none",
            )
        )
    provisional = ExtensionLifecycleProjectionV1.model_construct(
        schema_version=EXTENSION_LIFECYCLE_PROJECTION_V1,
        projection_sha256=ZERO_SHA256,
        item_count=len(items),
        items=tuple(items),
        source="explicit_canonical_receipts_only",
        installed_state_discovered=False,
        code_loaded=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["projection_sha256"] = _receipt_identity(
        "projection", provisional, "projection_sha256"
    )
    return ExtensionLifecycleProjectionV1.model_validate(payload)


def encode_extension_disable_receipt_v1(receipt: ExtensionDisableReceiptV1) -> bytes:
    return _encode_checked(receipt, ExtensionDisableReceiptV1, "disable")


def decode_extension_disable_receipt_v1(payload: bytes) -> ExtensionDisableReceiptV1:
    return cast(
        ExtensionDisableReceiptV1,
        _decode_lifecycle_receipt(payload, ExtensionDisableReceiptV1, "disable"),
    )


def encode_extension_rollback_plan_v1(plan: ExtensionRollbackPlanV1) -> bytes:
    return _encode_checked(plan, ExtensionRollbackPlanV1, "rollback plan")


def decode_extension_rollback_plan_v1(payload: bytes) -> ExtensionRollbackPlanV1:
    return cast(
        ExtensionRollbackPlanV1,
        _decode_lifecycle_receipt(payload, ExtensionRollbackPlanV1, "rollback plan"),
    )


def encode_extension_lifecycle_projection_v1(
    projection: ExtensionLifecycleProjectionV1,
) -> bytes:
    return _encode_checked(projection, ExtensionLifecycleProjectionV1, "projection")


def decode_extension_lifecycle_projection_v1(payload: bytes) -> ExtensionLifecycleProjectionV1:
    return cast(
        ExtensionLifecycleProjectionV1,
        _decode_lifecycle_receipt(payload, ExtensionLifecycleProjectionV1, "projection"),
    )


def extension_lifecycle_v1_json_schemas() -> dict[str, dict[str, Any]]:
    return {
        "extension-disable-receipt.v1.schema.json": ExtensionDisableReceiptV1.model_json_schema(),
        "extension-rollback-plan.v1.schema.json": ExtensionRollbackPlanV1.model_json_schema(),
        "extension-lifecycle-projection.v1.schema.json": (
            ExtensionLifecycleProjectionV1.model_json_schema()
        ),
    }


def read_extension_inspection_file_v1(
    path: Path, *, expected_sha256: str
) -> ExtensionDistributionInspectionV1:
    return decode_extension_distribution_inspection_v1(
        _read_operator_file(path, "inspection", expected_sha256=expected_sha256)
    )


def read_extension_approval_file_v1(
    path: Path, *, expected_sha256: str
) -> ExtensionDistributionApprovalV1:
    return decode_extension_distribution_approval_v1(
        _read_operator_file(path, "approval", expected_sha256=expected_sha256)
    )


def read_extension_disable_file_v1(
    path: Path, *, expected_sha256: str
) -> ExtensionDisableReceiptV1:
    return decode_extension_disable_receipt_v1(
        _read_operator_file(path, "disable", expected_sha256=expected_sha256)
    )


def read_extension_rollback_plan_file_v1(
    path: Path, *, expected_sha256: str
) -> ExtensionRollbackPlanV1:
    return decode_extension_rollback_plan_v1(
        _read_operator_file(path, "rollback plan", expected_sha256=expected_sha256)
    )


def read_extension_configuration_file_v1(path: Path, *, expected_sha256: str) -> bytes:
    return _read_operator_file(path, "configuration", expected_sha256=expected_sha256)


def _checked_approval(value: ExtensionDistributionApprovalV1) -> ExtensionDistributionApprovalV1:
    try:
        return decode_extension_distribution_approval_v1(
            # The source codec performs semantic validation and canonicalization.
            json.dumps(
                value.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (AttributeError, ExtensionDistributionError, TypeError, ValueError) as exc:
        raise ExtensionLifecycleError("approval receipt violates V1") from exc


def _checked_model(value: Any, model: type[ModelT], label: str) -> ModelT:
    try:
        return model.model_validate(value.model_dump(mode="python"))
    except (AttributeError, ValueError) as exc:
        raise ExtensionLifecycleError(f"{label} receipt violates V1") from exc


def _disable_matches_approval(
    disabled: ExtensionDisableReceiptV1, approval: ExtensionDistributionApprovalV1
) -> bool:
    return (
        disabled.approval_id == approval.approval_id
        and disabled.inspection_id == approval.inspection_id
        and disabled.distribution_name == approval.distribution_name
        and disabled.distribution_version == approval.distribution_version
        and disabled.extension_id == approval.extension_id
        and disabled.extension_version == approval.extension_version
        and disabled.manifest_sha256 == approval.manifest_sha256
        and disabled.implementation_sha256 == approval.implementation_sha256
        and disabled.configuration_sha256 == approval.configuration_sha256
    )


def _rollback_matches(
    plan: ExtensionRollbackPlanV1,
    current: ExtensionDistributionApprovalV1,
    disabled: ExtensionDisableReceiptV1,
    target: ExtensionDistributionApprovalV1,
) -> bool:
    return (
        _disable_matches_approval(disabled, current)
        and plan.disable_id == disabled.disable_id
        and plan.current_approval_id == current.approval_id
        and plan.target_approval_id == target.approval_id
        and plan.distribution_name == current.distribution_name == target.distribution_name
        and plan.extension_id == current.extension_id == target.extension_id
        and plan.from_distribution_version == current.distribution_version
        and plan.to_distribution_version == target.distribution_version
        and plan.from_extension_version == current.extension_version
        and plan.to_extension_version == target.extension_version
        and plan.current_manifest_sha256 == current.manifest_sha256
        and plan.target_manifest_sha256 == target.manifest_sha256
        and plan.target_implementation_sha256 == target.implementation_sha256
        and plan.target_configuration_sha256 == target.configuration_sha256
    )


def _reject_rollback_cycles(plans: dict[str, ExtensionRollbackPlanV1]) -> None:
    for start in plans:
        visited: set[str] = set()
        current = start
        while current in plans:
            if current in visited:
                raise ExtensionLifecycleError("rollback plans contain a cycle")
            visited.add(current)
            current = plans[current].target_approval_id


def _operator_action_sha256(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExtensionLifecycleError("operator action id must be non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ExtensionLifecycleError("operator action id must be valid UTF-8") from exc
    if len(encoded) > MAX_OPERATOR_ACTION_BYTES or b"\0" in encoded:
        raise ExtensionLifecycleError("operator action id is outside V1")
    return hashlib.sha256(b"ash-extension-operator-action-v1\0" + encoded).hexdigest()


def _receipt_identity(domain: str, value: BaseModel, identity_field: str) -> str:
    payload = value.model_dump(mode="json", exclude={identity_field})
    return hashlib.sha256(
        f"agentic-security-harness/extension-lifecycle-{domain}/v1.0".encode("ascii")
        + b"\0"
        + _canonical_bytes(payload)
    ).hexdigest()


def _encode_checked(value: Any, model: type[BaseModel], label: str) -> bytes:
    checked = _checked_model(value, model, label)
    return _canonical_bytes(checked.model_dump(mode="json"))


def _canonical_bytes(payload: Any) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ExtensionLifecycleError("lifecycle value is not canonical JSON") from exc
    if len(encoded) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionLifecycleError("lifecycle receipt exceeds V1")
    return encoded


def _decode_lifecycle_receipt(payload: bytes, model: type[BaseModel], label: str) -> BaseModel:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionLifecycleError(f"{label} receipt size is outside V1")
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
    except ExtensionLifecycleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ExtensionLifecycleError(f"{label} receipt is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != set(model.model_fields):
        raise ExtensionLifecycleError(f"{label} receipt fields do not match V1")
    try:
        checked = model.model_validate(value)
    except ValueError as exc:
        raise ExtensionLifecycleError(f"{label} receipt values violate V1") from exc
    if _canonical_bytes(checked.model_dump(mode="json")) != payload:
        raise ExtensionLifecycleError(f"{label} receipt is not canonical V1 JSON")
    return checked


def _read_operator_file(path: Path, label: str, *, expected_sha256: str) -> bytes:
    if not isinstance(path, Path):
        raise ExtensionLifecycleError(f"{label} path must be a Path")
    if (
        not isinstance(expected_sha256, str)
        or re.fullmatch(SHA256_PATTERN, expected_sha256) is None
    ):
        raise ExtensionLifecycleError(f"{label} expected SHA-256 is invalid")
    candidate = path.resolve(strict=False)
    for component in (path, *path.parents):
        if is_link_or_reparse(component):
            raise ExtensionLifecycleError(f"{label} path traverses a link or reparse point")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor: int | None = None
    try:
        before = candidate.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ExtensionLifecycleError(f"{label} must be a regular single-link file")
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise ExtensionLifecycleError(f"{label} file changed before read")
        first = _read_descriptor(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_descriptor(descriptor)
        after = os.fstat(descriptor)
        if first != second or _file_identity(opened) != _file_identity(after):
            raise ExtensionLifecycleError(f"{label} file changed while read")
        path_after = candidate.lstat()
        if _file_identity(before) != _file_identity(path_after):
            raise ExtensionLifecycleError(f"{label} path changed while read")
        for component in (path, *path.parents):
            if is_link_or_reparse(component):
                raise ExtensionLifecycleError(f"{label} path changed to a link or reparse point")
        if hashlib.sha256(first).hexdigest() != expected_sha256:
            raise ExtensionLifecycleError(f"{label} file does not match expected SHA-256")
    except ExtensionLifecycleError:
        raise
    except OSError as exc:
        raise ExtensionLifecycleError(f"{label} file is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return first


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_EXTENSION_PAYLOAD_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > MAX_EXTENSION_PAYLOAD_BYTES:
        raise ExtensionLifecycleError("operator file exceeds V1")
    return payload


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


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
            if depth > MAX_LIFECYCLE_JSON_DEPTH:
                raise ExtensionLifecycleError("lifecycle JSON nesting exceeds V1")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ExtensionLifecycleError("lifecycle JSON nesting is invalid")


def _bounded_json_integer(token: str) -> int:
    if len(token.removeprefix("-")) > MAX_LIFECYCLE_INTEGER_DIGITS:
        raise ExtensionLifecycleError("lifecycle JSON integer exceeds V1")
    return int(token)


def _reject_json_float(_token: str) -> float:
    raise ExtensionLifecycleError("lifecycle JSON floats are forbidden")


def _reject_json_constant(_token: str) -> None:
    raise ExtensionLifecycleError("lifecycle JSON constants are forbidden")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ExtensionLifecycleError("duplicate lifecycle JSON field")
        value[key] = item
    return value


__all__ = [
    "ExtensionDisableReceiptV1",
    "ExtensionLifecycleError",
    "ExtensionLifecycleItemV1",
    "ExtensionLifecycleProjectionV1",
    "ExtensionRollbackPlanV1",
    "bind_active_operator_extension_v1",
    "decode_extension_disable_receipt_v1",
    "decode_extension_lifecycle_projection_v1",
    "decode_extension_rollback_plan_v1",
    "disable_extension_approval_v1",
    "encode_extension_disable_receipt_v1",
    "encode_extension_lifecycle_projection_v1",
    "encode_extension_rollback_plan_v1",
    "extension_lifecycle_v1_json_schemas",
    "plan_extension_rollback_v1",
    "project_extension_lifecycle_v1",
    "read_extension_approval_file_v1",
    "read_extension_configuration_file_v1",
    "read_extension_disable_file_v1",
    "read_extension_inspection_file_v1",
    "read_extension_rollback_plan_file_v1",
]
