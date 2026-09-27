"""Pure, opt-in normalization of one declared garak-style JSON tool plan.

The caller owns tool aliases, capability bindings, profile identity, and request
identity. Normalization grants no Quarantine admission or Gateway authority.
This module imports no garak code and performs no transport or dispatch.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.runtime_gateway import SAFE_TOKEN_PATTERN, SHA256_PATTERN

MAX_GARAK_PLAN_BYTES = 16_384
MAX_GARAK_PLAN_DEPTH = 8
MAX_GARAK_TOOL_BINDINGS = 32

GarakPlanReason = Literal[
    "normalized_request",
    "normalized_no_request",
    "input_type_invalid",
    "input_empty",
    "input_oversized",
    "malformed_utf8",
    "malformed_json",
    "duplicate_json_key",
    "nonfinite_number",
    "numeric_value_loss",
    "depth_exceeded",
    "invalid_unicode",
    "root_shape_invalid",
    "call_count_invalid",
    "call_shape_invalid",
    "tool_alias_unknown",
]


class GarakPlanAdapterError(ValueError):
    """Caller configuration error, never an untrusted plan diagnostic."""


class GarakToolBindingV1(BaseModel):
    """Caller-owned exact alias to an existing Quarantine capability identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tool_name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    capability_id: str = Field(pattern=SAFE_TOKEN_PATTERN)


class GarakPlanAdapterConfigV1(BaseModel):
    """Closed plan vocabulary; bindings are sorted by alias and unique."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    bindings: tuple[GarakToolBindingV1, ...] = Field(
        min_length=1, max_length=MAX_GARAK_TOOL_BINDINGS
    )

    @model_validator(mode="after")
    def _closed_bindings(self) -> GarakPlanAdapterConfigV1:
        aliases = [binding.tool_name for binding in self.bindings]
        capabilities = [binding.capability_id for binding in self.bindings]
        if aliases != sorted(set(aliases)) or len(capabilities) != len(set(capabilities)):
            raise ValueError("bindings must be sorted and one-to-one")
        return self


class GarakPlanAdapterOutcomeV1(BaseModel):
    """Content-free local observation, with no admission or execution claim."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["AgenticSecurityHarnessGarakPlanAdapterOutcome.v1"] = (
        "AgenticSecurityHarnessGarakPlanAdapterOutcome.v1"
    )
    reason_code: GarakPlanReason
    input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    envelope_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    operational_authority: Literal["none"] = "none"
    dispatch_performed: Literal[False] = False

    @model_validator(mode="after")
    def _coherent(self) -> GarakPlanAdapterOutcomeV1:
        normalized = self.reason_code in {"normalized_request", "normalized_no_request"}
        if normalized != (self.envelope_sha256 is not None):
            raise ValueError("only a normalized plan may have an envelope commitment")
        if normalized and self.input_sha256 is None:
            raise ValueError("normalized plan requires an input commitment")
        return self


@dataclass(frozen=True, slots=True)
class GarakPlanNormalizationV1:
    """Candidate envelope bytes plus a content-free normalization outcome."""

    envelope: bytes | None
    outcome: GarakPlanAdapterOutcomeV1

    def __post_init__(self) -> None:
        if (self.envelope is None) != (self.outcome.envelope_sha256 is None):
            raise ValueError("envelope and outcome commitment must agree")
        if self.envelope is not None and (
            type(self.envelope) is not bytes
            or hashlib.sha256(self.envelope).hexdigest() != self.outcome.envelope_sha256
        ):
            raise ValueError("envelope bytes do not match the outcome commitment")


class _Rejected(ValueError):
    def __init__(self, reason_code: GarakPlanReason) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Rejected("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise _Rejected("nonfinite_number")


def _exact_json_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise _Rejected("nonfinite_number")
    try:
        preserved = Decimal(token) == Decimal(str(value))
    except InvalidOperation:
        preserved = False
    if not preserved:
        raise _Rejected("numeric_value_loss")
    return value


def _check_depth(payload: bytes) -> None:
    """Bound container nesting before json.loads creates recursive structures."""

    depth = 0
    quoted = False
    escaped = False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_GARAK_PLAN_DEPTH:
                raise _Rejected("depth_exceeded")
        elif byte in (93, 125):
            depth -= 1


def _check_scalars(value: Any) -> None:
    """Reject JSON values that cannot be preserved as finite UTF-8 canonical JSON."""

    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise _Rejected("invalid_unicode") from exc
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise _Rejected("nonfinite_number")
    elif type(value) is dict:
        for key, item in value.items():
            _check_scalars(key)
            _check_scalars(item)
    elif type(value) is list:
        for item in value:
            _check_scalars(item)


def _decode(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Rejected("malformed_utf8") from exc
    _check_depth(payload)
    try:
        value = json.loads(text, object_pairs_hook=_unique, parse_constant=_reject_constant,
                           parse_float=_exact_json_float)
    except _Rejected:
        raise
    except (ValueError, RecursionError) as exc:
        raise _Rejected("malformed_json") from exc
    _check_scalars(value)
    if type(value) is not dict or set(value) != {"tool_calls"}:
        raise _Rejected("root_shape_invalid")
    return value


def _result(
    reason_code: GarakPlanReason,
    *,
    input_sha256: str | None,
    envelope: bytes | None = None,
) -> GarakPlanNormalizationV1:
    return GarakPlanNormalizationV1(
        envelope=envelope,
        outcome=GarakPlanAdapterOutcomeV1(
            reason_code=reason_code,
            input_sha256=input_sha256,
            envelope_sha256=hashlib.sha256(envelope).hexdigest() if envelope is not None else None,
        ),
    )


def normalize_garak_plan_v1(
    payload: bytes, *, config: GarakPlanAdapterConfigV1, request_id: str
) -> GarakPlanNormalizationV1:
    """Normalize zero or one exact plan call into an untrusted Harness envelope.

    Untrusted bytes return typed rejections. The application must submit any
    resulting envelope to Quarantine before asking the Gateway for a decision.
    """

    if type(config) is not GarakPlanAdapterConfigV1:
        raise GarakPlanAdapterError("exact adapter config type required")
    try:
        GarakPlanAdapterConfigV1.model_validate(config.model_dump(mode="python"))
    except ValueError:
        raise GarakPlanAdapterError("invalid adapter config") from None
    if type(request_id) is not str or re.fullmatch(SAFE_TOKEN_PATTERN, request_id) is None:
        raise GarakPlanAdapterError("invalid application request identity")
    if type(payload) is not bytes:
        return _result("input_type_invalid", input_sha256=None)
    if not payload:
        return _result("input_empty", input_sha256=hashlib.sha256(payload).hexdigest())
    if len(payload) > MAX_GARAK_PLAN_BYTES:
        return _result("input_oversized", input_sha256=None)
    input_sha256 = hashlib.sha256(payload).hexdigest()
    try:
        plan = _decode(payload)
        calls = plan["tool_calls"]
        if type(calls) is not list:
            raise _Rejected("root_shape_invalid")
        if len(calls) > 1:
            raise _Rejected("call_count_invalid")
        if not calls:
            representation: dict[str, Any] = {"kind": "no_request"}
            reason: GarakPlanReason = "normalized_no_request"
        else:
            call = calls[0]
            if (
                type(call) is not dict
                or set(call) != {"tool", "args"}
                or type(call["tool"]) is not str
                or type(call["args"]) is not dict
            ):
                raise _Rejected("call_shape_invalid")
            binding = next(
                (item for item in config.bindings if item.tool_name == call["tool"]), None
            )
            if binding is None:
                raise _Rejected("tool_alias_unknown")
            representation = {
                "kind": "capability_request",
                "request_id": request_id,
                "capability_id": binding.capability_id,
                "arguments": call["args"],
            }
            reason = "normalized_request"
        envelope = _canonical(
            {
                "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
                "profile_id": config.profile_id,
                "profile_version": config.profile_version,
                "representation": representation,
            }
        )
    except _Rejected as exc:
        return _result(exc.reason_code, input_sha256=input_sha256)
    return _result(reason, input_sha256=input_sha256, envelope=envelope)


__all__ = [
    "GarakPlanAdapterConfigV1",
    "GarakPlanAdapterError",
    "GarakPlanAdapterOutcomeV1",
    "GarakPlanNormalizationV1",
    "GarakToolBindingV1",
    "MAX_GARAK_PLAN_BYTES",
    "normalize_garak_plan_v1",
]
