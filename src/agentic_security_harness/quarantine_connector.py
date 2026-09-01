"""Model-independent, non-executing admission contract before the Runtime Gateway.

The connector accepts only bounded canonical JSON bytes under one explicitly selected,
application-owned profile. It performs no discovery, transport, provider/model call,
policy evaluation, tool execution, dispatch, persistence, or activation. An admitted
capability request can be converted into the existing untrusted ``GatewayToolCallV1``;
the Runtime Gateway remains the only policy and action decision point.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayProtocol,
    GatewayToolCallV1,
)

QUARANTINE_CONNECTOR_API_VERSION = "AgenticSecurityHarnessQuarantineConnector.v1"
MAX_QUARANTINE_INPUT_BYTES = 65_536
MAX_QUARANTINE_ARGUMENT_BYTES = 16_384
MAX_QUARANTINE_PROFILES = 64
MAX_QUARANTINE_CAPABILITIES = 32

QuarantineDisposition = Literal["admit", "reject", "inconclusive"]
QuarantineRepresentationKind = Literal["no_request", "capability_request"]
QuarantineContextMode = Literal["forbidden", "required"]

_WIRE_SCHEMA_VERSION: Literal["AgenticSecurityHarnessModelEnvelope.v1"] = (
    "AgenticSecurityHarnessModelEnvelope.v1"
)
_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "allow",
        "approval",
        "approval_id",
        "authority",
        "capabilities",
        "capability",
        "capability_token",
        "effect",
        "endpoint",
        "executor",
        "policy",
        "policy_id",
        "permission",
        "permissions",
        "principal",
        "role",
        "route",
        "token",
        "tool",
        "tool_definition",
        "tool_name",
        "tools",
    }
)
_SEMANTIC_CONTEXT_KEYS = frozenset(
    {"context", "history", "messages", "session", "state", "transport_context"}
)
_NORMALIZED_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    "".join(character for character in key.casefold() if character.isalnum())
    for key in _FORBIDDEN_AUTHORITY_KEYS
)


class QuarantineConnectorError(ValueError):
    """Raised for caller/configuration misuse, never for rejected untrusted bytes."""


class QuarantineCapabilityBindingV1(BaseModel):
    """Application-owned mapping from one capability id to an existing Gateway call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessQuarantineCapabilityBinding.v1"] = (
        "AgenticSecurityHarnessQuarantineCapabilityBinding.v1"
    )
    capability_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    gateway_protocol: GatewayProtocol
    gateway_tool_name: str = Field(pattern=SAFE_TOKEN_PATTERN)
    allowed_argument_keys: tuple[str, ...] = ()
    required_argument_keys: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _closed_argument_keys(self) -> QuarantineCapabilityBindingV1:
        allowed = self.allowed_argument_keys
        required = self.required_argument_keys
        if allowed != tuple(sorted(set(allowed))):
            raise ValueError("allowed argument keys must be sorted and unique")
        if required != tuple(sorted(set(required))):
            raise ValueError("required argument keys must be sorted and unique")
        if not set(required) <= set(allowed):
            raise ValueError("required argument keys must be allowed")
        if any(not _is_safe_token(key) for key in allowed):
            raise ValueError("argument keys must be safe tokens")
        return self


class ProviderAdapterProfileV1(BaseModel):
    """One immutable, explicitly selected canonical representation profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessProviderAdapterProfile.v1"] = (
        "AgenticSecurityHarnessProviderAdapterProfile.v1"
    )
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    representation: Literal["canonical_json"] = "canonical_json"
    context_mode: QuarantineContextMode = "forbidden"
    max_input_bytes: int = Field(default=16_384, ge=128, le=MAX_QUARANTINE_INPUT_BYTES)
    max_depth: int = Field(default=8, ge=1, le=12)
    max_string_bytes: int = Field(default=4_096, ge=1, le=16_384)
    max_collection_items: int = Field(default=64, ge=1, le=256)
    max_object_fields: int = Field(default=32, ge=1, le=256)
    capabilities: tuple[QuarantineCapabilityBindingV1, ...] = Field(
        default=(), max_length=MAX_QUARANTINE_CAPABILITIES
    )

    @model_validator(mode="after")
    def _closed_capabilities(self) -> ProviderAdapterProfileV1:
        identities = [item.capability_id for item in self.capabilities]
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise ValueError("profile capabilities must be sorted and unique")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-quarantine-profile-v1", self.model_dump(mode="json"))

    def capability(self, capability_id: str) -> QuarantineCapabilityBindingV1 | None:
        return next(
            (item for item in self.capabilities if item.capability_id == capability_id),
            None,
        )


class ProviderAdapterProfileRegistryV1(BaseModel):
    """Closed explicit registry; exact lookup has no discovery, fallback, or upgrade."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessProviderAdapterProfileRegistry.v1"] = (
        "AgenticSecurityHarnessProviderAdapterProfileRegistry.v1"
    )
    profiles: tuple[ProviderAdapterProfileV1, ...] = Field(
        min_length=1, max_length=MAX_QUARANTINE_PROFILES
    )

    @model_validator(mode="after")
    def _closed_profiles(self) -> ProviderAdapterProfileRegistryV1:
        identities = [(item.profile_id, item.profile_version) for item in self.profiles]
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise ValueError("registry profiles must be sorted and unique")
        return self

    def select_exact(
        self, profile_id: str, profile_version: str
    ) -> ProviderAdapterProfileV1 | None:
        return next(
            (
                item
                for item in self.profiles
                if item.profile_id == profile_id and item.profile_version == profile_version
            ),
            None,
        )

    def sha256(self) -> str:
        return _domain_sha256("ash-quarantine-profile-registry-v1", self.model_dump(mode="json"))


class QuarantineContextBindingV1(BaseModel):
    """Opaque digest-only profile/session/endpoint binding for explicit stateful profiles."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessQuarantineContextBinding.v1"] = (
        "AgenticSecurityHarnessQuarantineContextBinding.v1"
    )
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    session_sha256: str = Field(pattern=SHA256_PATTERN)
    endpoint_sha256: str = Field(pattern=SHA256_PATTERN)


class CapabilityRequestV1(BaseModel):
    """Admitted request without allow, policy, role, token, route, or executor authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessCapabilityRequest.v1"] = (
        "AgenticSecurityHarnessCapabilityRequest.v1"
    )
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    request_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    capability_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    arguments: dict[str, Any] = Field(default_factory=dict, repr=False)

    @model_validator(mode="after")
    def _bounded_arguments(self) -> CapabilityRequestV1:
        _validate_json_value(
            self.arguments,
            depth=0,
            max_depth=12,
            max_string_bytes=16_384,
            max_collection_items=256,
            max_object_fields=256,
        )
        if len(_canonical_json_bytes(self.arguments)) > MAX_QUARANTINE_ARGUMENT_BYTES:
            raise ValueError("capability arguments exceed the connector limit")
        return self

    def arguments_sha256(self) -> str:
        return _domain_sha256("ash-quarantine-capability-arguments-v1", self.arguments)

    def sha256(self) -> str:
        return _domain_sha256("ash-quarantine-capability-request-v1", self.model_dump(mode="json"))


class ModelEnvelopeV1(BaseModel):
    """Admitted typed projection; raw input bytes are represented only by a digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessModelEnvelope.v1"] = _WIRE_SCHEMA_VERSION
    profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    representation_kind: QuarantineRepresentationKind
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    profile_sha256: str = Field(pattern=SHA256_PATTERN)
    context_binding: QuarantineContextBindingV1 | None = None
    capability_request: CapabilityRequestV1 | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def _coherent_representation(self) -> ModelEnvelopeV1:
        request = self.capability_request
        if self.representation_kind == "no_request" and request is not None:
            raise ValueError("no-request envelope cannot contain a capability request")
        if self.representation_kind == "capability_request" and request is None:
            raise ValueError("capability-request envelope requires a request")
        if request is not None and (
            request.profile_id != self.profile_id or request.profile_version != self.profile_version
        ):
            raise ValueError("capability request profile identity drifted")
        if self.context_binding is not None and (
            self.context_binding.profile_id != self.profile_id
            or self.context_binding.profile_version != self.profile_version
        ):
            raise ValueError("context binding profile identity drifted")
        return self

    def canonical_input_bytes(self) -> bytes:
        representation: dict[str, Any] = {"kind": self.representation_kind}
        if self.capability_request is not None:
            representation.update(
                {
                    "arguments": self.capability_request.arguments,
                    "capability_id": self.capability_request.capability_id,
                    "request_id": self.capability_request.request_id,
                }
            )
        value: dict[str, Any] = {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "representation": representation,
            "schema_version": self.schema_version,
        }
        if self.context_binding is not None:
            value["context_binding"] = self.context_binding.model_dump(mode="json")
        return _canonical_json_bytes(value)

    def sha256(self) -> str:
        return _domain_sha256("ash-quarantine-model-envelope-v1", self.model_dump(mode="json"))


class QuarantineVerdictV1(BaseModel):
    """Closed admission result. Admission is never an action or policy decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessQuarantineVerdict.v1"] = (
        "AgenticSecurityHarnessQuarantineVerdict.v1"
    )
    disposition: QuarantineDisposition
    reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    profile_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    envelope: ModelEnvelopeV1 | None = Field(default=None, repr=False)
    capability_request: CapabilityRequestV1 | None = Field(default=None, repr=False)
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _coherent_verdict(self) -> QuarantineVerdictV1:
        if self.disposition != "admit":
            if self.envelope is not None or self.capability_request is not None:
                raise ValueError("non-admit verdict cannot retain admitted objects")
            return self
        if self.envelope is None or self.profile_sha256 is None or self.input_sha256 is None:
            raise ValueError("admit verdict requires profile, input, and envelope commitments")
        if (
            self.envelope.profile_id != self.selected_profile_id
            or self.envelope.profile_version != self.selected_profile_version
            or self.envelope.profile_sha256 != self.profile_sha256
            or self.envelope.input_sha256 != self.input_sha256
            or self.envelope.capability_request != self.capability_request
        ):
            raise ValueError("admit verdict commitments drifted")
        return self

    def sha256(self) -> str:
        return _domain_sha256("ash-quarantine-verdict-v1", self.model_dump(mode="json"))


class QuarantineGatewayBridgeV1(BaseModel):
    """Additive in-memory sidecar linkage; constructing it never calls the Gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessQuarantineGatewayBridge.v1"] = (
        "AgenticSecurityHarnessQuarantineGatewayBridge.v1"
    )
    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    capability_request_sha256: str = Field(pattern=SHA256_PATTERN)
    profile_sha256: str = Field(pattern=SHA256_PATTERN)
    gateway_call: GatewayToolCallV1 = Field(repr=False)
    operational_authority: Literal["none"] = "none"

    def sha256(self) -> str:
        return _domain_sha256("ash-quarantine-gateway-bridge-v1", self.model_dump(mode="json"))


def evaluate_quarantine_input_v1(
    registry: ProviderAdapterProfileRegistryV1,
    *,
    selected_profile_id: str,
    selected_profile_version: str,
    payload: bytes,
) -> QuarantineVerdictV1:
    """Decode one exact profile representation without fallback or side effects."""

    if type(registry) is not ProviderAdapterProfileRegistryV1:
        raise QuarantineConnectorError("registry must be the exact V1 type")
    if not _is_safe_token(selected_profile_id) or not _is_safe_token(selected_profile_version):
        raise QuarantineConnectorError("selected profile identity must use safe tokens")
    profile = registry.select_exact(selected_profile_id, selected_profile_version)
    if profile is None:
        return _verdict(
            disposition="inconclusive",
            reason_code="profile_not_registered",
            profile_id=selected_profile_id,
            profile_version=selected_profile_version,
            input_sha256=_bounded_input_sha256(payload),
        )
    profile_sha256 = profile.sha256()
    if type(payload) is not bytes:
        return _reject(profile, "input_type_invalid")
    if not payload:
        return _reject(profile, "input_empty")
    if len(payload) > profile.max_input_bytes:
        return _reject(profile, "input_oversized")
    input_sha256 = _domain_sha256_bytes("ash-quarantine-input-v1", payload)
    try:
        root = _decode_canonical_root(payload, profile)
        envelope = _normalize_envelope(root, profile, input_sha256)
    except _InputViolation as exc:
        return _reject(profile, exc.reason_code, input_sha256=input_sha256)
    request = envelope.capability_request
    return _verdict(
        disposition="admit",
        reason_code=(
            "admitted_capability_request" if request is not None else "admitted_no_request"
        ),
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        input_sha256=input_sha256,
        profile_sha256=profile_sha256,
        envelope=envelope,
        capability_request=request,
    )


def bridge_quarantine_admission_v1(
    verdict: QuarantineVerdictV1,
    registry: ProviderAdapterProfileRegistryV1,
) -> QuarantineGatewayBridgeV1 | None:
    """Construct an untrusted Gateway call only from an admitted capability request."""

    if type(verdict) is not QuarantineVerdictV1:
        raise QuarantineConnectorError("verdict must be the exact V1 type")
    if type(registry) is not ProviderAdapterProfileRegistryV1:
        raise QuarantineConnectorError("registry must be the exact V1 type")
    if verdict.disposition != "admit" or verdict.envelope is None:
        raise QuarantineConnectorError("only an admit verdict may reach the bridge")
    request = verdict.capability_request
    if request is None:
        return None
    profile = registry.select_exact(verdict.selected_profile_id, verdict.selected_profile_version)
    if profile is None or profile.sha256() != verdict.profile_sha256:
        raise QuarantineConnectorError("selected profile registry commitment drifted")
    binding = profile.capability(request.capability_id)
    if binding is None:
        raise QuarantineConnectorError("admitted capability binding drifted")
    call = GatewayToolCallV1(
        call_id=f"quarantine:{request.sha256()}",
        protocol=binding.gateway_protocol,
        tool_name=binding.gateway_tool_name,
        arguments=request.arguments,
    )
    return QuarantineGatewayBridgeV1(
        envelope_sha256=verdict.envelope.sha256(),
        capability_request_sha256=request.sha256(),
        profile_sha256=profile.sha256(),
        gateway_call=call,
    )


def quarantine_connector_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return deterministic public schemas for the source-level V1 contract."""

    models: tuple[type[BaseModel], ...] = (
        QuarantineCapabilityBindingV1,
        ProviderAdapterProfileV1,
        ProviderAdapterProfileRegistryV1,
        QuarantineContextBindingV1,
        CapabilityRequestV1,
        ModelEnvelopeV1,
        QuarantineVerdictV1,
        QuarantineGatewayBridgeV1,
    )
    return {model.__name__: model.model_json_schema() for model in models}


def quarantine_connector_v1_api_sha256() -> str:
    """Digest the API version, schemas, and non-executing entry points for Lab handoff."""

    return _domain_sha256(
        "ash-quarantine-connector-api-v1",
        {
            "api_version": QUARANTINE_CONNECTOR_API_VERSION,
            "entry_points": [
                "bridge_quarantine_admission_v1",
                "evaluate_quarantine_input_v1",
            ],
            "schemas": quarantine_connector_v1_json_schemas(),
        },
    )


def _decode_canonical_root(payload: bytes, profile: ProviderAdapterProfileV1) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _InputViolation("malformed_utf8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_bounded_int,
            parse_float=_bounded_float,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey as exc:
        raise _InputViolation("duplicate_json_key") from exc
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _InputViolation("malformed_json") from exc
    if type(value) is not dict:
        raise _InputViolation("root_type_invalid")
    try:
        _validate_json_value(
            value,
            depth=0,
            max_depth=profile.max_depth,
            max_string_bytes=profile.max_string_bytes,
            max_collection_items=profile.max_collection_items,
            max_object_fields=profile.max_object_fields,
        )
    except QuarantineConnectorError as exc:
        raise _InputViolation("profile_bounds_exceeded") from exc
    if _canonical_json_bytes(value) != payload:
        raise _InputViolation("noncanonical_json")
    if _contains_forbidden_key(value):
        raise _InputViolation("authority_claim_forbidden")
    if set(value) & _SEMANTIC_CONTEXT_KEYS:
        raise _InputViolation("semantic_context_unbound")
    return value


def _normalize_envelope(
    root: dict[str, Any], profile: ProviderAdapterProfileV1, input_sha256: str
) -> ModelEnvelopeV1:
    allowed_root = {"profile_id", "profile_version", "representation", "schema_version"}
    if profile.context_mode == "required":
        allowed_root.add("context_binding")
    if set(root) != allowed_root:
        reason = (
            "context_binding_required"
            if profile.context_mode == "required" and "context_binding" not in root
            else "outer_shape_invalid"
        )
        raise _InputViolation(reason)
    if root.get("schema_version") != _WIRE_SCHEMA_VERSION:
        raise _InputViolation("schema_version_mismatch")
    if (
        root.get("profile_id") != profile.profile_id
        or root.get("profile_version") != profile.profile_version
    ):
        raise _InputViolation("profile_identity_mismatch")
    context_binding: QuarantineContextBindingV1 | None = None
    if profile.context_mode == "required":
        try:
            context_binding = QuarantineContextBindingV1.model_validate(root["context_binding"])
        except ValidationError as exc:
            raise _InputViolation("context_binding_invalid") from exc
        if (
            context_binding.profile_id != profile.profile_id
            or context_binding.profile_version != profile.profile_version
        ):
            raise _InputViolation("context_binding_mismatch")
    representation = root.get("representation")
    if type(representation) is not dict:
        raise _InputViolation("representation_type_invalid")
    kind = representation.get("kind")
    request: CapabilityRequestV1 | None = None
    if kind == "no_request":
        if set(representation) != {"kind"}:
            raise _InputViolation("representation_shape_invalid")
    elif kind == "capability_request":
        expected = {"arguments", "capability_id", "kind", "request_id"}
        if set(representation) != expected:
            raise _InputViolation("representation_shape_invalid")
        capability_id = representation.get("capability_id")
        request_id = representation.get("request_id")
        arguments = representation.get("arguments")
        if not isinstance(capability_id, str) or not isinstance(request_id, str):
            raise _InputViolation("representation_type_invalid")
        if type(arguments) is not dict:
            raise _InputViolation("representation_type_invalid")
        binding = profile.capability(capability_id)
        if binding is None:
            raise _InputViolation("capability_not_registered")
        argument_keys = set(arguments)
        if not set(binding.required_argument_keys) <= argument_keys or not argument_keys <= set(
            binding.allowed_argument_keys
        ):
            raise _InputViolation("capability_arguments_invalid")
        try:
            request = CapabilityRequestV1(
                profile_id=profile.profile_id,
                profile_version=profile.profile_version,
                request_id=request_id,
                capability_id=capability_id,
                arguments=arguments,
            )
        except ValidationError as exc:
            raise _InputViolation("representation_type_invalid") from exc
    else:
        raise _InputViolation("representation_kind_invalid")
    try:
        envelope = ModelEnvelopeV1(
            profile_id=profile.profile_id,
            profile_version=profile.profile_version,
            representation_kind=kind,
            input_sha256=input_sha256,
            profile_sha256=profile.sha256(),
            context_binding=context_binding,
            capability_request=request,
        )
    except ValidationError as exc:  # pragma: no cover - defensive model coherence guard
        raise _InputViolation("representation_invalid") from exc
    if envelope.canonical_input_bytes() != _canonical_json_bytes(root):
        raise _InputViolation("representation_preservation_failed")
    return envelope


def _reject(
    profile: ProviderAdapterProfileV1,
    reason_code: str,
    *,
    input_sha256: str | None = None,
) -> QuarantineVerdictV1:
    return _verdict(
        disposition="reject",
        reason_code=reason_code,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        input_sha256=input_sha256,
        profile_sha256=profile.sha256(),
    )


def _verdict(
    *,
    disposition: QuarantineDisposition,
    reason_code: str,
    profile_id: str,
    profile_version: str,
    input_sha256: str | None = None,
    profile_sha256: str | None = None,
    envelope: ModelEnvelopeV1 | None = None,
    capability_request: CapabilityRequestV1 | None = None,
) -> QuarantineVerdictV1:
    return QuarantineVerdictV1(
        disposition=disposition,
        reason_code=reason_code,
        selected_profile_id=profile_id,
        selected_profile_version=profile_version,
        input_sha256=input_sha256,
        profile_sha256=profile_sha256,
        envelope=envelope,
        capability_request=capability_request,
    )


def _bounded_input_sha256(payload: Any) -> str | None:
    if type(payload) is not bytes or not payload or len(payload) > MAX_QUARANTINE_INPUT_BYTES:
        return None
    return _domain_sha256_bytes("ash-quarantine-input-v1", payload)


class _InputViolation(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _bounded_int(value: str) -> int:
    parsed = int(value)
    if not -(2**63) <= parsed < 2**63:
        raise ValueError("integer exceeds signed 64-bit range")
    return parsed


def _bounded_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite number")
    return parsed


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-JSON constant is forbidden: {value}")


def _validate_json_value(
    value: Any,
    *,
    depth: int,
    max_depth: int,
    max_string_bytes: int,
    max_collection_items: int,
    max_object_fields: int,
) -> None:
    if depth > max_depth:
        raise QuarantineConnectorError("JSON depth exceeds the selected profile")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if _utf8_length(value) > max_string_bytes:
            raise QuarantineConnectorError("JSON string exceeds the selected profile")
        return
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise QuarantineConnectorError("JSON integer exceeds signed 64-bit range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise QuarantineConnectorError("JSON number is non-finite")
        return
    if isinstance(value, list):
        if len(value) > max_collection_items:
            raise QuarantineConnectorError("JSON array exceeds the selected profile")
        for item in value:
            _validate_json_value(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_string_bytes=max_string_bytes,
                max_collection_items=max_collection_items,
                max_object_fields=max_object_fields,
            )
        return
    if type(value) is dict:
        if len(value) > max_object_fields or any(not isinstance(key, str) for key in value):
            raise QuarantineConnectorError("JSON object exceeds the selected profile")
        for key, item in value.items():
            if _utf8_length(key) > max_string_bytes:
                raise QuarantineConnectorError("JSON key exceeds the selected profile")
            _validate_json_value(
                item,
                depth=depth + 1,
                max_depth=max_depth,
                max_string_bytes=max_string_bytes,
                max_collection_items=max_collection_items,
                max_object_fields=max_object_fields,
            )
        return
    raise QuarantineConnectorError("unsupported JSON value")


def _contains_forbidden_key(value: Any) -> bool:
    if type(value) is dict:
        normalized_keys = {
            "".join(character for character in key.casefold() if character.isalnum())
            for key in value
        }
        return bool(normalized_keys & _NORMALIZED_FORBIDDEN_AUTHORITY_KEYS) or any(
            _contains_forbidden_key(item) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise QuarantineConnectorError("value is not canonical JSON") from exc


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise QuarantineConnectorError("JSON string contains an invalid Unicode scalar") from exc


def _domain_sha256(domain: str, value: Any) -> str:
    return _domain_sha256_bytes(domain, _canonical_json_bytes(value))


def _domain_sha256_bytes(domain: str, payload: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def _is_safe_token(value: str) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    return value[0] in "abcdefghijklmnopqrstuvwxyz0123456789" and all(
        character in "abcdefghijklmnopqrstuvwxyz0123456789._:-" for character in value
    )


__all__ = [
    "QUARANTINE_CONNECTOR_API_VERSION",
    "MAX_QUARANTINE_INPUT_BYTES",
    "CapabilityRequestV1",
    "ModelEnvelopeV1",
    "ProviderAdapterProfileRegistryV1",
    "ProviderAdapterProfileV1",
    "QuarantineCapabilityBindingV1",
    "QuarantineConnectorError",
    "QuarantineContextBindingV1",
    "QuarantineGatewayBridgeV1",
    "QuarantineVerdictV1",
    "bridge_quarantine_admission_v1",
    "evaluate_quarantine_input_v1",
    "quarantine_connector_v1_api_sha256",
    "quarantine_connector_v1_json_schemas",
]
