"""Opt-in, non-executing composition of quarantine admission and Gateway policy.

The caller supplies one immutable profile registry, an exact profile identity, bounded
candidate bytes, and an existing deterministic Gateway policy. The composition ends at
the Gateway's pure pre-execution decision and never selects an executor, writes an audit
record, dispatches a call, or retains raw candidate bytes or tool arguments.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.quarantine_connector import (
    ProviderAdapterProfileRegistryV1,
    QuarantineDisposition,
    QuarantineVerdictV1,
    bridge_quarantine_admission_v1,
    evaluate_quarantine_input_v1,
)
from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayDecisionV1,
    GatewayPolicyV1,
    evaluate_gateway_tool_call,
)

QUARANTINE_GATEWAY_COMPOSITION_API_VERSION = (
    "AgenticSecurityHarnessQuarantineGatewayComposition.v1"
)


class QuarantineGatewayCompositionError(ValueError):
    """Raised for caller/configuration misuse, never for rejected candidate bytes."""


class QuarantineGatewayCompositionV1(BaseModel):
    """Privacy-minimized outcome ending before Gateway execution or dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["AgenticSecurityHarnessQuarantineGatewayComposition.v1"] = (
        "AgenticSecurityHarnessQuarantineGatewayComposition.v1"
    )
    registry_sha256: str = Field(pattern=SHA256_PATTERN)
    connector_verdict_sha256: str = Field(pattern=SHA256_PATTERN)
    connector_disposition: QuarantineDisposition
    connector_reason_code: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_id: str = Field(pattern=SAFE_TOKEN_PATTERN)
    selected_profile_version: str = Field(pattern=SAFE_TOKEN_PATTERN)
    input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    profile_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    envelope_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    capability_request_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    bridge_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    gateway_decision_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    gateway_decision: GatewayDecisionV1 | None = Field(default=None, repr=False)
    gateway_evaluated: bool = False
    dispatch_performed: Literal[False] = False
    operational_authority: Literal["none"] = "none"

    @model_validator(mode="after")
    def _coherent_outcome(self) -> QuarantineGatewayCompositionV1:
        admitted_identity = (self.input_sha256, self.profile_sha256, self.envelope_sha256)
        gateway_identity = (
            self.bridge_sha256,
            self.gateway_decision_sha256,
            self.gateway_decision,
        )
        if self.connector_disposition != "admit":
            if any(item is not None for item in admitted_identity[2:]):
                raise ValueError("non-admit composition cannot retain an envelope")
            if self.capability_request_sha256 is not None or any(
                item is not None for item in gateway_identity
            ):
                raise ValueError("non-admit composition cannot retain Gateway linkage")
            if self.gateway_evaluated:
                raise ValueError("non-admit composition cannot evaluate the Gateway")
            return self

        if any(item is None for item in admitted_identity):
            raise ValueError("admit composition requires input, profile, and envelope commitments")
        if self.capability_request_sha256 is None:
            if any(item is not None for item in gateway_identity) or self.gateway_evaluated:
                raise ValueError("admitted no-request composition cannot evaluate the Gateway")
            return self

        if any(item is None for item in gateway_identity) or not self.gateway_evaluated:
            raise ValueError("admitted capability request requires one Gateway decision")
        if self.gateway_decision_sha256 != _gateway_decision_sha256(self.gateway_decision):
            raise ValueError("Gateway decision commitment drifted")
        return self

    def sha256(self) -> str:
        """Return a domain-separated commitment to this safe-to-publish outcome."""

        return _domain_sha256(
            "ash-quarantine-gateway-composition-v1", self.model_dump(mode="json")
        )


def compose_quarantine_gateway_v1(
    registry: ProviderAdapterProfileRegistryV1,
    *,
    selected_profile_id: str,
    selected_profile_version: str,
    payload: bytes,
    gateway_policy: GatewayPolicyV1,
) -> QuarantineGatewayCompositionV1:
    """Admit exact-profile bytes and, only for a request, obtain a pure Gateway decision."""

    if type(registry) is not ProviderAdapterProfileRegistryV1:
        raise QuarantineGatewayCompositionError("registry must be the exact V1 type")
    if type(gateway_policy) is not GatewayPolicyV1:
        raise QuarantineGatewayCompositionError("gateway policy must be the exact V1 type")

    verdict = evaluate_quarantine_input_v1(
        registry,
        selected_profile_id=selected_profile_id,
        selected_profile_version=selected_profile_version,
        payload=payload,
    )
    common = _outcome_identity(registry, verdict)
    if verdict.disposition != "admit":
        return QuarantineGatewayCompositionV1(**common)

    envelope = verdict.envelope
    if envelope is None:  # pragma: no cover - guarded by QuarantineVerdictV1
        raise QuarantineGatewayCompositionError("admit verdict lost its envelope")
    admitted = {
        **common,
        "envelope_sha256": envelope.sha256(),
    }
    request = verdict.capability_request
    if request is None:
        return QuarantineGatewayCompositionV1(**admitted)

    bridge = bridge_quarantine_admission_v1(verdict, registry)
    if bridge is None:  # pragma: no cover - guarded by admitted request shape
        raise QuarantineGatewayCompositionError("admitted request did not create a bridge")
    decision = evaluate_gateway_tool_call(bridge.gateway_call, gateway_policy)
    return QuarantineGatewayCompositionV1(
        **admitted,
        capability_request_sha256=request.sha256(),
        bridge_sha256=bridge.sha256(),
        gateway_decision_sha256=_gateway_decision_sha256(decision),
        gateway_decision=decision,
        gateway_evaluated=True,
    )


def quarantine_gateway_composition_v1_json_schemas() -> dict[str, dict[str, Any]]:
    """Return deterministic public schemas for the non-executing composition result."""

    return {
        QuarantineGatewayCompositionV1.__name__: (
            QuarantineGatewayCompositionV1.model_json_schema()
        )
    }


def quarantine_gateway_composition_v1_api_sha256() -> str:
    """Digest the separate additive composition API for sanitized handoff."""

    return _domain_sha256(
        "ash-quarantine-gateway-composition-api-v1",
        {
            "api_version": QUARANTINE_GATEWAY_COMPOSITION_API_VERSION,
            "entry_points": ["compose_quarantine_gateway_v1"],
            "schemas": quarantine_gateway_composition_v1_json_schemas(),
        },
    )


def _outcome_identity(
    registry: ProviderAdapterProfileRegistryV1,
    verdict: QuarantineVerdictV1,
) -> dict[str, Any]:
    return {
        "registry_sha256": registry.sha256(),
        "connector_verdict_sha256": verdict.sha256(),
        "connector_disposition": verdict.disposition,
        "connector_reason_code": verdict.reason_code,
        "selected_profile_id": verdict.selected_profile_id,
        "selected_profile_version": verdict.selected_profile_version,
        "input_sha256": verdict.input_sha256,
        "profile_sha256": verdict.profile_sha256,
    }


def _gateway_decision_sha256(decision: GatewayDecisionV1 | None) -> str | None:
    if decision is None:
        return None
    return _domain_sha256(
        "ash-quarantine-gateway-decision-link-v1",
        decision.model_dump(mode="json"),
    )


def _domain_sha256(domain: str, value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


__all__ = [
    "QUARANTINE_GATEWAY_COMPOSITION_API_VERSION",
    "QuarantineGatewayCompositionError",
    "QuarantineGatewayCompositionV1",
    "compose_quarantine_gateway_v1",
    "quarantine_gateway_composition_v1_api_sha256",
    "quarantine_gateway_composition_v1_json_schemas",
]
