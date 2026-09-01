"""Synthetic conformance vectors for the non-executing quarantine connector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

from agentic_security_harness.quarantine_connector import (
    QUARANTINE_CONNECTOR_API_VERSION,
    ProviderAdapterProfileRegistryV1,
    ProviderAdapterProfileV1,
    QuarantineCapabilityBindingV1,
    QuarantineConnectorError,
    QuarantineVerdictV1,
    bridge_quarantine_admission_v1,
    evaluate_quarantine_input_v1,
    quarantine_connector_v1_api_sha256,
    quarantine_connector_v1_json_schemas,
)
from agentic_security_harness.runtime_gateway import evaluate_gateway_tool_call


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _binding(
    capability_id: str,
    gateway_tool_name: str,
    *,
    allowed: tuple[str, ...] = (),
    required: tuple[str, ...] = (),
) -> QuarantineCapabilityBindingV1:
    return QuarantineCapabilityBindingV1(
        capability_id=capability_id,
        gateway_protocol="mcp",
        gateway_tool_name=gateway_tool_name,
        allowed_argument_keys=allowed,
        required_argument_keys=required,
    )


def _profile(
    *,
    context_mode: Literal["forbidden", "required"] = "forbidden",
    max_depth: int = 8,
) -> ProviderAdapterProfileV1:
    return ProviderAdapterProfileV1(
        profile_id="synthetic.canonical",
        profile_version="1",
        context_mode=context_mode,
        max_depth=max_depth,
        capabilities=(
            _binding(
                "digest.text",
                "synthetic.sha256",
                allowed=("text",),
                required=("text",),
            ),
            _binding("unknown.action", "custom.plugin"),
        ),
    )


def _registry(
    *,
    context_mode: Literal["forbidden", "required"] = "forbidden",
    max_depth: int = 8,
) -> ProviderAdapterProfileRegistryV1:
    return ProviderAdapterProfileRegistryV1(
        profiles=(_profile(context_mode=context_mode, max_depth=max_depth),)
    )


def _root(representation: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "profile_id": "synthetic.canonical",
        "profile_version": "1",
        "representation": representation,
        "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
        **extra,
    }


def _evaluate(
    value: dict[str, Any] | bytes,
    *,
    registry: ProviderAdapterProfileRegistryV1 | None = None,
) -> QuarantineVerdictV1:
    payload = value if isinstance(value, bytes) else _canonical(value)
    return evaluate_quarantine_input_v1(
        registry or _registry(),
        selected_profile_id="synthetic.canonical",
        selected_profile_version="1",
        payload=payload,
    )


def test_canonical_no_request_is_admitted_without_a_gateway_bridge() -> None:
    payload = _canonical(_root({"kind": "no_request"}))
    verdict = _evaluate(payload)

    assert verdict.disposition == "admit"
    assert verdict.reason_code == "admitted_no_request"
    assert verdict.operational_authority == "none"
    assert verdict.capability_request is None
    assert verdict.envelope is not None
    assert verdict.envelope.canonical_input_bytes() == payload
    assert bridge_quarantine_admission_v1(verdict, _registry()) is None


def test_canonical_capability_request_builds_only_an_untrusted_gateway_call() -> None:
    verdict = _evaluate(
        _root(
            {
                "arguments": {"text": "synthetic input"},
                "capability_id": "digest.text",
                "kind": "capability_request",
                "request_id": "request:1",
            }
        )
    )

    bridge = bridge_quarantine_admission_v1(verdict, _registry())
    assert verdict.disposition == "admit"
    assert verdict.operational_authority == "none"
    assert bridge is not None
    assert bridge.operational_authority == "none"
    assert bridge.gateway_call.tool_name == "synthetic.sha256"
    assert bridge.gateway_call.arguments == {"text": "synthetic input"}


def test_admit_does_not_equal_gateway_allow() -> None:
    verdict = _evaluate(
        _root(
            {
                "arguments": {},
                "capability_id": "unknown.action",
                "kind": "capability_request",
                "request_id": "request:denied",
            }
        )
    )
    bridge = bridge_quarantine_admission_v1(verdict, _registry())

    assert verdict.disposition == "admit"
    assert bridge is not None
    gateway_decision = evaluate_gateway_tool_call(bridge.gateway_call)
    assert gateway_decision.disposition == "deny"
    assert gateway_decision.reason_code == "unknown_tool_denied"


@pytest.mark.parametrize(
    ("profile_id", "profile_version"),
    [("unregistered", "1"), ("synthetic.canonical", "2")],
)
def test_profile_lookup_is_exact_and_has_no_fallback(profile_id: str, profile_version: str) -> None:
    payload = _canonical(_root({"kind": "no_request"}))
    verdict = evaluate_quarantine_input_v1(
        _registry(),
        selected_profile_id=profile_id,
        selected_profile_version=profile_version,
        payload=payload,
    )

    assert verdict.disposition == "inconclusive"
    assert verdict.reason_code == "profile_not_registered"
    assert verdict.envelope is None
    assert verdict.capability_request is None
    with pytest.raises(QuarantineConnectorError, match="only an admit"):
        bridge_quarantine_admission_v1(verdict, _registry())


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"{",
        b'{"profile_id":"synthetic.canonical","profile_id":"duplicate"}',
        _canonical(_root({"kind": "no_request"})) + b"\n",
        json.dumps(_root({"kind": "no_request"})).encode("utf-8"),
    ],
)
def test_malformed_duplicate_trailing_and_noncanonical_bytes_reject(payload: bytes) -> None:
    verdict = _evaluate(payload)
    assert verdict.disposition == "reject"
    assert verdict.envelope is None
    assert verdict.capability_request is None


def test_escaped_unpaired_surrogate_rejects_instead_of_escaping_the_boundary() -> None:
    payload = _canonical(
        _root(
            {
                "arguments": {"text": "synthetic input"},
                "capability_id": "digest.text",
                "kind": "capability_request",
                "request_id": "request:1",
            }
        )
    ).replace(b'"synthetic input"', b'"\\ud800"')
    verdict = _evaluate(payload)
    assert verdict.disposition == "reject"
    assert verdict.envelope is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"unexpected": True},
        {"schema_version": "AgenticSecurityHarnessModelEnvelope.v2"},
        {"profile_id": "different.profile"},
        {"profile_version": "2"},
    ],
)
def test_outer_shape_and_identity_are_closed(mutation: dict[str, Any]) -> None:
    root = _root({"kind": "no_request"})
    root.update(mutation)
    verdict = _evaluate(root)
    assert verdict.disposition == "reject"


@pytest.mark.parametrize(
    "representation",
    [
        "no_request",
        {"kind": "unknown"},
        {"kind": "no_request", "extra": 1},
        {
            "arguments": [],
            "capability_id": "digest.text",
            "kind": "capability_request",
            "request_id": "request:1",
        },
        {
            "arguments": {},
            "capability_id": "missing.capability",
            "kind": "capability_request",
            "request_id": "request:1",
        },
        {
            "arguments": {"other": "value"},
            "capability_id": "digest.text",
            "kind": "capability_request",
            "request_id": "request:1",
        },
    ],
)
def test_representation_types_shapes_and_capabilities_are_closed(
    representation: Any,
) -> None:
    verdict = _evaluate(_root(representation))
    assert verdict.disposition == "reject"
    assert verdict.capability_request is None


@pytest.mark.parametrize(
    "authority_key",
    [
        "allow",
        "Approval",
        "authority",
        "capability-token",
        "effect",
        "endpoint",
        "policy-id",
        "principal",
        "role",
        "route",
        "token",
        "toolDefinition",
    ],
)
def test_model_bytes_cannot_inject_authority(authority_key: str) -> None:
    verdict = _evaluate(
        _root(
            {
                "arguments": {authority_key: "model-claimed"},
                "capability_id": "digest.text",
                "kind": "capability_request",
                "request_id": "request:1",
            }
        )
    )
    assert verdict.disposition == "reject"
    assert verdict.reason_code == "authority_claim_forbidden"


def test_semantic_outer_context_never_falls_back() -> None:
    verdict = _evaluate(_root({"kind": "no_request"}, context={"turn": 1}))
    assert verdict.disposition == "reject"
    assert verdict.reason_code == "semantic_context_unbound"


def test_required_context_is_explicit_digest_only_and_profile_bound() -> None:
    registry = _registry(context_mode="required")
    missing = _evaluate(_root({"kind": "no_request"}), registry=registry)
    assert missing.disposition == "reject"
    assert missing.reason_code == "context_binding_required"

    context_binding = {
        "endpoint_sha256": "1" * 64,
        "profile_id": "synthetic.canonical",
        "profile_version": "1",
        "schema_version": "AgenticSecurityHarnessQuarantineContextBinding.v1",
        "session_sha256": "2" * 64,
    }
    admitted = _evaluate(
        _root({"kind": "no_request"}, context_binding=context_binding),
        registry=registry,
    )
    assert admitted.disposition == "admit"
    assert admitted.envelope is not None
    assert admitted.envelope.context_binding is not None

    context_binding["profile_version"] = "2"
    mismatched = _evaluate(
        _root({"kind": "no_request"}, context_binding=context_binding),
        registry=registry,
    )
    assert mismatched.disposition == "reject"
    assert mismatched.reason_code == "context_binding_mismatch"


def test_profile_byte_string_and_depth_limits_fail_closed() -> None:
    profile = _profile(max_depth=3).model_copy(update={"max_input_bytes": 256})
    registry = ProviderAdapterProfileRegistryV1(profiles=(profile,))
    oversized = _evaluate(b"x" * 257, registry=registry)
    assert oversized.disposition == "reject"
    assert oversized.reason_code == "input_oversized"

    deep = _evaluate(
        _root(
            {
                "arguments": {"text": [[["nested"]]]},
                "capability_id": "digest.text",
                "kind": "capability_request",
                "request_id": "request:1",
            }
        ),
        registry=_registry(max_depth=3),
    )
    assert deep.disposition == "reject"
    assert deep.reason_code == "profile_bounds_exceeded"

    short_strings = _profile().model_copy(update={"max_string_bytes": 8})
    string_limited = ProviderAdapterProfileRegistryV1(profiles=(short_strings,))
    long_string = _evaluate(
        _root(
            {
                "arguments": {"text": "123456789"},
                "capability_id": "digest.text",
                "kind": "capability_request",
                "request_id": "request:1",
            }
        ),
        registry=string_limited,
    )
    assert long_string.disposition == "reject"
    assert long_string.reason_code == "profile_bounds_exceeded"


def test_non_admit_verdicts_create_zero_bridge() -> None:
    rejected = _evaluate(b"not-json")
    inconclusive = evaluate_quarantine_input_v1(
        _registry(),
        selected_profile_id="unregistered",
        selected_profile_version="1",
        payload=b"not-json",
    )
    for verdict in (rejected, inconclusive):
        assert verdict.envelope is None
        assert verdict.capability_request is None
        with pytest.raises(QuarantineConnectorError, match="only an admit"):
            bridge_quarantine_admission_v1(verdict, _registry())


def test_profiles_and_registry_are_immutable_sorted_and_unique() -> None:
    with pytest.raises(ValidationError, match="sorted and unique"):
        ProviderAdapterProfileV1(
            profile_id="synthetic.canonical",
            profile_version="1",
            capabilities=(
                _binding("z", "synthetic.lookup"),
                _binding("a", "synthetic.sha256"),
            ),
        )
    with pytest.raises(ValidationError, match="sorted and unique"):
        ProviderAdapterProfileRegistryV1(profiles=(_profile(), _profile()))
    with pytest.raises(ValidationError, match="frozen"):
        _profile().profile_version = "2"


def test_api_schema_and_digest_are_deterministic() -> None:
    schemas = quarantine_connector_v1_json_schemas()
    assert QUARANTINE_CONNECTOR_API_VERSION.endswith(".v1")
    assert "ModelEnvelopeV1" in schemas
    assert "QuarantineVerdictV1" in schemas
    assert quarantine_connector_v1_api_sha256() == quarantine_connector_v1_api_sha256()
    assert len(quarantine_connector_v1_api_sha256()) == 64


def test_public_module_has_no_execution_transport_or_environment_access() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "agentic_security_harness" / "quarantine_connector.py"
    ).read_text(encoding="utf-8")
    forbidden_fragments = (
        "GatewayEngine",
        ".call_tool(",
        "subprocess",
        "os.environ",
        "http.client",
        "urllib",
        "requests",
        "socket",
    )
    assert all(fragment not in source for fragment in forbidden_fragments)
