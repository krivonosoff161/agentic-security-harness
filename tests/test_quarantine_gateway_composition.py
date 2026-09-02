"""Causal synthetic tests for the non-executing quarantine/Gateway composition."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import agentic_security_harness.quarantine_gateway_composition as composition
from agentic_security_harness.quarantine_connector import (
    ProviderAdapterProfileRegistryV1,
    ProviderAdapterProfileV1,
    QuarantineCapabilityBindingV1,
    evaluate_quarantine_input_v1,
    quarantine_connector_v1_api_sha256,
)
from agentic_security_harness.quarantine_gateway_composition import (
    QUARANTINE_GATEWAY_COMPOSITION_API_VERSION,
    compose_quarantine_gateway_v1,
    quarantine_gateway_composition_v1_api_sha256,
    quarantine_gateway_composition_v1_json_schemas,
)
from agentic_security_harness.runtime_gateway import (
    GatewayEngine,
    default_gateway_policy_v1,
    evaluate_gateway_tool_call,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _registry(*, tool_name: str = "synthetic.lookup") -> ProviderAdapterProfileRegistryV1:
    return ProviderAdapterProfileRegistryV1(
        profiles=(
            ProviderAdapterProfileV1(
                profile_id="synthetic.composition",
                profile_version="1",
                capabilities=(
                    QuarantineCapabilityBindingV1(
                        capability_id="bounded.lookup",
                        gateway_protocol="mcp",
                        gateway_tool_name=tool_name,
                        allowed_argument_keys=("key",),
                        required_argument_keys=("key",),
                    ),
                ),
            ),
        )
    )


def _payload(representation: dict[str, Any], **extra: Any) -> bytes:
    return _canonical(
        {
            "profile_id": "synthetic.composition",
            "profile_version": "1",
            "representation": representation,
            "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
            **extra,
        }
    )


def _request_payload(*, value: str = "project-status") -> bytes:
    return _payload(
        {
            "arguments": {"key": value},
            "capability_id": "bounded.lookup",
            "kind": "capability_request",
            "request_id": "request:composition",
        }
    )


def _unexpected(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("Gateway bridge/decision/dispatch must not be reached")


@pytest.mark.parametrize(
    ("payload", "profile_id", "expected"),
    [
        (b"{", "synthetic.composition", "reject"),
        (_payload({"kind": "no_request"}), "missing.profile", "inconclusive"),
        (_payload({"kind": "no_request"}, allow=True), "synthetic.composition", "reject"),
    ],
)
def test_non_admit_has_zero_bridge_gateway_and_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    profile_id: str,
    expected: str,
) -> None:
    monkeypatch.setattr(composition, "bridge_quarantine_admission_v1", _unexpected)
    monkeypatch.setattr(composition, "evaluate_gateway_tool_call", _unexpected)
    monkeypatch.setattr(GatewayEngine, "call_tool", _unexpected)

    outcome = compose_quarantine_gateway_v1(
        _registry(),
        selected_profile_id=profile_id,
        selected_profile_version="1",
        payload=payload,
        gateway_policy=default_gateway_policy_v1(),
    )

    assert outcome.connector_disposition == expected
    assert outcome.envelope_sha256 is None
    assert outcome.gateway_decision is None
    assert outcome.gateway_evaluated is False
    assert outcome.dispatch_performed is False


def test_admitted_no_request_has_zero_bridge_gateway_and_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(composition, "bridge_quarantine_admission_v1", _unexpected)
    monkeypatch.setattr(composition, "evaluate_gateway_tool_call", _unexpected)
    monkeypatch.setattr(GatewayEngine, "call_tool", _unexpected)

    outcome = compose_quarantine_gateway_v1(
        _registry(),
        selected_profile_id="synthetic.composition",
        selected_profile_version="1",
        payload=_payload({"kind": "no_request"}),
        gateway_policy=default_gateway_policy_v1(),
    )

    assert outcome.connector_disposition == "admit"
    assert outcome.connector_reason_code == "admitted_no_request"
    assert outcome.envelope_sha256 is not None
    assert outcome.capability_request_sha256 is None
    assert outcome.gateway_decision is None
    assert outcome.gateway_evaluated is False
    assert outcome.dispatch_performed is False


def test_admitted_request_can_receive_gateway_deny_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _evaluate(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return evaluate_gateway_tool_call(*args, **kwargs)

    monkeypatch.setattr(composition, "evaluate_gateway_tool_call", _evaluate)
    monkeypatch.setattr(GatewayEngine, "call_tool", _unexpected)

    outcome = compose_quarantine_gateway_v1(
        _registry(tool_name="custom.unregistered"),
        selected_profile_id="synthetic.composition",
        selected_profile_version="1",
        payload=_request_payload(),
        gateway_policy=default_gateway_policy_v1(),
    )

    assert calls == 1
    assert outcome.connector_disposition == "admit"
    assert outcome.gateway_decision is not None
    assert outcome.gateway_decision.disposition == "deny"
    assert outcome.gateway_decision.reason_code == "unknown_tool_denied"
    assert outcome.gateway_evaluated is True
    assert outcome.dispatch_performed is False
    assert outcome.operational_authority == "none"


def test_gateway_allow_remains_non_executing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(GatewayEngine, "call_tool", _unexpected)

    outcome = compose_quarantine_gateway_v1(
        _registry(),
        selected_profile_id="synthetic.composition",
        selected_profile_version="1",
        payload=_request_payload(),
        gateway_policy=default_gateway_policy_v1(),
    )

    assert outcome.gateway_decision is not None
    assert outcome.gateway_decision.disposition == "allow"
    assert outcome.gateway_decision.execution_permitted is True
    assert outcome.gateway_evaluated is True
    assert outcome.dispatch_performed is False


def test_profile_binding_drift_fails_before_gateway_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_registry = _registry()
    verdict = evaluate_quarantine_input_v1(
        original_registry,
        selected_profile_id="synthetic.composition",
        selected_profile_version="1",
        payload=_request_payload(),
    )
    drifted_registry = _registry(tool_name="custom.changed")
    monkeypatch.setattr(composition, "evaluate_quarantine_input_v1", lambda *_a, **_k: verdict)
    monkeypatch.setattr(composition, "evaluate_gateway_tool_call", _unexpected)
    monkeypatch.setattr(GatewayEngine, "call_tool", _unexpected)

    with pytest.raises(ValueError, match="registry commitment drifted"):
        compose_quarantine_gateway_v1(
            drifted_registry,
            selected_profile_id="synthetic.composition",
            selected_profile_version="1",
            payload=_request_payload(),
            gateway_policy=default_gateway_policy_v1(),
        )


def test_outcome_retains_only_safe_identity_and_reason_fields() -> None:
    marker = "raw-candidate-marker"
    outcome = compose_quarantine_gateway_v1(
        _registry(),
        selected_profile_id="synthetic.composition",
        selected_profile_version="1",
        payload=_request_payload(value=marker),
        gateway_policy=default_gateway_policy_v1(),
    )
    encoded = json.dumps(outcome.model_dump(mode="json"), sort_keys=True)
    safe_decision = outcome.model_dump(mode="json")["gateway_decision"]

    assert marker not in encoded
    assert isinstance(safe_decision, dict)
    assert "arguments" not in safe_decision
    assert "tool_name" not in safe_decision
    assert "arguments_sha256" in safe_decision
    assert "tool_name_sha256" in safe_decision
    assert outcome.sha256() == outcome.sha256()


def test_composition_api_is_separate_and_deterministic() -> None:
    schemas = quarantine_gateway_composition_v1_json_schemas()

    assert QUARANTINE_GATEWAY_COMPOSITION_API_VERSION.endswith(".v1")
    assert "QuarantineGatewayCompositionV1" in schemas
    assert len(quarantine_gateway_composition_v1_api_sha256()) == 64
    assert quarantine_gateway_composition_v1_api_sha256() == (
        quarantine_gateway_composition_v1_api_sha256()
    )
    assert quarantine_connector_v1_api_sha256() == (
        "70c5b4e8dfcf14420e254f63f5ec7dcd4bb645da7064b776ceb934dbda6130b8"
    )


def test_public_composition_module_has_no_execution_transport_or_environment_access() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "agentic_security_harness"
        / "quarantine_gateway_composition.py"
    ).read_text(encoding="utf-8")
    forbidden_fragments = (
        "GatewayEngine",
        ".call_tool(",
        "GatewayAuditLedger",
        "subprocess",
        "os.environ",
        "http.client",
        "urllib",
        "requests",
        "socket",
    )
    assert all(fragment not in source for fragment in forbidden_fragments)
