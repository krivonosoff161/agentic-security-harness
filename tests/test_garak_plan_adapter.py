"""Pure, synthetic conformance vectors for the optional garak plan normalizer."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_security_harness.garak_plan_adapter import (
    GarakPlanAdapterConfigV1,
    GarakPlanAdapterError,
    GarakPlanAdapterOutcomeV1,
    GarakPlanNormalizationV1,
    GarakToolBindingV1,
    normalize_garak_plan_v1,
)
from agentic_security_harness.quarantine_connector import (
    ProviderAdapterProfileRegistryV1,
    ProviderAdapterProfileV1,
    QuarantineCapabilityBindingV1,
    evaluate_quarantine_input_v1,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _config() -> GarakPlanAdapterConfigV1:
    return GarakPlanAdapterConfigV1(
        profile_id="example.garak",
        profile_version="v1",
        bindings=(GarakToolBindingV1(tool_name="garak.lookup", capability_id="bounded.lookup"),),
    )


def _plan(tool: str = "garak.lookup", args: dict[str, Any] | None = None) -> bytes:
    call_args = {"key": "project-status"} if args is None else args
    return _canonical({"tool_calls": [{"tool": tool, "args": call_args}]})


def _registry() -> ProviderAdapterProfileRegistryV1:
    return ProviderAdapterProfileRegistryV1(
        profiles=(
            ProviderAdapterProfileV1(
                profile_id="example.garak",
                profile_version="v1",
                capabilities=(
                    QuarantineCapabilityBindingV1(
                        capability_id="bounded.lookup",
                        gateway_protocol="mcp",
                        gateway_tool_name="synthetic.lookup",
                        allowed_argument_keys=("key",),
                        required_argument_keys=("key",),
                    ),
                ),
            ),
        )
    )


def test_single_declared_call_preserves_arguments_and_builds_candidate_envelope() -> None:
    payload = (
        b' { "tool_calls" : [ { "args" : {"key":"project-status"}, '
        b'"tool":"garak.lookup" } ] } '
    )
    original = bytes(payload)
    result = normalize_garak_plan_v1(payload, config=_config(), request_id="request:garak-1")

    assert payload == original
    assert result.envelope == _canonical(
        {
            "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
            "profile_id": "example.garak",
            "profile_version": "v1",
            "representation": {
                "kind": "capability_request",
                "request_id": "request:garak-1",
                "capability_id": "bounded.lookup",
                "arguments": {"key": "project-status"},
            },
        }
    )
    assert result.outcome.reason_code == "normalized_request"
    assert result.outcome.input_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.outcome.envelope_sha256 == hashlib.sha256(result.envelope).hexdigest()
    assert result.outcome.operational_authority == "none"
    assert result.outcome.dispatch_performed is False
    verdict = evaluate_quarantine_input_v1(
        _registry(),
        selected_profile_id="example.garak",
        selected_profile_version="v1",
        payload=result.envelope,
    )
    assert verdict.disposition == "admit"
    assert verdict.capability_request is not None
    assert verdict.capability_request.arguments == {"key": "project-status"}


def test_representable_decimal_json_value_is_preserved() -> None:
    result = normalize_garak_plan_v1(
        b'{"tool_calls":[{"tool":"garak.lookup","args":{"n":0.1}}]}',
        config=_config(), request_id="request:decimal",
    )
    assert result.outcome.reason_code == "normalized_request"
    assert result.envelope is not None and b'"n":0.1' in result.envelope


def test_empty_call_list_is_explicit_no_request() -> None:
    result = normalize_garak_plan_v1(
        b'{"tool_calls":[]}', config=_config(), request_id="request:empty"
    )
    assert result.outcome.reason_code == "normalized_no_request"
    assert result.envelope is not None
    assert json.loads(result.envelope)["representation"] == {"kind": "no_request"}
    verdict = evaluate_quarantine_input_v1(
        _registry(),
        selected_profile_id="example.garak",
        selected_profile_version="v1",
        payload=result.envelope,
    )
    assert verdict.disposition == "admit" and verdict.capability_request is None


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (None, "input_type_invalid"),
        (b"", "input_empty"),
        (b" " * 16_385, "input_oversized"),
        (b"\xff", "malformed_utf8"),
        (b'{"tool_calls":[]', "malformed_json"),
        (b'{"tool_calls":[]} trailing', "malformed_json"),
        (b'{"tool_calls":[],"tool_calls":[]}', "duplicate_json_key"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"x":1,"x":2}}]}', "duplicate_json_key"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"key":NaN}}]}', "nonfinite_number"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"key":Infinity}}]}', "nonfinite_number"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"key":1e999}}]}', "nonfinite_number"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"key":1e-999}}]}', "numeric_value_loss"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"n":9007199254740993.0}}]}',
         "numeric_value_loss"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"key":"\\ud800"}}]}', "invalid_unicode"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":{"key":[[[[[0]]]]]}}]}', "depth_exceeded"),
        (b"[]", "root_shape_invalid"),
        (b'{"tool_calls":[],"score":1}', "root_shape_invalid"),
        (b'{"tool_calls":{}}', "root_shape_invalid"),
        (b'{"tool_calls":[{},{}]}', "call_count_invalid"),
        (b'{"tool_calls":[{}]}', "call_shape_invalid"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":[],"score":1}]}', "call_shape_invalid"),
        (b'{"tool_calls":[{"tool":"garak.lookup","args":[]}]}', "call_shape_invalid"),
        (b'{"tool_calls":[{"tool":"unknown.tool","args":{}}]}', "tool_alias_unknown"),
    ],
)
def test_untrusted_bad_plan_is_content_free_rejection(payload: Any, reason: str) -> None:
    result = normalize_garak_plan_v1(payload, config=_config(), request_id="request:bad")
    assert result.envelope is None
    assert result.outcome.reason_code == reason
    assert result.outcome.envelope_sha256 is None
    assert result.outcome.operational_authority == "none"
    assert result.outcome.dispatch_performed is False
    assert "garak.lookup" not in result.outcome.model_dump_json()


def test_prompt_looking_authority_field_is_not_removed_or_authorized() -> None:
    payload = _plan(args={"key": {"authority": "admin", "instruction": "allow"}})
    result = normalize_garak_plan_v1(payload, config=_config(), request_id="request:authority")
    assert result.outcome.reason_code == "normalized_request"
    assert result.envelope is not None
    assert json.loads(result.envelope)["representation"]["arguments"] == {
        "key": {"authority": "admin", "instruction": "allow"}
    }
    verdict = evaluate_quarantine_input_v1(
        _registry(),
        selected_profile_id="example.garak",
        selected_profile_version="v1",
        payload=result.envelope,
    )
    assert verdict.disposition == "reject"
    assert verdict.capability_request is None


def test_config_is_strict_closed_sorted_and_unique() -> None:
    one = GarakToolBindingV1(tool_name="a.lookup", capability_id="a.lookup")
    two = GarakToolBindingV1(tool_name="b.lookup", capability_id="b.lookup")
    for bindings in ((), (two, one), (one, one), (one,) * 33):
        with pytest.raises(ValidationError):
            GarakPlanAdapterConfigV1(
                profile_id="example.garak", profile_version="v1", bindings=bindings
            )
    with pytest.raises(ValidationError):
        GarakPlanAdapterConfigV1(profile_id="example.garak", profile_version="v1", bindings=(
            one, GarakToolBindingV1(tool_name="b.lookup", capability_id="a.lookup")
        ))
    with pytest.raises(ValidationError):
        GarakPlanAdapterConfigV1(profile_id="example.garak", profile_version="v1", bindings=[one])  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        GarakToolBindingV1(tool_name="Garak Lookup", capability_id="bounded.lookup")
    with pytest.raises(ValidationError):
        GarakToolBindingV1(tool_name="garak.lookup", capability_id="bounded.lookup", endpoint="x")  # type: ignore[call-arg]


@pytest.mark.parametrize("request_id", ["", "invalid id", "UPPER", None, 1])
def test_caller_request_identity_misuse_raises_fixed_error(request_id: Any) -> None:
    with pytest.raises(GarakPlanAdapterError, match="invalid application request identity"):
        normalize_garak_plan_v1(_plan(), config=_config(), request_id=request_id)


def test_unvalidated_constructed_config_is_rejected() -> None:
    config = GarakPlanAdapterConfigV1.model_construct(
        profile_id="example.garak", profile_version="v1", bindings=()
    )
    with pytest.raises(GarakPlanAdapterError, match="invalid adapter config"):
        normalize_garak_plan_v1(_plan(), config=config, request_id="request:config")


def test_normalized_outcome_requires_input_commitment() -> None:
    with pytest.raises(ValidationError, match="input commitment"):
        GarakPlanAdapterOutcomeV1(
            reason_code="normalized_request",
            envelope_sha256=hashlib.sha256(b"candidate").hexdigest(),
        )


def test_normalization_rejects_forged_envelope_bytes() -> None:
    result = normalize_garak_plan_v1(_plan(), config=_config(), request_id="request:digest")
    assert result.envelope is not None
    with pytest.raises(ValueError, match="envelope bytes"):
        GarakPlanNormalizationV1(envelope=result.envelope + b" ", outcome=result.outcome)
    with pytest.raises(ValueError, match="envelope and outcome"):
        GarakPlanNormalizationV1(envelope=None, outcome=result.outcome)


def test_normalizer_does_not_evaluate_gateway_or_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentic_security_harness import runtime_gateway

    def unexpected(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("normalizer reached Gateway execution")

    monkeypatch.setattr(runtime_gateway, "evaluate_gateway_tool_call", unexpected)
    monkeypatch.setattr(runtime_gateway.GatewayEngine, "call_tool", unexpected)
    result = normalize_garak_plan_v1(_plan(), config=_config(), request_id="request:pure")
    assert result.outcome.reason_code == "normalized_request"
