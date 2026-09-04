"""Synthetic causal tests for the explicit advisory source-result ingress."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

import agentic_security_harness.advisory_ingress as ingress
from agentic_security_harness.advisory_gateway_connector import (
    AdvisoryCapabilityBindingV1,
    AdvisoryFixedArgumentV1,
    AdvisoryMappingRuleV1,
    AdvisoryRiskLabel,
)
from agentic_security_harness.advisory_ingress import (
    ADVISORY_INGRESS_API_VERSION,
    MAX_PLAYBOOKS_EVALUATION_BYTES,
    AdvisoryIngressOutcomeV1,
    AdvisoryIngressProfileV1,
    AdvisoryIngressReplayStateV1,
    advisory_ingress_v1_api_sha256,
    advisory_ingress_v1_json_schemas,
    ingest_advisory_source_result_v1,
)
from agentic_security_harness.policy_pack_extension import (
    POLICY_PACK_SEMANTIC_SHA256,
    PolicyPackEvaluationV1,
    PolicyPackRuleEvaluationV1,
    reviewed_policy_pack_source_v1,
)
from agentic_security_harness.receipt_auditors import build_receipt_source_pin_v1
from agentic_security_harness.runtime_gateway import (
    GatewayPolicyV1,
    default_gateway_policy_v1,
)

SESSION_SHA256 = "a" * 64
_POLICY_EVALUATION_DOMAIN = b"agentic-security-harness/policy-pack-evaluation/v1\0"
_PLAYBOOK_RULES = (
    (
        "untrusted-instructions-v1",
        "untrusted_instructions_detected",
        "playbooks/data-vs-instructions.md",
        "bf993293a8a4b8340029bdfbc8fa3ee2052450c7a5ad4618143a0b08e44c9298",
    ),
    (
        "secret-exposure-v1",
        "secret_exposure_risk",
        "playbooks/secret-handling.md",
        "91f1d24612c787bf93f7d2e4e7c7fb7d129c4a0994ca26da3ea0f5715b4b0618",
    ),
    (
        "generated-resource-v1",
        "generated_resource_unverified",
        "playbooks/generated-resource-check.md",
        "3e4884da1b30fcb56b5ebed2cedb5b7f6b652dcabcf3a7221bb331a514fafc95",
    ),
    (
        "git-change-control-v1",
        "git_change_control_unclear",
        "playbooks/git-agent-safety.md",
        "a5fc7e5ac3c17e7b12dffa0bee026e3b3515e7bf1e3a24e1b8d3c57453b06ca2",
    ),
    (
        "handoff-verification-v1",
        "handoff_verification_incomplete",
        "playbooks/handoff-verification.md",
        "46553384d34f5fa4c13c2d745d9260bc6fc83f2923e280f792ad5c14d9280bec",
    ),
    (
        "research-authorization-v1",
        "research_authorization_unclear",
        "playbooks/safe-research-scope.md",
        "709c4482278af2d2497317352d92e05059b20a0108d11dc108234ab6c791c221",
    ),
    (
        "observation-metadata-v1",
        "observation_metadata_invalid",
        "playbooks/canonical-observation-review.md",
        "bd2c518c484072804f860d50d4b4ff52c246fafbaac4c7fb87db86aafd2f79f0",
    ),
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _binding(tool_name: str = "synthetic.lookup") -> AdvisoryCapabilityBindingV1:
    return AdvisoryCapabilityBindingV1(
        binding_id="review.advisory",
        capability_id="bounded.advisory-review",
        gateway_protocol="mcp",
        gateway_tool_name=tool_name,
        fixed_arguments=(
            AdvisoryFixedArgumentV1(name="key", value="project-status"),
        ),
    )


def _filter_profile(*, mapped: bool = False) -> AdvisoryIngressProfileV1:
    source = build_receipt_source_pin_v1("llm-cheap-filter")
    mappings = (
        (
            AdvisoryMappingRuleV1(
                source_component_id="llm-cheap-filter",
                advisory_kind="cheap_filter_finding",
                risk_label="inconclusive",
                binding_id="review.advisory",
            ),
        )
        if mapped
        else ()
    )
    return AdvisoryIngressProfileV1(
        profile_id="filter.receipt.review",
        profile_version="1",
        source_kind="cheap_filter_receipt",
        source_component_id="llm-cheap-filter",
        advisory_kind="cheap_filter_finding",
        source_contract_id=source.contract_id,
        source_contract_version=source.contract_version,
        source_commit=source.source_commit,
        source_tree=source.source_tree,
        source_contract_sha256=source.contract_sha256,
        evidence_class="external_unreviewed",
        fixed_risk_label="inconclusive",
        fixed_advisory_text="A reviewed Cheap Filter receipt was presented.",
        fixed_summary="Accounting evidence only; no security verdict.",
        bindings=(_binding(),),
        mappings=mappings,
    )


def _playbooks_profile(
    *,
    fixed_label: AdvisoryRiskLabel = "observe",
    tool_name: str = "synthetic.lookup",
) -> AdvisoryIngressProfileV1:
    source = reviewed_policy_pack_source_v1()
    return AdvisoryIngressProfileV1(
        profile_id="playbooks.policy.review",
        profile_version="1",
        source_kind="playbooks_policy_evaluation",
        source_component_id="llm-safety-playbooks",
        advisory_kind="playbooks_policy_evaluation",
        source_contract_id="policy-pack-evaluation",
        source_contract_version="1.0",
        source_commit=source.source_commit,
        source_tree=source.source_tree,
        source_contract_sha256=source.output_schema_sha256,
        evidence_class="synthetic_fixture",
        fixed_risk_label=fixed_label,
        fixed_advisory_text="A reviewed Playbooks evaluation was presented.",
        fixed_summary="Deterministic advisory evaluation only.",
        bindings=(_binding(tool_name),),
        mappings=(
            AdvisoryMappingRuleV1(
                source_component_id="llm-safety-playbooks",
                advisory_kind="playbooks_policy_evaluation",
                risk_label=fixed_label,
                binding_id="review.advisory",
            ),
        ),
    )


def _filter_payload() -> bytes:
    input_rows: list[dict[str, object]] = []
    receipt = {
        "escalation_policy_sha256": "b" * 64,
        "input_batch_sha256": hashlib.sha256(
            b"llm-cheap-filter/triage-input-batch/v1\0" + _canonical(input_rows)
        ).hexdigest(),
        "may_lower_security_decision": False,
        "operational_authority": "none",
        "prefilter_configuration_sha256": "c" * 64,
        "results": [],
        "schema_version": "llm-cheap-filter-triage-batch-receipt-v1.0",
        "summary": {
            "cancelled": 0,
            "cheap_drop": 0,
            "cheap_keep": 0,
            "chief": 0,
            "error": 0,
            "input_count": 0,
            "prefilter_drop": 0,
            "total_cost_usd": 0.0,
            "total_tokens": 0,
        },
        "verdict_semantics": "triage_accounting_only_no_security_verdict",
    }
    receipt["receipt_id"] = hashlib.sha256(
        b"llm-cheap-filter/triage-batch-receipt/v1\0" + _canonical(receipt)
    ).hexdigest()
    return _canonical(receipt) + b"\n"


def _playbooks_payload(
    *,
    overall: Literal["observe", "challenge"] = "observe",
    event_id: str = "d" * 64,
) -> bytes:
    results = []
    for index, (rule_id, signal, path, digest) in enumerate(_PLAYBOOK_RULES):
        challenged = overall == "challenge" and index == 0
        state: Literal["absent", "present"] = "present" if challenged else "absent"
        disposition: Literal["observe", "challenge"] = (
            "challenge" if challenged else "observe"
        )
        results.append(
            PolicyPackRuleEvaluationV1(
                rule_id=rule_id,
                signal=signal,
                signal_state=state,
                matched=challenged,
                advisory_disposition=disposition,
                reason_code=f"policy.{rule_id}.{state}",
                playbook_path=path,
                playbook_sha256=digest,
                may_authorize_effects=False,
                operational_authority="none",
            )
        )
    provisional = PolicyPackEvaluationV1.model_construct(
        schema_version="harness-policy-pack-evaluation-v1.0",
        evaluation_sha256="0" * 64,
        event_id=event_id,
        signal_binding_sha256="e" * 64,
        pack_sha256=POLICY_PACK_SEMANTIC_SHA256,
        results=tuple(results),
        overall_advisory_disposition=overall,
        verdict_semantics="advisory_only_no_allow_or_enforcement",
        may_authorize_effects=False,
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="json")
    payload.pop("evaluation_sha256")
    evaluation_sha256 = hashlib.sha256(
        _POLICY_EVALUATION_DOMAIN + _canonical(payload)
    ).hexdigest()
    evaluation = PolicyPackEvaluationV1(
        evaluation_sha256=evaluation_sha256,
        **provisional.model_dump(mode="python", exclude={"evaluation_sha256"}),
    )
    return _canonical(evaluation.model_dump(mode="json"))


def _state() -> AdvisoryIngressReplayStateV1:
    return AdvisoryIngressReplayStateV1(session_sha256=SESSION_SHA256, next_sequence=0)


def _ingest(
    profile: AdvisoryIngressProfileV1,
    payload: bytes,
    *,
    replay_state: AdvisoryIngressReplayStateV1 | None = None,
    sequence: int = 0,
) -> AdvisoryIngressOutcomeV1:
    return ingest_advisory_source_result_v1(
        profile,
        selected_profile_id=profile.profile_id,
        selected_profile_version=profile.profile_version,
        selected_session_sha256=SESSION_SHA256,
        sequence=sequence,
        replay_state=_state() if replay_state is None else replay_state,
        payload=payload,
        gateway_policy=default_gateway_policy_v1(),
    )


def _unexpected(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("the downstream connector must not be reached")


def test_filter_receipt_is_dynamically_bound_but_stays_accounting_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _filter_payload()
    calls = 0
    real_compose = ingress.compose_advisory_gateway_v1

    def _compose(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return real_compose(*args, **kwargs)

    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _compose)
    outcome = _ingest(_filter_profile(), payload)

    assert calls == 1
    assert outcome.ingress_disposition == "admit"
    assert outcome.source_result_sha256 == hashlib.sha256(payload).hexdigest()
    assert outcome.connector_outcome is not None
    assert outcome.connector_outcome.disposition == "inconclusive"
    assert outcome.connector_outcome.reason_code == "mapping_not_registered"
    assert outcome.gateway_evaluated is False
    assert outcome.dispatch_performed is False


@pytest.mark.parametrize(
    ("tool_name", "gateway_disposition"),
    [("synthetic.lookup", "allow"), ("system.shell", "deny")],
)
def test_playbooks_result_reaches_only_the_pure_gateway_decision(
    tool_name: str, gateway_disposition: str
) -> None:
    outcome = _ingest(_playbooks_profile(tool_name=tool_name), _playbooks_payload())

    assert outcome.ingress_disposition == "admit"
    assert outcome.connector_outcome is not None
    assert outcome.connector_outcome.disposition == "admit"
    assert outcome.connector_outcome.gateway_decision is not None
    assert outcome.connector_outcome.gateway_decision.disposition == gateway_disposition
    assert outcome.gateway_evaluated is True
    assert outcome.dispatch_performed is False
    assert outcome.connector_outcome.dispatch_performed is False


def test_dynamic_result_and_replay_transition_are_exactly_linked() -> None:
    first_payload = _playbooks_payload(event_id="d" * 64)
    second_payload = _playbooks_payload(event_id="f" * 64)
    first = _ingest(_playbooks_profile(), first_payload)
    assert first.next_replay_state is not None
    assert first.ingress_receipt_sha256 is not None
    assert first.next_replay_state.previous_ingress_receipt_sha256 == (
        first.ingress_receipt_sha256
    )
    assert first.next_replay_state.next_sequence == 1

    second = _ingest(
        _playbooks_profile(),
        second_payload,
        replay_state=first.next_replay_state,
        sequence=1,
    )
    assert second.ingress_disposition == "admit"
    assert second.source_result_sha256 != first.source_result_sha256
    assert second.ingress_receipt_sha256 != first.ingress_receipt_sha256
    assert second.next_replay_state is not None
    assert len(second.next_replay_state.consumed_source_result_sha256s) == 2


def test_replay_is_rejected_before_connector(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _playbooks_profile()
    payload = _playbooks_payload()
    first = _ingest(profile, payload)
    assert first.next_replay_state is not None
    monkeypatch.setattr(ingress, "_validate_source_result", _unexpected)
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)

    replay = _ingest(profile, payload, replay_state=first.next_replay_state, sequence=1)

    assert replay.ingress_disposition == "reject"
    assert replay.reason_code == "source_result_replay"
    assert replay.connector_invoked is False
    assert replay.gateway_evaluated is False


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("profile", "profile_identity_mismatch"),
        ("session", "session_identity_mismatch"),
        ("sequence", "sequence_mismatch"),
    ],
)
def test_selector_and_session_drift_stop_before_source_validation(
    monkeypatch: pytest.MonkeyPatch, case: str, expected: str
) -> None:
    profile = _playbooks_profile()
    monkeypatch.setattr(ingress, "_validate_source_result", _unexpected)
    kwargs: dict[str, Any] = {
        "selected_profile_id": profile.profile_id,
        "selected_profile_version": profile.profile_version,
        "selected_session_sha256": SESSION_SHA256,
        "sequence": 0,
    }
    if case == "profile":
        kwargs["selected_profile_version"] = "2"
    elif case == "session":
        kwargs["selected_session_sha256"] = "b" * 64
    else:
        kwargs["sequence"] = 1
    outcome = ingest_advisory_source_result_v1(
        profile,
        replay_state=_state(),
        payload=_playbooks_payload(),
        gateway_policy=default_gateway_policy_v1(),
        **kwargs,
    )
    assert outcome.ingress_disposition == "reject"
    assert outcome.reason_code == expected
    assert outcome.connector_invoked is False


def test_semantic_label_drift_stops_before_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)

    outcome = _ingest(
        _playbooks_profile(fixed_label="observe"),
        _playbooks_payload(overall="challenge"),
    )

    assert outcome.ingress_disposition == "reject"
    assert outcome.reason_code == "source_semantic_label_mismatch"
    assert outcome.connector_invoked is False
    assert outcome.gateway_evaluated is False


def test_authority_field_is_rejected_before_contract_and_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = json.loads(_playbooks_payload())
    root["tool_name"] = "system.shell"
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)

    outcome = _ingest(_playbooks_profile(), _canonical(root))

    assert outcome.ingress_disposition == "reject"
    assert outcome.reason_code == "authority_claim_forbidden"
    assert outcome.connector_invoked is False


def test_source_representation_and_exact_bytes_cannot_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)

    wrong_source = _ingest(_playbooks_profile(), _filter_payload())
    missing_filter_newline = _ingest(_filter_profile(), _filter_payload().rstrip(b"\n"))

    assert wrong_source.reason_code == "noncanonical_json"
    assert missing_filter_newline.reason_code == "noncanonical_json"
    assert wrong_source.connector_invoked is missing_filter_newline.connector_invoked is False


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"\xff", "malformed_utf8"),
        (b'{"a":1,"a":2}', "duplicate_json_key"),
        (b'{"a": 1}', "noncanonical_json"),
        (b"[]", "root_type_invalid"),
        (b"", "input_empty"),
    ],
)
def test_malformed_inputs_fail_before_connector(
    monkeypatch: pytest.MonkeyPatch, payload: bytes, reason: str
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)

    outcome = _ingest(_playbooks_profile(), payload)

    assert outcome.ingress_disposition == "reject"
    assert outcome.reason_code == reason
    assert outcome.connector_invoked is False
    assert outcome.gateway_evaluated is False


def test_oversized_input_fails_before_parsing_or_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ingress, "_decode_canonical_object", _unexpected)
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)

    outcome = _ingest(
        _playbooks_profile(), b"x" * (MAX_PLAYBOOKS_EVALUATION_BYTES + 1)
    )

    assert outcome.ingress_disposition == "reject"
    assert outcome.reason_code == "input_oversized"
    assert outcome.source_result_sha256 is None


def test_profile_cannot_claim_filter_security_or_source_drift() -> None:
    source = build_receipt_source_pin_v1("llm-cheap-filter")
    common = {
        "profile_id": "filter.receipt.review",
        "profile_version": "1",
        "source_kind": "cheap_filter_receipt",
        "source_component_id": "llm-cheap-filter",
        "advisory_kind": "cheap_filter_finding",
        "source_contract_id": source.contract_id,
        "source_contract_version": source.contract_version,
        "source_commit": source.source_commit,
        "source_tree": source.source_tree,
        "source_contract_sha256": source.contract_sha256,
        "evidence_class": "external_unreviewed",
        "fixed_risk_label": "inconclusive",
        "fixed_advisory_text": "Reviewed receipt.",
        "fixed_summary": "Accounting only.",
        "bindings": (_binding(),),
        "mappings": (),
    }
    with pytest.raises(ValidationError, match="reviewed source contract"):
        AdvisoryIngressProfileV1.model_validate({**common, "source_commit": "f" * 40})
    with pytest.raises(ValidationError, match="reviewed source contract"):
        AdvisoryIngressProfileV1.model_validate({**common, "fixed_risk_label": "high"})
    with pytest.raises(ValidationError, match="evidence class must remain unreviewed"):
        AdvisoryIngressProfileV1.model_validate(
            {**common, "evidence_class": "producer_declared"}
        )


def test_outcome_retains_only_commitments_not_source_bytes() -> None:
    payload = _playbooks_payload()
    outcome = _ingest(_playbooks_profile(), payload)
    rendered = _canonical(outcome.model_dump(mode="json"))

    assert payload not in rendered
    assert b"endpoint" not in rendered
    assert b"tool output" not in rendered
    assert outcome.operational_authority == "none"
    assert outcome.next_replay_state is not None
    assert outcome.next_replay_state.operational_authority == "none"


def test_explicit_module_import_does_not_import_companion_distributions() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys;"
        f"sys.path.insert(0, {str(source_root)!r});"
        "import agentic_security_harness.advisory_ingress;"
        "assert not any(n == 'llm_cheap_filter' or n.startswith('llm_cheap_filter.') "
        "or n == 'llm_safety_playbooks' or n.startswith('llm_safety_playbooks.') "
        "for n in sys.modules)"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_schema_and_api_digest_are_closed_and_stable() -> None:
    schemas = advisory_ingress_v1_json_schemas()
    assert set(schemas) == {
        "AdvisoryIngressOutcomeV1",
        "AdvisoryIngressProfileV1",
        "AdvisoryIngressReplayStateV1",
    }
    assert ADVISORY_INGRESS_API_VERSION == "AgenticSecurityHarnessAdvisoryIngress.v1"
    assert advisory_ingress_v1_api_sha256() == (
        "a9899c60f6af11018099ab9d6eee60e08e8833aa0e9f050e5eedbdd448fa43c7"
    )


def test_reject_outcome_cannot_retain_connector_or_gateway_state() -> None:
    with pytest.raises(ValidationError, match="rejected ingress"):
        AdvisoryIngressOutcomeV1(
            ingress_disposition="reject",
            reason_code="source_contract_invalid",
            selected_profile_id="playbooks.policy.review",
            selected_profile_version="1",
            ingress_profile_sha256="a" * 64,
            selected_session_sha256="b" * 64,
            input_state_sha256="c" * 64,
            sequence=0,
            connector_invoked=True,
            gateway_evaluated=False,
        )


def test_gateway_policy_must_remain_the_exact_existing_type() -> None:
    profile = _playbooks_profile()
    policy = default_gateway_policy_v1()
    clone = GatewayPolicyV1.model_validate(policy.model_dump(mode="python"))
    assert type(clone) is GatewayPolicyV1
    with pytest.raises(ingress.AdvisoryIngressError, match="gateway policy"):
        ingest_advisory_source_result_v1(
            profile,
            selected_profile_id=profile.profile_id,
            selected_profile_version=profile.profile_version,
            selected_session_sha256=SESSION_SHA256,
            sequence=0,
            replay_state=_state(),
            payload=_playbooks_payload(),
            gateway_policy=object(),  # type: ignore[arg-type]
        )


def test_model_construct_cannot_bypass_replay_state_validation() -> None:
    invalid_state = AdvisoryIngressReplayStateV1.model_construct(
        schema_version="AgenticSecurityHarnessAdvisoryIngressReplayState.v1",
        session_sha256=SESSION_SHA256,
        next_sequence=1,
        previous_ingress_receipt_sha256=None,
        consumed_source_result_sha256s=(),
        operational_authority="none",
    )

    with pytest.raises(ingress.AdvisoryIngressError, match="configuration violates"):
        ingest_advisory_source_result_v1(
            _playbooks_profile(),
            selected_profile_id="playbooks.policy.review",
            selected_profile_version="1",
            selected_session_sha256=SESSION_SHA256,
            sequence=1,
            replay_state=invalid_state,
            payload=_playbooks_payload(),
            gateway_policy=default_gateway_policy_v1(),
        )
