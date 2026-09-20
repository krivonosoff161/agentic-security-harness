from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

import agentic_security_harness.advisory_gateway_connector as connector
import agentic_security_harness.external_playbooks_ingress as ingress
from agentic_security_harness.advisory_gateway_connector import (
    AdvisoryCapabilityBindingV1,
    AdvisoryFixedArgumentV1,
    AdvisoryMappingRuleV1,
)
from agentic_security_harness.advisory_ingress import AdvisoryIngressReplayStateV1
from agentic_security_harness.external_playbooks_ingress import (
    EXTERNAL_PLAYBOOKS_INGRESS_API_VERSION,
    ExternalPlaybooksIngressOutcomeV1,
    ExternalPlaybooksIngressProfileV1,
    external_playbooks_ingress_v1_api_sha256,
    external_playbooks_ingress_v1_json_schemas,
    ingest_external_playbooks_pair_v1,
)
from agentic_security_harness.runtime_gateway import default_gateway_policy_v1

SUBJECT = "a" * 64
SESSION = "b" * 64
INPUT_DOMAIN = b"llm-safety-playbooks/policy-input/v1\0"
OUTPUT_DOMAIN = b"llm-safety-playbooks/policy-output/v1\0"
INPUT_BYTES_DOMAIN = b"llm-safety-playbooks/policy-input-bytes/v1\0"
RULES = (
    (
        "untrusted-instructions-v1",
        "untrusted_instructions_detected",
        "playbooks/data-vs-instructions.md",
        "bf993293a8a4b8340029bdfbc8fa3ee2052450c7a5ad4618143a0b08e44c9298",
        "challenge",
        "challenge",
    ),
    (
        "secret-exposure-v1",
        "secret_exposure_risk",
        "playbooks/secret-handling.md",
        "91f1d24612c787bf93f7d2e4e7c7fb7d129c4a0994ca26da3ea0f5715b4b0618",
        "abstain",
        "abstain",
    ),
    (
        "generated-resource-v1",
        "generated_resource_unverified",
        "playbooks/generated-resource-check.md",
        "3e4884da1b30fcb56b5ebed2cedb5b7f6b652dcabcf3a7221bb331a514fafc95",
        "challenge",
        "challenge",
    ),
    (
        "git-change-control-v1",
        "git_change_control_unclear",
        "playbooks/git-agent-safety.md",
        "a5fc7e5ac3c17e7b12dffa0bee026e3b3515e7bf1e3a24e1b8d3c57453b06ca2",
        "escalate",
        "escalate",
    ),
    (
        "handoff-verification-v1",
        "handoff_verification_incomplete",
        "playbooks/handoff-verification.md",
        "46553384d34f5fa4c13c2d745d9260bc6fc83f2923e280f792ad5c14d9280bec",
        "challenge",
        "challenge",
    ),
    (
        "research-authorization-v1",
        "research_authorization_unclear",
        "playbooks/safe-research-scope.md",
        "709c4482278af2d2497317352d92e05059b20a0108d11dc108234ab6c791c221",
        "abstain",
        "abstain",
    ),
    (
        "observation-metadata-v1",
        "observation_metadata_invalid",
        "playbooks/canonical-observation-review.md",
        "bd2c518c484072804f860d50d4b4ff52c246fafbaac4c7fb87db86aafd2f79f0",
        "abstain",
        "abstain",
    ),
)
MIXED = {
    "untrusted_instructions_detected": "present",
    "secret_exposure_risk": "absent",
    "generated_resource_unverified": "unknown",
    "git_change_control_unclear": "absent",
    "handoff_verification_incomplete": "present",
    "research_authorization_unclear": "absent",
    "observation_metadata_invalid": "absent",
}
ABSENT = {signal: "absent" for _, signal, *_ in RULES}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _input(signals: dict[str, str] = MIXED, *, subject: str = SUBJECT) -> bytes:
    root: dict[str, Any] = {
        "digest_is_authentication": False,
        "may_authorize_effects": False,
        "operational_authority": "none",
        "pack_sha256": ingress.PLAYBOOKS_PACK_SHA256,
        "raw_content_included": False,
        "schema_version": ingress.PLAYBOOKS_INPUT_SCHEMA,
        "signals": signals,
        "source_class": "synthetic_fixture",
        "subject_digest_semantics": "caller_supplied_sanitized_subject_commitment",
        "subject_sha256": subject,
    }
    root["input_receipt_id"] = hashlib.sha256(INPUT_DOMAIN + _canonical(root)).hexdigest()
    return _canonical(root) + b"\n"


def _output(input_payload: bytes, *, mutate: Any = None) -> bytes:
    source = json.loads(input_payload)
    results: list[dict[str, Any]] = []
    dispositions: list[str] = []
    counts = {
        name: 0
        for name in ("absent", "present", "unknown", "observe", "challenge", "escalate", "abstain")
    }
    for rule_id, signal, path, digest, present, unknown in RULES:
        state = source["signals"][signal]
        disposition = "observe" if state == "absent" else present if state == "present" else unknown
        counts[state] += 1
        counts[disposition] += 1
        dispositions.append(disposition)
        results.append(
            {
                "advisory_disposition": disposition,
                "matched": state != "absent",
                "may_authorize_effects": False,
                "operational_authority": "none",
                "playbook_path": path,
                "playbook_sha256": digest,
                "reason_codes": [f"policy.{rule_id}.{state}"],
                "rule_id": rule_id,
                "signal": signal,
                "signal_state": state,
            }
        )
    root: dict[str, Any] = {
        "input_receipt_id": source["input_receipt_id"],
        "input_sha256": hashlib.sha256(INPUT_BYTES_DOMAIN + input_payload).hexdigest(),
        "may_authorize_effects": False,
        "operational_authority": "none",
        "overall_advisory_disposition": max(
            dispositions, key=("observe", "challenge", "escalate", "abstain").index
        ),
        "pack_sha256": ingress.PLAYBOOKS_PACK_SHA256,
        "results": results,
        "schema_version": ingress.PLAYBOOKS_OUTPUT_SCHEMA,
        "summary": {"signal_count": len(RULES), **counts},
        "verdict_semantics": "advisory_only_no_allow_or_enforcement",
    }
    if mutate is not None:
        mutate(root)
    root.pop("receipt_id", None)
    root["receipt_id"] = hashlib.sha256(OUTPUT_DOMAIN + _canonical(root)).hexdigest()
    return _canonical(root) + b"\n"


def _profile(
    disposition: Literal["observe", "challenge"] = "challenge",
    *,
    tool_name: str = "synthetic.lookup",
) -> ExternalPlaybooksIngressProfileV1:
    return ExternalPlaybooksIngressProfileV1(
        profile_id=f"playbooks.external.{disposition}",
        profile_version="1",
        expected_disposition=disposition,
        fixed_advisory_text="An exact external Playbooks receipt pair was validated.",
        fixed_summary="Deterministic external advisory evidence only.",
        bindings=(
            AdvisoryCapabilityBindingV1(
                binding_id="review.advisory",
                capability_id="bounded.project-status",
                gateway_protocol="mcp",
                gateway_tool_name=tool_name,
                fixed_arguments=(AdvisoryFixedArgumentV1(name="key", value="project-status"),),
            ),
        ),
        mappings=(
            AdvisoryMappingRuleV1(
                source_component_id="llm-safety-playbooks",
                advisory_kind="playbooks_policy_evaluation",
                risk_label=disposition,
                binding_id="review.advisory",
            ),
        ),
    )


def _state() -> AdvisoryIngressReplayStateV1:
    return AdvisoryIngressReplayStateV1(session_sha256=SESSION, next_sequence=0)


def _ingest(
    profile: ExternalPlaybooksIngressProfileV1,
    input_payload: bytes,
    output_payload: bytes,
    *,
    state: AdvisoryIngressReplayStateV1 | None = None,
    sequence: int = 0,
) -> ExternalPlaybooksIngressOutcomeV1:
    return ingest_external_playbooks_pair_v1(
        profile,
        selected_profile_id=profile.profile_id,
        selected_profile_version=profile.profile_version,
        selected_subject_sha256=SUBJECT,
        selected_session_sha256=SESSION,
        sequence=sequence,
        replay_state=_state() if state is None else state,
        input_payload=input_payload,
        output_payload=output_payload,
        gateway_policy=default_gateway_policy_v1(),
    )


@pytest.mark.parametrize(
    ("signals", "disposition", "tool_name", "gateway_disposition"),
    [
        (MIXED, "challenge", "synthetic.lookup", "allow"),
        (ABSENT, "observe", "system.shell", "deny"),
    ],
)
def test_public_vectors_reach_one_pure_gateway_decision_and_never_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    signals: dict[str, str],
    disposition: Literal["observe", "challenge"],
    tool_name: str,
    gateway_disposition: str,
) -> None:
    gateway_calls = 0
    real_evaluate = connector.evaluate_gateway_tool_call

    def counted(*args: Any, **kwargs: Any) -> Any:
        nonlocal gateway_calls
        gateway_calls += 1
        return real_evaluate(*args, **kwargs)

    monkeypatch.setattr(connector, "evaluate_gateway_tool_call", counted)
    input_payload = _input(signals)
    outcome = _ingest(
        _profile(disposition, tool_name=tool_name), input_payload, _output(input_payload)
    )

    assert outcome.ingress_disposition == "admit"
    assert outcome.stage == "complete"
    assert outcome.connector_outcome is not None
    assert outcome.connector_outcome.disposition == "admit"
    assert outcome.connector_outcome.gateway_decision is not None
    assert outcome.connector_outcome.gateway_decision.disposition == gateway_disposition
    assert gateway_calls == 1
    assert outcome.gateway_evaluated is True
    assert outcome.dispatch_performed is outcome.connector_outcome.dispatch_performed is False


def test_exact_pair_and_returned_replay_state_are_digest_linked() -> None:
    input_payload = _input()
    output_payload = _output(input_payload)
    first = _ingest(_profile(), input_payload, output_payload)

    assert first.input_bytes_sha256 == hashlib.sha256(input_payload).hexdigest()
    assert first.source_result_sha256 == hashlib.sha256(output_payload).hexdigest()
    assert first.next_replay_state is not None
    assert first.next_replay_state.next_sequence == 1
    assert first.next_replay_state.previous_ingress_receipt_sha256 == first.ingress_receipt_sha256

    replay = _ingest(
        _profile(), input_payload, output_payload, state=first.next_replay_state, sequence=1
    )
    assert replay.ingress_disposition == "reject"
    assert replay.stage == "replay"
    assert replay.reason_code == "source_result_replay"
    assert replay.next_replay_state is None
    assert replay.connector_invoked is replay.gateway_evaluated is False


@pytest.mark.parametrize(
    ("case", "stage", "reason"),
    [
        ("input_lf", "input_bytes", "noncanonical_json"),
        ("output_lf", "output_bytes", "noncanonical_json"),
        ("duplicate", "output_bytes", "duplicate_json_key"),
        ("unknown", "schema_authority", "external_schema_invalid"),
        ("authority", "schema_authority", "authority_claim_forbidden"),
        ("authority_value", "schema_authority", "authority_claim_forbidden"),
        ("schema", "schema_authority", "external_schema_invalid"),
        ("receipt", "identity_correspondence", "receipt_identity_mismatch"),
        ("input_binding", "identity_correspondence", "input_output_binding_mismatch"),
        ("pack", "identity_correspondence", "pack_binding_mismatch"),
        ("rule", "identity_correspondence", "rule_binding_mismatch"),
        ("semantic", "identity_correspondence", "semantic_accounting_mismatch"),
        ("summary", "identity_correspondence", "semantic_accounting_mismatch"),
    ],
)
def test_negative_vectors_stop_before_connector_and_gateway(
    monkeypatch: pytest.MonkeyPatch, case: str, stage: str, reason: str
) -> None:
    input_payload = _input()
    output_payload = _output(input_payload)
    if case == "input_lf":
        input_payload = input_payload.rstrip(b"\n")
    elif case == "output_lf":
        output_payload = output_payload.rstrip(b"\n")
    elif case == "duplicate":
        output_payload = output_payload[:-2] + b',"schema_version":"x"}\n'
    elif case == "receipt":
        root = json.loads(output_payload)
        root["receipt_id"] = "f" * 64
        output_payload = _canonical(root) + b"\n"
    else:

        def mutate(root: dict[str, Any]) -> None:
            if case == "unknown":
                root["extra_field"] = False
            elif case == "authority":
                root["tool_name"] = "synthetic.lookup"
            elif case == "authority_value":
                root["may_authorize_effects"] = True
            elif case == "schema":
                root["schema_version"] = "llm-safety-policy-evaluation-receipt-v2.0"
            elif case == "input_binding":
                root["input_receipt_id"] = "f" * 64
            elif case == "pack":
                root["pack_sha256"] = "f" * 64
            elif case == "rule":
                root["results"][0]["playbook_sha256"] = "f" * 64
            elif case == "summary":
                root["summary"]["present"] = 0
            elif case == "semantic":
                root["results"][0]["signal_state"] = "absent"
                root["results"][0]["matched"] = False
                root["results"][0]["advisory_disposition"] = "observe"
                root["results"][0]["reason_codes"] = ["policy.untrusted-instructions-v1.absent"]

        output_payload = _output(input_payload, mutate=mutate)

    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)
    monkeypatch.setattr(connector, "evaluate_gateway_tool_call", _unexpected)
    outcome = _ingest(_profile(), input_payload, output_payload)

    assert outcome.ingress_disposition == "reject"
    assert outcome.stage == stage
    assert outcome.reason_code == reason
    assert outcome.next_replay_state is None
    assert outcome.connector_invoked is outcome.gateway_evaluated is False


@pytest.mark.parametrize("case", ["sequence", "semantic_profile", "history_full"])
def test_selection_and_history_limits_never_reach_downstream(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)
    monkeypatch.setattr(connector, "evaluate_gateway_tool_call", _unexpected)
    state = _state()
    if case == "history_full":
        state = AdvisoryIngressReplayStateV1(
            session_sha256=SESSION,
            next_sequence=64,
            previous_ingress_receipt_sha256="c" * 64,
            consumed_source_result_sha256s=tuple(f"{index:064x}" for index in range(64)),
        )
    original = state.model_dump_json()
    payload = _input()
    outcome = _ingest(
        _profile("observe" if case == "semantic_profile" else "challenge"),
        payload,
        _output(payload),
        state=state,
        sequence=1 if case == "sequence" else state.next_sequence,
    )
    assert outcome.reason_code == {
        "sequence": "sequence_mismatch",
        "semantic_profile": "source_semantic_label_mismatch",
        "history_full": "replay_history_full",
    }[case]
    assert outcome.ingress_disposition == "reject"
    assert outcome.next_replay_state is None
    assert state.model_dump_json() == original


@pytest.mark.parametrize("wire", ["input", "output"])
@pytest.mark.parametrize("replacement", [None, [], {}, False, 1, 1.5])
def test_wrong_json_field_types_are_typed_rejections_not_exceptions(
    monkeypatch: pytest.MonkeyPatch, wire: str, replacement: Any
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)
    monkeypatch.setattr(connector, "evaluate_gateway_tool_call", _unexpected)
    input_payload = _input()
    output_payload = _output(input_payload)
    template = json.loads(input_payload if wire == "input" else output_payload)
    for key, original in template.items():
        if type(original) is type(replacement):
            continue
        root = {**template, key: replacement}
        # Recompute self-identity so type tests are not masked by stale digests.
        id_key = "input_receipt_id" if wire == "input" else "receipt_id"
        if key != id_key:
            unsigned = {name: value for name, value in root.items() if name != id_key}
            domain = INPUT_DOMAIN if wire == "input" else OUTPUT_DOMAIN
            root[id_key] = hashlib.sha256(domain + _canonical(unsigned)).hexdigest()
        payload = _canonical(root) + b"\n"
        outcome = _ingest(
            _profile(),
            payload if wire == "input" else input_payload,
            payload if wire == "output" else output_payload,
        )
        assert outcome.ingress_disposition == "reject", (wire, key, type(replacement))
        assert outcome.connector_invoked is outcome.gateway_evaluated is False
        assert outcome.next_replay_state is None


@pytest.mark.parametrize("wire", ["input", "output"])
@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b'{"x":"\\ud800"}\n', "input_bounds_invalid"),
        (b'{"' + b"x" * 1025 + b'":0}\n', "input_bounds_invalid"),
        (b'{"x":' + b"[" * 9 + b"0" + b"]" * 9 + b"}\n", "input_bounds_invalid"),
        (b"\xef\xbb\xbf{}\n", "bom_forbidden"),
        (b"\xff\n", "malformed_utf8"),
        (b'{"x":NaN}\n', "malformed_json"),
    ],
)
def test_invalid_wire_bounds_are_typed_before_downstream(
    monkeypatch: pytest.MonkeyPatch, wire: str, payload: bytes, reason: str
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)
    monkeypatch.setattr(connector, "evaluate_gateway_tool_call", _unexpected)
    valid_input = _input()
    outcome = _ingest(
        _profile(),
        payload if wire == "input" else valid_input,
        payload if wire == "output" else _output(valid_input),
    )
    assert outcome.ingress_disposition == "reject"
    assert outcome.stage == f"{wire}_bytes"
    assert outcome.reason_code == reason
    assert outcome.next_replay_state is None


@pytest.mark.parametrize("source_class", ["sanitized_metadata", "external_adapter_receipt"])
def test_fixture_profile_cannot_relabel_other_evidence_classes(
    monkeypatch: pytest.MonkeyPatch, source_class: str
) -> None:
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)
    root = json.loads(_input())
    root["source_class"] = source_class
    root.pop("input_receipt_id")
    root["input_receipt_id"] = hashlib.sha256(INPUT_DOMAIN + _canonical(root)).hexdigest()
    payload = _canonical(root) + b"\n"
    outcome = _ingest(_profile(), payload, _output(payload))
    assert outcome.reason_code == "external_schema_invalid"
    assert outcome.connector_invoked is False
    assert outcome.next_replay_state is None


def test_subject_pack_profile_and_session_drift_are_typed_pre_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_payload = _input()
    output_payload = _output(input_payload)
    monkeypatch.setattr(ingress, "compose_advisory_gateway_v1", _unexpected)
    profile = _profile()

    def run(*, version: str = "1", subject: str = SUBJECT, session: str = SESSION) -> str:
        return ingest_external_playbooks_pair_v1(
            profile,
            selected_profile_id=profile.profile_id,
            selected_profile_version=version,
            selected_subject_sha256=subject,
            selected_session_sha256=session,
            sequence=0,
            replay_state=_state(),
            input_payload=input_payload,
            output_payload=output_payload,
            gateway_policy=default_gateway_policy_v1(),
        ).reason_code

    reasons = [run(version="2"), run(session="c" * 64), run(subject="d" * 64)]
    assert reasons == [
        "profile_identity_mismatch",
        "session_identity_mismatch",
        "subject_binding_mismatch",
    ]


def test_pin_mapping_and_outcome_models_are_fail_closed() -> None:
    profile = _profile()
    with pytest.raises(ValidationError, match="profile pin drift"):
        ExternalPlaybooksIngressProfileV1.model_validate(
            {**profile.model_dump(mode="python"), "source_commit": "f" * 40}
        )
    with pytest.raises(ValidationError, match="fixed external Playbooks tuple"):
        ExternalPlaybooksIngressProfileV1.model_validate(
            {
                **profile.model_dump(mode="python"),
                "mappings": (
                    {
                        **profile.mappings[0].model_dump(mode="python"),
                        "risk_label": "observe",
                    },
                ),
            }
        )
    with pytest.raises(ValidationError, match="rejected pair"):
        ExternalPlaybooksIngressOutcomeV1(
            ingress_disposition="reject",
            stage="input_bytes",
            reason_code="malformed_json",
            selected_profile_id=profile.profile_id,
            selected_profile_version="1",
            profile_sha256=profile.sha256(),
            selected_subject_sha256=SUBJECT,
            selected_session_sha256=SESSION,
            input_state_sha256=_state().sha256(),
            sequence=0,
            connector_invoked=True,
        )


def test_result_is_content_free_and_import_is_passive() -> None:
    input_payload = _input()
    output_payload = _output(input_payload)
    outcome = _ingest(_profile(), input_payload, output_payload)
    rendered = _canonical(outcome.model_dump(mode="json"))
    assert input_payload not in rendered
    assert output_payload not in rendered
    assert b"endpoint" not in rendered
    assert outcome.operational_authority == "none"

    source_root = Path(__file__).parents[1] / "src"
    code = f"""
import os
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, {str(source_root)!r})
attempts = []
def audit(event, args):
    denied = (
        event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn'))
        or event in {{'os.system', 'os.fork', 'os.forkpty'}}
        or (event == 'open' and (
            (isinstance(args[1], str) and any(c in args[1] for c in 'wax+'))
            or (isinstance(args[2], int) and args[2] & (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            ))
        ))
    )
    if denied:
        attempts.append(event)
        raise RuntimeError('passive import attempted a forbidden effect')
sys.addaudithook(audit)
import agentic_security_harness.external_playbooks_ingress
assert not attempts
assert not any(n == 'llm_safety_playbooks' or n.startswith('llm_safety_playbooks.')
               for n in sys.modules)
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_api_digest_and_content_free_regression_manifest_are_exact() -> None:
    manifest = json.loads(
        (
            Path(__file__).parents[1] / "tests/fixtures/external-playbooks-ingress-v1/manifest.json"
        ).read_text(encoding="utf-8")
    )
    challenge_input = _input()
    challenge_output = _output(challenge_input)
    benign_input = _input(ABSENT)
    benign_output = _output(benign_input)
    assert EXTERNAL_PLAYBOOKS_INGRESS_API_VERSION == (
        "AgenticSecurityHarnessExternalPlaybooksIngress.v1"
    )
    assert set(external_playbooks_ingress_v1_json_schemas()) == {
        "ExternalPlaybooksIngressOutcomeV1",
        "ExternalPlaybooksIngressProfileV1",
    }
    assert manifest["contract_digest"] == external_playbooks_ingress_v1_api_sha256()
    assert manifest["vectors"] == [
        {
            "expected_disposition": "challenge",
            "input_bytes_sha256": hashlib.sha256(challenge_input).hexdigest(),
            "output_bytes_sha256": hashlib.sha256(challenge_output).hexdigest(),
            "vector_id": "DP002-PB-EXT-01",
        },
        {
            "expected_disposition": "observe",
            "input_bytes_sha256": hashlib.sha256(benign_input).hexdigest(),
            "output_bytes_sha256": hashlib.sha256(benign_output).hexdigest(),
            "vector_id": "DP002-PB-EXT-OBSERVE-01",
        },
    ]
    assert manifest["producer_runtime_equivalence"] == "pending_fresh_lab_regression"
    assert manifest["operational_authority"] == "none"


def _unexpected(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("downstream boundary must not be reached")
