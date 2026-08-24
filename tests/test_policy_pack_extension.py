from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_security_harness.cli import _main
from agentic_security_harness.extension_sdk import (
    ExtensionObservationEnvelopeV1,
    build_extension_envelope_v1,
)
from agentic_security_harness.policy_pack_extension import (
    POLICY_PACK_FILE_SHA256,
    POLICY_PACK_SEMANTIC_SHA256,
    PolicyPackEvaluationV1,
    PolicyPackExtensionError,
    PolicyPackExtensionV1,
    PolicyPackSignalBindingV1,
    PolicyPackSignalsV1,
    build_policy_pack_signal_binding_v1,
    decode_policy_pack_signal_binding_v1,
    decode_policy_pack_v1,
    encode_policy_pack_signal_binding_v1,
    evaluate_policy_pack_binding_v1,
    read_local_policy_pack_bytes_v1,
    read_local_policy_signal_binding_v1,
    run_policy_pack_extension_v1,
)
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    encode_portfolio_observation_v1,
)

EVENT_ID = "a" * 64


def _playbooks_root() -> Path:
    configured = os.environ.get("ASH_POLICY_PACK_ROOT")
    if not configured:
        pytest.skip("exact llm-safety-playbooks checkout is not configured")
    root = Path(configured)
    if not root.is_dir():
        pytest.fail("ASH_POLICY_PACK_ROOT is not a checked-out directory")
    return root


def _pack_bytes() -> bytes:
    return (_playbooks_root() / "contracts" / "policy-pack.v1.json").read_bytes()


def _event(event_id: str = EVENT_ID) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/local-policy-subject",
            "repository_sha": "b" * 40,
            "occurred_at": datetime(2026, 8, 24, 1, 0, tzinfo=UTC),
            "producer_id_hash": "c" * 64,
            "producer_attestation": "unattested",
            "source_surface": "agent",
            "activity": "agent.observed",
            "entity_refs": (),
            "parent_event_ids": (),
            "data_envelope_ref": "d" * 64,
            "authority_envelope_ref": None,
            "telemetry_state": "complete",
            "operational_authority": "none",
        }
    )


def _signals() -> PolicyPackSignalsV1:
    return PolicyPackSignalsV1(
        untrusted_instructions_detected="present",
        secret_exposure_risk="absent",
        generated_resource_unverified="unknown",
        git_change_control_unclear="absent",
        handoff_verification_incomplete="present",
        research_authorization_unclear="absent",
        observation_metadata_invalid="absent",
    )


def _binding(event: CanonicalObservationEventV1 | None = None) -> PolicyPackSignalBindingV1:
    return build_policy_pack_signal_binding_v1(
        _event() if event is None else event,
        signals=_signals(),
        source_class="synthetic_fixture",
    )


def _envelope(
    event: CanonicalObservationEventV1 | None = None,
) -> ExtensionObservationEnvelopeV1:
    selected = _event() if event is None else event
    return build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256="e" * 64,
        events=(selected,),
    )


def test_exact_pack_decodes_and_matches_reviewed_semantics() -> None:
    pack = decode_policy_pack_v1(
        _pack_bytes(), expected_file_sha256=POLICY_PACK_FILE_SHA256
    )
    assert pack.pack_sha256 == POLICY_PACK_SEMANTIC_SHA256
    assert len(pack.rules) == 7
    assert pack.operational_authority == "none"
    assert pack.may_authorize_effects is False
    assert "allow" not in pack.allowed_dispositions


def test_binding_round_trip_and_evaluation_match_source_fixture_parity() -> None:
    event = _event()
    binding = _binding(event)
    decoded = decode_policy_pack_signal_binding_v1(
        encode_policy_pack_signal_binding_v1(binding)
    )
    evaluation = evaluate_policy_pack_binding_v1(
        decode_policy_pack_v1(
            _pack_bytes(), expected_file_sha256=POLICY_PACK_FILE_SHA256
        ),
        decoded,
        event,
    )
    assert [item.signal_state for item in evaluation.results] == [
        "present",
        "absent",
        "unknown",
        "absent",
        "present",
        "absent",
        "absent",
    ]
    assert [item.advisory_disposition for item in evaluation.results] == [
        "challenge",
        "observe",
        "challenge",
        "observe",
        "challenge",
        "observe",
        "observe",
    ]
    assert evaluation.overall_advisory_disposition == "challenge"
    assert evaluation.operational_authority == "none"


def test_run_is_advisory_and_digest_only() -> None:
    receipt = run_policy_pack_extension_v1(
        pack_bytes=_pack_bytes(),
        expected_pack_file_sha256=POLICY_PACK_FILE_SHA256,
        bindings=(_binding(),),
        envelope=_envelope(),
    )
    assert receipt.operational_authority == "none"
    assert receipt.result.verdict_semantics == "advisory_only_no_operational_effect"
    assert [item.outcome for item in receipt.result.findings].count("finding") == 2
    assert [item.outcome for item in receipt.result.findings].count("inconclusive") == 5
    wire = json.dumps(receipt.model_dump(mode="json"), sort_keys=True)
    assert "prompt" not in wire.lower()
    assert "response" not in wire.lower()
    assert os.environ["ASH_POLICY_PACK_ROOT"] not in wire


def test_missing_pack_is_inconclusive_not_success() -> None:
    receipt = run_policy_pack_extension_v1(
        pack_bytes=None,
        expected_pack_file_sha256=POLICY_PACK_FILE_SHA256,
        bindings=(_binding(),),
        envelope=_envelope(),
    )
    assert len(receipt.result.findings) == 1
    assert receipt.result.findings[0].outcome == "inconclusive"
    assert receipt.result.findings[0].reason_code == "policy_pack.pack-missing"


def test_missing_signal_binding_is_inconclusive() -> None:
    first = _event()
    second = _event("f" * 64)
    envelope = build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256="e" * 64,
        events=(first, second),
    )
    receipt = run_policy_pack_extension_v1(
        pack_bytes=_pack_bytes(),
        expected_pack_file_sha256=POLICY_PACK_FILE_SHA256,
        bindings=(_binding(first),),
        envelope=envelope,
    )
    assert len(receipt.result.findings) == 8
    assert receipt.result.findings[-1].reason_code == "policy_pack.signals-missing"
    extension = PolicyPackExtensionV1(
        pack_bytes=_pack_bytes(),
        expected_pack_file_sha256=POLICY_PACK_FILE_SHA256,
        bindings=(_binding(second),),
    )
    with pytest.raises(PolicyPackExtensionError, match="unknown event"):
        extension.evaluate(_envelope())


def test_replay_and_binding_mismatch_fail_closed() -> None:
    binding = _binding()
    with pytest.raises(PolicyPackExtensionError, match="replay"):
        PolicyPackExtensionV1(
            pack_bytes=_pack_bytes(),
            expected_pack_file_sha256=POLICY_PACK_FILE_SHA256,
            bindings=(binding, binding),
        )
    other = _event("f" * 64)
    with pytest.raises(PolicyPackExtensionError, match="does not match"):
        evaluate_policy_pack_binding_v1(
            decode_policy_pack_v1(
                _pack_bytes(), expected_file_sha256=POLICY_PACK_FILE_SHA256
            ),
            binding,
            other,
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"operational_authority": "write"}),
        lambda value: value["rules"][0].update({"playbook_path": "../unsafe.md"}),
        lambda value: value["rules"][0].update({"present_disposition": "observe"}),
    ],
)
def test_digest_and_semantic_drift_fail_closed(
    mutator: Callable[[dict[str, object]], object],
) -> None:
    value = json.loads(_pack_bytes())
    mutator(value)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(PolicyPackExtensionError):
        decode_policy_pack_v1(payload, expected_file_sha256=POLICY_PACK_FILE_SHA256)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"x":1,"x":2}\n',
        b'{"x":1.25}\n',
        b'{"x":NaN}\n',
        b'{"x":12345678901}\n',
        (b'{"x":' + b"[" * 17 + b"0" + b"]" * 17 + b"}\n"),
    ],
)
def test_ambiguous_deep_and_numeric_json_fail_before_model_construction(payload: bytes) -> None:
    with pytest.raises(PolicyPackExtensionError):
        decode_policy_pack_v1(payload, expected_file_sha256=POLICY_PACK_FILE_SHA256)


def test_model_construct_cannot_bypass_binding_or_evaluation_semantics() -> None:
    binding = _binding()
    invalid_binding = binding.model_copy(update={"operational_authority": "write"})
    with pytest.raises(PolicyPackExtensionError):
        PolicyPackExtensionV1(
            pack_bytes=_pack_bytes(),
            expected_pack_file_sha256=POLICY_PACK_FILE_SHA256,
            bindings=(invalid_binding,),
        )

    evaluation = evaluate_policy_pack_binding_v1(
        decode_policy_pack_v1(
            _pack_bytes(), expected_file_sha256=POLICY_PACK_FILE_SHA256
        ),
        binding,
        _event(),
    )
    raw = evaluation.model_dump(mode="python")
    raw["results"][0]["advisory_disposition"] = "observe"
    with pytest.raises(ValidationError):
        PolicyPackEvaluationV1.model_validate(raw)


def test_local_read_requires_regular_single_link_and_exact_digest(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert (
        read_local_policy_pack_bytes_v1(
            missing, expected_file_sha256=POLICY_PACK_FILE_SHA256
        )
        is None
    )
    pack = tmp_path / "pack.json"
    pack.write_bytes(_pack_bytes())
    assert (
        read_local_policy_pack_bytes_v1(
            pack, expected_file_sha256=POLICY_PACK_FILE_SHA256
        )
        == _pack_bytes()
    )
    hardlink = tmp_path / "pack-link.json"
    os.link(pack, hardlink)
    with pytest.raises(PolicyPackExtensionError, match="single-link"):
        read_local_policy_pack_bytes_v1(
            pack, expected_file_sha256=POLICY_PACK_FILE_SHA256
        )
    with pytest.raises(PolicyPackExtensionError, match="explicit safe path"):
        read_local_policy_pack_bytes_v1(
            tmp_path / "child" / ".." / "pack.json",
            expected_file_sha256=POLICY_PACK_FILE_SHA256,
        )


def test_local_signal_reader_rejects_noncanonical_and_directory(tmp_path: Path) -> None:
    signal_path = tmp_path / "signals.json"
    signal_path.write_bytes(encode_policy_pack_signal_binding_v1(_binding()))
    assert read_local_policy_signal_binding_v1(signal_path) == _binding()
    signal_path.write_text("{}", encoding="utf-8")
    with pytest.raises(PolicyPackExtensionError):
        read_local_policy_signal_binding_v1(signal_path)
    with pytest.raises(PolicyPackExtensionError):
        read_local_policy_signal_binding_v1(tmp_path)


def test_pack_payload_must_be_exact_bytes_and_expected_digest_caller_approved() -> None:
    with pytest.raises(PolicyPackExtensionError, match="exact bytes"):
        decode_policy_pack_v1(
            bytearray(_pack_bytes()),  # type: ignore[arg-type]
            expected_file_sha256=POLICY_PACK_FILE_SHA256,
        )
    with pytest.raises(PolicyPackExtensionError, match="reviewed pin"):
        decode_policy_pack_v1(_pack_bytes(), expected_file_sha256="0" * 64)


def test_pack_fixture_uses_explicit_workflow_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = _pack_bytes()
    isolated = tmp_path / "playbooks"
    contract = isolated / "contracts"
    contract.mkdir(parents=True)
    (contract / "policy-pack.v1.json").write_bytes(expected)
    monkeypatch.setenv("ASH_POLICY_PACK_ROOT", str(isolated))
    assert _pack_bytes() == expected


def test_cli_evaluates_only_explicit_local_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = tmp_path / "pack.json"
    observation = tmp_path / "observation.json"
    signals = tmp_path / "signals.json"
    pack.write_bytes(_pack_bytes())
    observation.write_bytes(encode_portfolio_observation_v1(_event()))
    signals.write_bytes(encode_policy_pack_signal_binding_v1(_binding()))
    assert (
        _main(
            [
                "policy-pack-evaluate",
                "--pack",
                str(pack),
                "--expected-pack-sha256",
                POLICY_PACK_FILE_SHA256,
                "--observation",
                str(observation),
                "--signals",
                str(signals),
                "--format",
                "text",
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert "Pack state: verified" in output.out
    assert "Operational authority: none" in output.out
    assert str(tmp_path) not in output.out + output.err


def test_cli_missing_pack_is_inconclusive_and_failure_is_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    observation = tmp_path / "observation.json"
    signals = tmp_path / "signals.json"
    observation.write_bytes(encode_portfolio_observation_v1(_event()))
    signals.write_bytes(encode_policy_pack_signal_binding_v1(_binding()))
    args = [
        "policy-pack-evaluate",
        "--pack",
        str(tmp_path / "missing-pack.json"),
        "--expected-pack-sha256",
        POLICY_PACK_FILE_SHA256,
        "--observation",
        str(observation),
        "--signals",
        str(signals),
    ]
    assert _main(args) == 0
    output = capsys.readouterr()
    assert "Pack state: missing" in output.out
    assert "Inconclusive: 1" in output.out

    signals.write_text('{"raw_content":"SYNTHETIC_PRIVATE_CANARY"}\n', encoding="utf-8")
    assert _main(args) == 1
    output = capsys.readouterr()
    assert "Error: invalid Policy Pack V1 local input" in output.out
    assert "SYNTHETIC_PRIVATE_CANARY" not in output.out + output.err
    assert str(tmp_path) not in output.out + output.err
