from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_security_harness.agent_host_adapter import (
    AgentHostDescriptorV1,
    AgentHostRecordingV1,
    build_agent_host_recording_v1,
    encode_agent_host_recording_v1,
)
from agentic_security_harness.agent_host_evaluator import (
    ADAPTER_ERROR_ACTIVITY,
    FINDING_ACTIVITY,
    INCONCLUSIVE_ACTIVITY,
    PASS_ACTIVITY,
    AgentHostEvaluationContractError,
    AgentHostEvaluationRulesetV1,
    AgentHostEvaluationV1,
    agent_host_evaluation_ruleset_v1,
    commit_agent_host_evaluation_v1,
    decode_agent_host_evaluation_v1,
    encode_agent_host_evaluation_ruleset_v1,
    encode_agent_host_evaluation_v1,
    evaluate_agent_host_recording_v1,
)
from agentic_security_harness.cli import _main
from agentic_security_harness.corpus import V1_PATTERN_IDS, corpus_manifest
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 22, 9, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _host() -> AgentHostDescriptorV1:
    return AgentHostDescriptorV1(
        schema_version="agent-host-descriptor-v1.0",
        adapter_id="reference.record-replay",
        adapter_version="1.0.0",
        host_type="owned.local.fixture",
        runtime_id="python",
        runtime_version="3.11",
        capture_mode="recorded_offline",
        network_mode="off",
        raw_payload_policy="digests_only",
        producer_attestation="unattested",
        operational_authority="none",
    )


def _event(
    event_id: str,
    activity: str,
    *,
    parents: tuple[str, ...] = (),
    offset: int = 0,
    telemetry_state: str = "complete",
) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/owned-agent-host",
            "repository_sha": "e" * 40,
            "occurred_at": NOW + timedelta(microseconds=offset),
            "producer_id_hash": SHA_B,
            "producer_attestation": "unattested",
            "source_surface": "audit",
            "activity": activity,
            "entity_refs": (),
            "parent_event_ids": parents,
            "data_envelope_ref": SHA_C,
            "authority_envelope_ref": None,
            "telemetry_state": telemetry_state,
            "operational_authority": "none",
        }
    )


def _recording(
    activity: str = PASS_ACTIVITY,
    *,
    pattern_id: str = V1_PATTERN_IDS[0],
    terminal_status: str = "completed",
    terminal_parents: tuple[str, ...] = (SHA_A,),
    extra_after: bool = False,
) -> AgentHostRecordingV1:
    events = [
        _event(SHA_A, "agent_host.received"),
        _event(SHA_D, activity, parents=terminal_parents, offset=1),
    ]
    if extra_after:
        events.append(_event("f" * 64, "agent_host.closed", parents=(SHA_D,), offset=2))
    return build_agent_host_recording_v1(
        pattern_id=pattern_id,
        host=_host(),
        events=tuple(events),
        terminal_status=terminal_status,  # type: ignore[arg-type]
    )


def test_ruleset_exactly_covers_frozen_corpus_metadata() -> None:
    ruleset = agent_host_evaluation_ruleset_v1()
    assert tuple(rule.pattern_id for rule in ruleset.rules) == V1_PATTERN_IDS
    assert [
        (rule.pattern_id, rule.category, rule.severity, rule.broke_at) for rule in ruleset.rules
    ] == [
        (entry.pattern_id, entry.category, entry.severity, entry.broke_at)
        for entry in corpus_manifest()
    ]
    assert len(json.loads(encode_agent_host_evaluation_ruleset_v1())["rules"]) == 24
    assert ruleset.operational_authority == "none"

    with pytest.raises(ValidationError, match="ruleset_sha256"):
        AgentHostEvaluationRulesetV1.model_validate(
            {**ruleset.model_dump(mode="python"), "ruleset_sha256": "f" * 64}
        )


@pytest.mark.parametrize("pattern_id", V1_PATTERN_IDS)
@pytest.mark.parametrize(
    ("activity", "outcome", "reason"),
    [
        (PASS_ACTIVITY, "pass", "terminal.boundary_preserved"),
        (FINDING_ACTIVITY, "finding", "terminal.boundary_violated"),
    ],
)
def test_all_frozen_patterns_receive_deterministic_decisive_outcomes(
    pattern_id: str,
    activity: str,
    outcome: str,
    reason: str,
) -> None:
    evaluation = evaluate_agent_host_recording_v1(_recording(activity, pattern_id=pattern_id))
    assert evaluation.pattern_id == pattern_id
    assert evaluation.outcome == outcome
    assert evaluation.reason_codes == (reason,)
    assert evaluation.terminal_event_id == SHA_D
    assert evaluation.producer_attestation == "unattested"
    assert evaluation.outcome_scope == "recording_contract_only_not_security_certification"
    assert evaluation.operational_authority == "none"


@pytest.mark.parametrize(
    ("recording", "outcome", "reason", "has_terminal"),
    [
        (_recording(INCONCLUSIVE_ACTIVITY), "inconclusive", "terminal.inconclusive", True),
        (_recording(ADAPTER_ERROR_ACTIVITY), "adapter_error", "terminal.adapter_error", True),
        (
            build_agent_host_recording_v1(
                pattern_id=V1_PATTERN_IDS[0],
                host=_host(),
                events=(_event(SHA_A, "agent_host.received"),),
                terminal_status="completed",
            ),
            "inconclusive",
            "terminal.missing",
            False,
        ),
        (_recording(PASS_ACTIVITY, extra_after=True), "inconclusive", "terminal.not_final", True),
        (
            _recording(PASS_ACTIVITY, terminal_parents=()),
            "inconclusive",
            "terminal.disconnected",
            True,
        ),
    ],
)
def test_fail_closed_terminal_classification(
    recording: AgentHostRecordingV1,
    outcome: str,
    reason: str,
    has_terminal: bool,
) -> None:
    evaluation = evaluate_agent_host_recording_v1(recording)
    assert evaluation.outcome == outcome
    assert evaluation.reason_codes == (reason,)
    assert (evaluation.terminal_event_id is not None) is has_terminal


def test_multiple_terminal_events_are_inconclusive() -> None:
    recording = build_agent_host_recording_v1(
        pattern_id=V1_PATTERN_IDS[0],
        host=_host(),
        events=(
            _event(SHA_A, PASS_ACTIVITY),
            _event(SHA_D, FINDING_ACTIVITY, parents=(SHA_A,), offset=1),
        ),
        terminal_status="completed",
    )
    evaluation = evaluate_agent_host_recording_v1(recording)
    assert evaluation.outcome == "inconclusive"
    assert evaluation.reason_codes == ("terminal.multiple",)
    assert evaluation.terminal_event_id is None


@pytest.mark.parametrize(
    ("terminal_status", "outcome", "reason"),
    [
        ("adapter_error", "adapter_error", "recording.adapter_error"),
        ("inconclusive", "inconclusive", "recording.inconclusive"),
    ],
)
def test_recording_terminal_status_takes_precedence(
    terminal_status: str,
    outcome: str,
    reason: str,
) -> None:
    evaluation = evaluate_agent_host_recording_v1(
        _recording(PASS_ACTIVITY, terminal_status=terminal_status)
    )
    assert evaluation.outcome == outcome
    assert evaluation.reason_codes == (reason,)
    assert evaluation.terminal_event_id is None


def test_incomplete_telemetry_is_explicitly_inconclusive() -> None:
    recording = build_agent_host_recording_v1(
        pattern_id=V1_PATTERN_IDS[0],
        host=_host(),
        events=(
            _event(
                SHA_A,
                PASS_ACTIVITY,
                telemetry_state="incomplete",
            ),
        ),
        terminal_status="inconclusive",
    )
    evaluation = evaluate_agent_host_recording_v1(recording)
    assert evaluation.outcome == "inconclusive"
    assert evaluation.reason_codes == ("recording.telemetry_incomplete",)
    assert evaluation.terminal_event_id is None


def test_evaluation_round_trip_commitment_and_tamper_rejection() -> None:
    evaluation = evaluate_agent_host_recording_v1(_recording())
    encoded = encode_agent_host_evaluation_v1(evaluation)
    assert decode_agent_host_evaluation_v1(encoded) == evaluation
    assert commit_agent_host_evaluation_v1(evaluation).operational_authority == "none"

    values = evaluation.model_dump(mode="python")
    with pytest.raises(ValidationError, match="evaluation_id"):
        AgentHostEvaluationV1.model_validate({**values, "evaluation_id": "f" * 64})
    with pytest.raises(ValidationError, match="terminal reason"):
        AgentHostEvaluationV1.model_validate({**values, "terminal_event_id": None})
    with pytest.raises(ValidationError):
        AgentHostEvaluationV1.model_validate({**values, "operational_authority": "allow"})


def test_decoder_rejects_unknown_duplicate_and_noncanonical_json() -> None:
    encoded = encode_agent_host_evaluation_v1(evaluate_agent_host_recording_v1(_recording()))
    payload = json.loads(encoded)
    payload["raw_response"] = "forbidden"
    with pytest.raises(AgentHostEvaluationContractError, match="fields"):
        decode_agent_host_evaluation_v1(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
    duplicate = encoded.replace(
        b'{"broke_at"',
        b'{"schema_version":"agent-host-evaluation-v1.0","broke_at"',
        1,
    )
    with pytest.raises(AgentHostEvaluationContractError, match="duplicate"):
        decode_agent_host_evaluation_v1(duplicate)
    with pytest.raises(AgentHostEvaluationContractError, match="canonical"):
        decode_agent_host_evaluation_v1((json.dumps(json.loads(encoded), indent=2) + "\n").encode())


def test_cli_evaluates_offline_and_failure_output_is_safe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "recording.json"
    path.write_bytes(encode_agent_host_recording_v1(_recording(FINDING_ACTIVITY)))
    assert _main(["agent-host-evaluate", str(path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "finding"
    assert payload["operational_authority"] == "none"

    bad = tmp_path / "sensitive-looking-name-token-123.json"
    bad.write_text('{"raw_prompt":"do not print me"}', encoding="utf-8")
    assert _main(["agent-host-evaluate", str(bad)]) == 1
    output = capsys.readouterr().out
    assert output == "Error: invalid Agent Host V1 evaluation input\n"
    assert bad.name not in output
    assert "raw_prompt" not in output


def test_schema_manifest_ruleset_and_fixtures_are_content_bound() -> None:
    manifest_path = ROOT / "schemas" / "agent-host-evaluation.v1.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "agent-host-evaluation-contract-manifest-v1.0"
    assert manifest["ruleset"]["pattern_count"] == 24
    assert manifest["evidence_class"] == "deterministic_rule_derived_unattested_observation"
    assert manifest["outcome_scope"] == "recording_contract_only_not_security_certification"
    assert manifest["operational_authority"] == "none"
    for section in (
        "evaluation_schema",
        "ruleset_schema",
        "ruleset",
        "recording_contract",
        "validator",
        "cli",
        "fixture_runner",
    ):
        item = manifest[section]
        assert item["sha256"] == hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest()
    for item in manifest["fixtures"]:
        content = (ROOT / item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(content).hexdigest()
        if item["expected"] == "accept":
            decode_agent_host_evaluation_v1(content)
        else:
            with pytest.raises(AgentHostEvaluationContractError):
                decode_agent_host_evaluation_v1(content)


def test_evaluator_has_no_live_transport_process_or_plugin_loader() -> None:
    source = (ROOT / "src/agentic_security_harness/agent_host_evaluator.py").read_text(
        encoding="utf-8"
    )
    forbidden = (
        "import socket",
        "import subprocess",
        "import requests",
        "import httpx",
        "import importlib",
        "entry_points(",
        "urlopen(",
    )
    assert all(token not in source for token in forbidden)
