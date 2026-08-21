from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_security_harness.agent_host_adapter import (
    AGENT_HOST_RECORDING_COMMITMENT_DOMAIN,
    MAX_AGENT_HOST_EVENTS,
    AgentHostContractError,
    AgentHostDescriptorV1,
    AgentHostInspectionV1,
    AgentHostRecordingCommitmentV1,
    AgentHostRecordingV1,
    StaticAgentHostAdapterV1,
    agent_host_recording_v1_json_schema,
    build_agent_host_recording_v1,
    commit_agent_host_recording_v1,
    decode_agent_host_recording_v1,
    encode_agent_host_recording_v1,
    inspect_agent_host_recording_v1,
    read_agent_host_recording_v1,
)
from agentic_security_harness.cli import _main
from agentic_security_harness.models import DefensivePattern
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    ObservationCommitmentV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
GIT_SHA = "e" * 40
NOW = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "agent-host-recording.v1.schema.json"
MANIFEST_PATH = ROOT / "schemas" / "agent-host-recording.v1.manifest.json"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "agent-host-recording-v1"


def _host(**updates: object) -> AgentHostDescriptorV1:
    values: dict[str, object] = {
        "schema_version": "agent-host-descriptor-v1.0",
        "adapter_id": "reference.record-replay",
        "adapter_version": "1.0.0",
        "host_type": "owned.local.fixture",
        "runtime_id": "python",
        "runtime_version": "3.11",
        "capture_mode": "recorded_offline",
        "network_mode": "off",
        "raw_payload_policy": "digests_only",
        "producer_attestation": "unattested",
        "operational_authority": "none",
    }
    values.update(updates)
    return AgentHostDescriptorV1.model_validate(values)


def _event(
    *,
    event_id: str = SHA_A,
    occurred_at: datetime = NOW,
    activity: str = "agent_host.received",
    source_surface: str = "agent",
    parents: tuple[str, ...] = (),
    telemetry_state: str = "complete",
) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/owned-agent-host",
            "repository_sha": GIT_SHA,
            "occurred_at": occurred_at,
            "producer_id_hash": SHA_B,
            "producer_attestation": "unattested",
            "source_surface": source_surface,
            "activity": activity,
            "entity_refs": (),
            "parent_event_ids": parents,
            "data_envelope_ref": SHA_C,
            "authority_envelope_ref": None,
            "telemetry_state": telemetry_state,
            "operational_authority": "none",
        }
    )


def _recording() -> AgentHostRecordingV1:
    events = (
        _event(),
        _event(
            event_id=SHA_D,
            occurred_at=NOW + timedelta(microseconds=1),
            activity="tool.requested",
            source_surface="tool",
            parents=(SHA_A,),
        ),
    )
    return build_agent_host_recording_v1(
        pattern_id=seed_patterns()[0].pattern_id,
        host=_host(),
        events=events,
        terminal_status="completed",
    )


def _pattern() -> DefensivePattern:
    return seed_patterns()[0]


def test_recording_round_trip_is_canonical_and_content_bound() -> None:
    recording = _recording()
    encoded = encode_agent_host_recording_v1(recording)

    assert decode_agent_host_recording_v1(encoded) == recording
    assert encode_agent_host_recording_v1(decode_agent_host_recording_v1(encoded)) == encoded
    assert encoded.endswith(b"\n")
    assert b"raw_prompt" not in encoded
    assert b"credential" not in encoded

    commitment = commit_agent_host_recording_v1(recording)
    assert commitment.domain == AGENT_HOST_RECORDING_COMMITMENT_DOMAIN
    assert commitment.operational_authority == "none"
    assert len(commitment.content_sha256) == 64
    assert len(commitment.commitment_sha256) == 64


def test_inspection_is_observation_only_and_safe() -> None:
    inspection = inspect_agent_host_recording_v1(_recording())

    assert inspection.event_count == 2
    assert inspection.source_surfaces == ("agent", "tool")
    assert inspection.activities == ("agent_host.received", "tool.requested")
    assert inspection.tool_activity_observed is True
    assert inspection.producer_attestation == "unattested"
    assert inspection.verdict_semantics == "observation_only_no_security_verdict"
    assert inspection.operational_authority == "none"
    assert not (
        {"pass", "fail", "finding", "allow"}
        & set(AgentHostInspectionV1.model_fields)
    )


def test_recording_rejects_identity_commitment_and_corpus_drift() -> None:
    recording = _recording()
    values = recording.model_dump(mode="python")

    with pytest.raises(ValidationError, match="recording_id"):
        AgentHostRecordingV1.model_validate({**values, "recording_id": "f" * 64})
    with pytest.raises(ValidationError, match="corpus manifest"):
        AgentHostRecordingV1.model_validate(
            {**values, "corpus_manifest_sha256": "f" * 64}
        )
    with pytest.raises(ValidationError, match="stable corpus"):
        AgentHostRecordingV1.model_validate({**values, "pattern_id": "unknown.pattern"})

    commitments = list(recording.event_commitments)
    original = commitments[0]
    commitments[0] = ObservationCommitmentV1.model_construct(
        **{
            **original.model_dump(mode="python"),
            "content_sha256": "f" * 64,
        }
    )
    with pytest.raises(ValidationError, match="commitment does not bind"):
        AgentHostRecordingV1.model_validate(
            {**values, "event_commitments": tuple(commitments)}
        )


def test_recording_rejects_graph_order_identity_and_telemetry_drift() -> None:
    recording = _recording()
    values = recording.model_dump(mode="python")
    first, second = recording.events

    with pytest.raises(ValidationError, match="parent events must precede"):
        build_agent_host_recording_v1(
            pattern_id=recording.pattern_id,
            host=recording.host,
            events=(second, first),
            terminal_status="completed",
        )

    other_identity = second.model_copy(update={"repository_sha": "f" * 40})
    with pytest.raises(ValidationError, match="project/repository identity"):
        build_agent_host_recording_v1(
            pattern_id=recording.pattern_id,
            host=recording.host,
            events=(first, other_identity),
            terminal_status="completed",
        )

    with pytest.raises(ValidationError, match="telemetry"):
        AgentHostRecordingV1.model_validate(
            {**values, "telemetry_state": "incomplete"}
        )

    incomplete = _event(telemetry_state="incomplete")
    with pytest.raises(ValidationError, match="completed recording"):
        build_agent_host_recording_v1(
            pattern_id=recording.pattern_id,
            host=recording.host,
            events=(incomplete,),
            terminal_status="completed",
        )


def test_decoder_rejects_unknown_duplicate_noncanonical_and_raw_fields() -> None:
    encoded = encode_agent_host_recording_v1(_recording())
    payload = json.loads(encoded)

    payload["raw_prompt"] = "synthetic but forbidden"
    with pytest.raises(AgentHostContractError, match="fields"):
        decode_agent_host_recording_v1(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )

    duplicate = encoded.replace(
        b'{"corpus_manifest_sha256"',
        b'{"schema_version":"agent-host-recording-v1.0","corpus_manifest_sha256"',
        1,
    )
    with pytest.raises(AgentHostContractError, match="duplicate"):
        decode_agent_host_recording_v1(duplicate)

    pretty = (json.dumps(json.loads(encoded), indent=2, sort_keys=True) + "\n").encode()
    with pytest.raises(AgentHostContractError, match="canonical"):
        decode_agent_host_recording_v1(pretty)


def test_commitment_and_descriptor_cannot_mint_authority_or_attestation() -> None:
    with pytest.raises(ValidationError):
        _host(operational_authority="allow")
    with pytest.raises(ValidationError):
        _host(producer_attestation="verified")
    with pytest.raises(ValidationError):
        _host(raw_payload_policy="retain_all")

    commitment = commit_agent_host_recording_v1(_recording())
    with pytest.raises(ValidationError, match="does not bind"):
        AgentHostRecordingCommitmentV1.model_validate(
            {**commitment.model_dump(), "commitment_sha256": "f" * 64}
        )


def test_static_reference_adapter_never_fabricates_missing_patterns() -> None:
    recording = _recording()
    adapter = StaticAgentHostAdapterV1((recording,))

    assert adapter.collect(_pattern()) == recording
    assert adapter.descriptor == recording.host
    missing = seed_patterns()[1]
    with pytest.raises(AgentHostContractError, match="no recording"):
        adapter.collect(missing)
    with pytest.raises(AgentHostContractError, match="unique"):
        StaticAgentHostAdapterV1((recording, recording))


def test_reader_rejects_links_and_accepts_stable_regular_file(tmp_path: Path) -> None:
    recording_path = tmp_path / "recording.json"
    recording_path.write_bytes(encode_agent_host_recording_v1(_recording()))
    assert read_agent_host_recording_v1(recording_path) == _recording()

    hardlink_path = tmp_path / "hardlink.json"
    os.link(recording_path, hardlink_path)
    with pytest.raises(AgentHostContractError, match="single-link"):
        read_agent_host_recording_v1(recording_path)

    symlink_path = tmp_path / "symlink.json"
    try:
        symlink_path.symlink_to(recording_path)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    with pytest.raises(AgentHostContractError, match="link or reparse"):
        read_agent_host_recording_v1(symlink_path)


def test_schema_is_closed_and_cardinality_is_bounded() -> None:
    schema = agent_host_recording_v1_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["events"]["maxItems"] == MAX_AGENT_HOST_EVENTS
    assert schema["properties"]["event_commitments"]["maxItems"] == MAX_AGENT_HOST_EVENTS

    recording = _recording()
    values = recording.model_dump(mode="python")
    with pytest.raises(ValidationError, match="at most 2048"):
        AgentHostRecordingV1.model_validate(
            {
                **values,
                "events": recording.events * (MAX_AGENT_HOST_EVENTS + 1),
                "event_commitments": recording.event_commitments
                * (MAX_AGENT_HOST_EVENTS + 1),
            }
        )


def test_schema_manifest_and_fixtures_are_content_bound() -> None:
    assert json.loads(SCHEMA_PATH.read_text(encoding="utf-8")) == (
        agent_host_recording_v1_json_schema()
    )
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == (
        "agent-host-recording-contract-manifest-v1.0"
    )
    assert manifest["contract_id"] == "agent-host-recording-v1.0"
    assert manifest["verdict_semantics"] == (
        "observation_only_no_security_verdict"
    )
    assert manifest["operational_authority"] == "none"
    assert manifest["schema_sha256"] == hashlib.sha256(
        SCHEMA_PATH.read_bytes()
    ).hexdigest()
    for section in ("validator", "cli", "fixture_runner"):
        bound_path = ROOT / manifest[section]["path"]
        assert manifest[section]["sha256"] == hashlib.sha256(
            bound_path.read_bytes()
        ).hexdigest()

    expected_paths = sorted(
        path.relative_to(ROOT).as_posix() for path in FIXTURE_ROOT.rglob("*.json")
    )
    assert sorted(item["path"] for item in manifest["fixtures"]) == expected_paths
    for item in manifest["fixtures"]:
        fixture = ROOT / item["path"]
        content = fixture.read_bytes()
        assert item["sha256"] == hashlib.sha256(content).hexdigest()
        if item["expected"] == "accept":
            decode_agent_host_recording_v1(content)
        else:
            with pytest.raises(AgentHostContractError):
                decode_agent_host_recording_v1(content)


def test_public_module_has_no_live_transport_or_plugin_loader() -> None:
    source = Path("src/agentic_security_harness/agent_host_adapter.py").read_text(
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


def test_cli_inspects_recording_without_executing_host(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "recording.json"
    path.write_bytes(encode_agent_host_recording_v1(_recording()))

    assert _main(["agent-host-inspect", str(path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "agent-host-inspection-v1.0"
    assert payload["verdict_semantics"] == "observation_only_no_security_verdict"
    assert payload["operational_authority"] == "none"


def test_cli_failure_does_not_echo_untrusted_path_or_bytes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "sensitive-looking-name-token-123.json"
    path.write_text('{"raw_prompt":"do not print me"}', encoding="utf-8")

    assert _main(["agent-host-inspect", str(path)]) == 1
    output = capsys.readouterr().out
    assert output == "Error: invalid Agent Host V1 recording\n"
    assert path.name not in output
    assert "raw_prompt" not in output
