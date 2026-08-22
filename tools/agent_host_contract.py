"""Generate or verify the public Agent Host Adapter V1 contract artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentic_security_harness.agent_host_adapter import (
    AGENT_HOST_RECORDING_COMMITMENT_DOMAIN,
    MAX_AGENT_HOST_EVENTS,
    MAX_AGENT_HOST_RECORDING_BYTES,
    AgentHostDescriptorV1,
    agent_host_recording_v1_json_schema,
    build_agent_host_recording_v1,
    encode_agent_host_recording_v1,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1

SCHEMA_PATH = "schemas/agent-host-recording.v1.schema.json"
MANIFEST_PATH = "schemas/agent-host-recording.v1.manifest.json"
VALIDATOR_PATH = "src/agentic_security_harness/agent_host_adapter.py"
CLI_PATH = "src/agentic_security_harness/cli.py"
TEST_PATH = "tests/test_agent_host_adapter.py"
FIXTURE_ROOT = "tests/fixtures/agent-host-recording-v1"


def _encoded_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _fixture_recording() -> bytes:
    now = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)
    common: dict[str, object] = {
        "schema_version": "portfolio-observation-v1.0",
        "project_id": "agentic-security-harness",
        "repository_id": "example/owned-agent-host",
        "repository_sha": "e" * 40,
        "producer_id_hash": "b" * 64,
        "producer_attestation": "unattested",
        "entity_refs": (),
        "data_envelope_ref": "c" * 64,
        "authority_envelope_ref": None,
        "telemetry_state": "complete",
        "operational_authority": "none",
    }
    first = CanonicalObservationEventV1.model_validate(
        {
            **common,
            "event_id": "a" * 64,
            "occurred_at": now,
            "source_surface": "agent",
            "activity": "agent_host.received",
            "parent_event_ids": (),
        }
    )
    second = CanonicalObservationEventV1.model_validate(
        {
            **common,
            "event_id": "d" * 64,
            "occurred_at": now + timedelta(microseconds=1),
            "source_surface": "tool",
            "activity": "tool.requested",
            "parent_event_ids": ("a" * 64,),
        }
    )
    host = AgentHostDescriptorV1(
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
    return encode_agent_host_recording_v1(
        build_agent_host_recording_v1(
            pattern_id=seed_patterns()[0].pattern_id,
            host=host,
            events=(first, second),
            terminal_status="completed",
        )
    )


def build_outputs(root: Path) -> dict[str, bytes]:
    schema_bytes = _encoded_json(agent_host_recording_v1_json_schema())
    valid_bytes = _fixture_recording()
    valid_payload = json.loads(valid_bytes)
    unknown_payload = {**valid_payload, "raw_prompt": "forbidden"}
    unknown_bytes = (
        json.dumps(
            unknown_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    duplicate_bytes = valid_bytes.replace(
        b'{"corpus_manifest_sha256"',
        b'{"schema_version":"agent-host-recording-v1.0","corpus_manifest_sha256"',
        1,
    )
    noncanonical_bytes = _encoded_json(valid_payload)
    fixture_outputs = {
        f"{FIXTURE_ROOT}/valid/minimal.json": valid_bytes,
        f"{FIXTURE_ROOT}/invalid/unknown-field.json": unknown_bytes,
        f"{FIXTURE_ROOT}/invalid/duplicate-field.json": duplicate_bytes,
        f"{FIXTURE_ROOT}/invalid/noncanonical.json": noncanonical_bytes,
    }
    outputs = {SCHEMA_PATH: schema_bytes, **fixture_outputs}
    fixtures = [
        {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "expected": "accept" if "/valid/" in path else "reject",
        }
        for path, content in fixture_outputs.items()
    ]
    manifest = {
        "schema_version": "agent-host-recording-contract-manifest-v1.0",
        "contract_id": "agent-host-recording-v1.0",
        "owner": "agentic-security-harness",
        "canonicalization": "utf8-json-sort-keys-compact-utc-microseconds-lf-v1",
        "max_bytes": MAX_AGENT_HOST_RECORDING_BYTES,
        "max_events": MAX_AGENT_HOST_EVENTS,
        "commitment_domain": AGENT_HOST_RECORDING_COMMITMENT_DOMAIN,
        "producer_attestation": "unattested_only",
        "verdict_semantics": "observation_only_no_security_verdict",
        "operational_authority": "none",
        "schema_path": SCHEMA_PATH,
        "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
        "validator": {
            "path": VALIDATOR_PATH,
            "sha256": hashlib.sha256((root / VALIDATOR_PATH).read_bytes()).hexdigest(),
        },
        "cli": {
            "path": CLI_PATH,
            "command": "ash agent-host-inspect",
            "sha256": hashlib.sha256((root / CLI_PATH).read_bytes()).hexdigest(),
        },
        "fixture_runner": {
            "path": TEST_PATH,
            "sha256": hashlib.sha256((root / TEST_PATH).read_bytes()).hexdigest(),
        },
        "forbidden_capabilities": [
            "dynamic_plugin_loading",
            "host_process_execution",
            "network_transport",
            "provider_credentials",
            "security_verdict_from_producer",
            "operational_authority_grant",
        ],
        "fixtures": fixtures,
    }
    outputs[MANIFEST_PATH] = _encoded_json(manifest)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    for relative, content in build_outputs(root).items():
        path = (root / relative).resolve()
        if root not in path.parents:
            raise RuntimeError("agent-host contract output escaped repository root")
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise RuntimeError(f"generated contract artifact is stale: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
