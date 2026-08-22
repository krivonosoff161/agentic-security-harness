"""Generate or verify the public Agent Host Evaluator V1 contract artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentic_security_harness.agent_host_adapter import (
    AgentHostDescriptorV1,
    build_agent_host_recording_v1,
)
from agentic_security_harness.agent_host_evaluator import (
    AGENT_HOST_EVALUATION_COMMITMENT_DOMAIN,
    MAX_AGENT_HOST_EVALUATION_BYTES,
    PASS_ACTIVITY,
    agent_host_evaluation_ruleset_v1,
    agent_host_evaluation_ruleset_v1_json_schema,
    agent_host_evaluation_v1_json_schema,
    encode_agent_host_evaluation_ruleset_v1,
    encode_agent_host_evaluation_v1,
    evaluate_agent_host_recording_v1,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1

EVALUATION_SCHEMA_PATH = "schemas/agent-host-evaluation.v1.schema.json"
RULESET_SCHEMA_PATH = "schemas/agent-host-evaluation-ruleset.v1.schema.json"
RULESET_PATH = "schemas/agent-host-evaluation-ruleset.v1.json"
MANIFEST_PATH = "schemas/agent-host-evaluation.v1.manifest.json"
RECORDING_MANIFEST_PATH = "schemas/agent-host-recording.v1.manifest.json"
VALIDATOR_PATH = "src/agentic_security_harness/agent_host_evaluator.py"
CLI_PATH = "src/agentic_security_harness/cli.py"
TEST_PATH = "tests/test_agent_host_evaluator.py"
FIXTURE_ROOT = "tests/fixtures/agent-host-evaluation-v1"


def _pretty_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _fixture_evaluation() -> bytes:
    now = datetime(2026, 8, 22, 9, 0, tzinfo=UTC)
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
    terminal = CanonicalObservationEventV1.model_validate(
        {
            **common,
            "event_id": "d" * 64,
            "occurred_at": now + timedelta(microseconds=1),
            "source_surface": "audit",
            "activity": PASS_ACTIVITY,
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
    recording = build_agent_host_recording_v1(
        pattern_id=seed_patterns()[0].pattern_id,
        host=host,
        events=(first, terminal),
        terminal_status="completed",
    )
    return encode_agent_host_evaluation_v1(evaluate_agent_host_recording_v1(recording))


def build_outputs(root: Path) -> dict[str, bytes]:
    evaluation_schema = _pretty_json(agent_host_evaluation_v1_json_schema())
    ruleset_schema = _pretty_json(agent_host_evaluation_ruleset_v1_json_schema())
    ruleset_bytes = encode_agent_host_evaluation_ruleset_v1()
    valid_bytes = _fixture_evaluation()
    valid_payload = json.loads(valid_bytes)
    unknown_bytes = (
        json.dumps(
            {**valid_payload, "raw_response": "forbidden"},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    duplicate_bytes = valid_bytes.replace(
        b'{"broke_at"',
        b'{"schema_version":"agent-host-evaluation-v1.0","broke_at"',
        1,
    )
    noncanonical_bytes = _pretty_json(valid_payload)
    fixture_outputs = {
        f"{FIXTURE_ROOT}/valid/pass.json": valid_bytes,
        f"{FIXTURE_ROOT}/invalid/unknown-field.json": unknown_bytes,
        f"{FIXTURE_ROOT}/invalid/duplicate-field.json": duplicate_bytes,
        f"{FIXTURE_ROOT}/invalid/noncanonical.json": noncanonical_bytes,
    }
    outputs = {
        EVALUATION_SCHEMA_PATH: evaluation_schema,
        RULESET_SCHEMA_PATH: ruleset_schema,
        RULESET_PATH: ruleset_bytes,
        **fixture_outputs,
    }
    fixtures = [
        {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "expected": "accept" if "/valid/" in path else "reject",
        }
        for path, content in fixture_outputs.items()
    ]
    recording_manifest = root / RECORDING_MANIFEST_PATH
    manifest = {
        "schema_version": "agent-host-evaluation-contract-manifest-v1.0",
        "contract_id": "agent-host-evaluation-v1.0",
        "owner": "agentic-security-harness",
        "canonicalization": "utf8-json-sort-keys-compact-lf-v1",
        "max_bytes": MAX_AGENT_HOST_EVALUATION_BYTES,
        "commitment_domain": AGENT_HOST_EVALUATION_COMMITMENT_DOMAIN,
        "producer_attestation": "unattested_only",
        "evidence_class": "deterministic_rule_derived_unattested_observation",
        "outcome_scope": "recording_contract_only_not_security_certification",
        "operational_authority": "none",
        "outcome_vocabulary": ["pass", "finding", "inconclusive", "adapter_error"],
        "terminal_activity_vocabulary": [
            "benchmark.boundary_preserved",
            "benchmark.boundary_violated",
            "benchmark.inconclusive",
            "benchmark.adapter_error",
        ],
        "evaluation_schema": {
            "path": EVALUATION_SCHEMA_PATH,
            "sha256": hashlib.sha256(evaluation_schema).hexdigest(),
        },
        "ruleset_schema": {
            "path": RULESET_SCHEMA_PATH,
            "sha256": hashlib.sha256(ruleset_schema).hexdigest(),
        },
        "ruleset": {
            "path": RULESET_PATH,
            "sha256": hashlib.sha256(ruleset_bytes).hexdigest(),
            "identity_sha256": agent_host_evaluation_ruleset_v1().ruleset_sha256,
            "pattern_count": len(agent_host_evaluation_ruleset_v1().rules),
        },
        "recording_contract": {
            "path": RECORDING_MANIFEST_PATH,
            "sha256": hashlib.sha256(recording_manifest.read_bytes()).hexdigest(),
        },
        "validator": {
            "path": VALIDATOR_PATH,
            "sha256": hashlib.sha256((root / VALIDATOR_PATH).read_bytes()).hexdigest(),
        },
        "cli": {
            "path": CLI_PATH,
            "command": "ash agent-host-evaluate",
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
            "producer_security_verdict_trust",
            "operational_authority_grant",
        ],
        "fixtures": fixtures,
    }
    outputs[MANIFEST_PATH] = _pretty_json(manifest)
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
            raise RuntimeError("agent-host evaluation output escaped repository root")
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise RuntimeError(f"generated evaluator artifact is stale: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
