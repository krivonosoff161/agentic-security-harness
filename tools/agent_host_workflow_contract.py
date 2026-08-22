"""Generate or verify the public Agent Host owned-workflow V1 artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentic_security_harness.agent_host_workflow import (
    MAX_AGENT_HOST_SUMMARY_BYTES,
    agent_host_run_summary_v1_json_schema,
    build_agent_host_quickstart_v1,
    encode_agent_host_summary_v1,
)

SCHEMA_PATH = "schemas/agent-host-run-summary.v1.schema.json"
MANIFEST_PATH = "schemas/agent-host-run-summary.v1.manifest.json"
RECORDING_MANIFEST_PATH = "schemas/agent-host-recording.v1.manifest.json"
EVALUATION_MANIFEST_PATH = "schemas/agent-host-evaluation.v1.manifest.json"
VALIDATOR_PATH = "src/agentic_security_harness/agent_host_workflow.py"
GENERIC_VALIDATOR_PATH = "src/agentic_security_harness/validation.py"
PUBLIC_API_PATH = "src/agentic_security_harness/__init__.py"
CLI_PATH = "src/agentic_security_harness/cli.py"
TEST_PATH = "tests/test_agent_host_workflow.py"
FIXTURE_ROOT = "tests/fixtures/agent-host-run-summary-v1"


def _pretty_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def build_outputs(root: Path) -> dict[str, bytes]:
    schema_bytes = _pretty_json(agent_host_run_summary_v1_json_schema())
    summary, _ = build_agent_host_quickstart_v1()
    valid_bytes = encode_agent_host_summary_v1(summary)
    valid_payload = json.loads(valid_bytes)
    unknown_bytes = (
        json.dumps(
            {**valid_payload, "raw_prompt": "forbidden"},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    duplicate_bytes = valid_bytes.replace(
        b'{"case_count"',
        b'{"schema_version":"agent-host-run-summary-v1.0","case_count"',
        1,
    )
    noncanonical_bytes = _pretty_json(valid_payload)
    fixture_outputs = {
        f"{FIXTURE_ROOT}/valid/quickstart.json": valid_bytes,
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
        "schema_version": "agent-host-run-summary-contract-manifest-v1.0",
        "contract_id": "agent-host-run-summary-v1.0",
        "owner": "agentic-security-harness",
        "canonicalization": "utf8-json-sort-keys-compact-lf-v1",
        "max_bytes": MAX_AGENT_HOST_SUMMARY_BYTES,
        "case_count": 48,
        "pattern_count": 24,
        "modes": ["protected", "vulnerable"],
        "network_mode": "off",
        "raw_payload_policy": "digests_only",
        "producer_attestation": "unattested_only",
        "outcome_scope": "synthetic_fixture_not_security_certification",
        "operational_authority": "none",
        "schema": {
            "path": SCHEMA_PATH,
            "sha256": hashlib.sha256(schema_bytes).hexdigest(),
        },
        "recording_contract": {
            "path": RECORDING_MANIFEST_PATH,
            "sha256": hashlib.sha256((root / RECORDING_MANIFEST_PATH).read_bytes()).hexdigest(),
        },
        "evaluation_contract": {
            "path": EVALUATION_MANIFEST_PATH,
            "sha256": hashlib.sha256((root / EVALUATION_MANIFEST_PATH).read_bytes()).hexdigest(),
        },
        "producer": {
            "path": VALIDATOR_PATH,
            "sha256": hashlib.sha256((root / VALIDATOR_PATH).read_bytes()).hexdigest(),
        },
        "bundle_validator": {
            "path": GENERIC_VALIDATOR_PATH,
            "sha256": hashlib.sha256((root / GENERIC_VALIDATOR_PATH).read_bytes()).hexdigest(),
        },
        "public_api": {
            "path": PUBLIC_API_PATH,
            "sha256": hashlib.sha256((root / PUBLIC_API_PATH).read_bytes()).hexdigest(),
        },
        "cli": {
            "path": CLI_PATH,
            "command": "ash agent-host-quickstart",
            "sha256": hashlib.sha256((root / CLI_PATH).read_bytes()).hexdigest(),
        },
        "fixture_runner": {
            "path": TEST_PATH,
            "sha256": hashlib.sha256((root / TEST_PATH).read_bytes()).hexdigest(),
        },
        "forbidden_capabilities": [
            "dynamic_plugin_loading",
            "arbitrary_host_process_execution",
            "network_transport",
            "provider_credentials",
            "raw_prompt_or_tool_payload_retention",
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
            raise RuntimeError("agent-host workflow contract output escaped repository root")
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise RuntimeError(f"generated workflow artifact is stale: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
