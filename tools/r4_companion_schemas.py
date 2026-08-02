"""Generate or verify the content-bound R4 companion contract schemas."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentic_security_harness.companion_contracts import r4_companion_json_schemas

SCHEMA_PATHS = {
    "portfolio-outcome-v1.0": "schemas/portfolio-outcome.v1.schema.json",
    "mcp-redaction-receipt-v1.0": "schemas/mcp-redaction-receipt.v1.schema.json",
    "portfolio-trajectory-accounting-v1.0": (
        "schemas/portfolio-trajectory-accounting.v1.schema.json"
    ),
    "portfolio-telemetry-manifest-v1.0": ("schemas/portfolio-telemetry-manifest.v1.schema.json"),
    "portfolio-coverage-expectation-v1.0": (
        "schemas/portfolio-coverage-expectation.v1.schema.json"
    ),
}
MANIFEST_PATH = "schemas/r4-companion-contracts.v1.manifest.json"
VALIDATOR_PATH = "src/agentic_security_harness/companion_contracts.py"
FIXTURE_PATH = "tests/fixtures/r4-companion-contracts/cases.json"
FIXTURE_RUNNER_PATH = "tests/test_companion_contracts.py"


def encoded_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def build_outputs(root: Path) -> dict[str, bytes]:
    schemas = r4_companion_json_schemas()
    outputs = {
        SCHEMA_PATHS[contract_id]: encoded_json(schema) for contract_id, schema in schemas.items()
    }
    manifest = {
        "schema_version": "r4-companion-contract-manifest-v1.0",
        "owner": "agentic-security-harness",
        "authority": "none",
        "observation_contract_unchanged": "portfolio-observation-v1.0",
        "schema_role": "shape_only_semantic_validation_requires_python_validator_and_fixtures",
        "validator": {
            "path": VALIDATOR_PATH,
            "sha256": hashlib.sha256((root / VALIDATOR_PATH).read_bytes()).hexdigest(),
        },
        "fixtures": [
            {
                "path": FIXTURE_PATH,
                "sha256": hashlib.sha256((root / FIXTURE_PATH).read_bytes()).hexdigest(),
                "verdict_semantics": "valid_must_accept_invalid_must_reject",
            }
        ],
        "fixture_runner": {
            "path": FIXTURE_RUNNER_PATH,
            "sha256": hashlib.sha256((root / FIXTURE_RUNNER_PATH).read_bytes()).hexdigest(),
        },
        "contracts": [
            {
                "contract_id": contract_id,
                "schema_path": SCHEMA_PATHS[contract_id],
                "schema_sha256": hashlib.sha256(outputs[SCHEMA_PATHS[contract_id]]).hexdigest(),
            }
            for contract_id in sorted(SCHEMA_PATHS)
        ],
        "forbidden_content": [
            "scientific_labels",
            "raw_mcp_arguments",
            "raw_mcp_output",
            "credentials",
            "operational_authority_grant",
        ],
    }
    outputs[MANIFEST_PATH] = encoded_json(manifest)
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
            raise RuntimeError("schema output escaped repository root")
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise RuntimeError(f"generated schema is stale: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
