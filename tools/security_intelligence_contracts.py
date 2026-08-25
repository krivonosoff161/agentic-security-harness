"""Generate or verify the offline Security Intelligence V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.security_intelligence import (  # noqa: E402
    default_security_intelligence_source_registry_v1,
    encode_security_intelligence_contract_v1,
    security_intelligence_v1_json_schemas,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in security_intelligence_v1_json_schemas().items()
    }
    registry = encode_security_intelligence_contract_v1(
        default_security_intelligence_source_registry_v1()
    )
    registry_path = ROOT / "ecosystem" / "security-intelligence-sources.v1.json"
    generated: dict[Path, bytes] = {**schemas, registry_path: registry}
    manifest = {
        "schema_version": "harness-security-intelligence-contract-manifest-v1.0",
        "contract_id": "harness-security-intelligence-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "source_registry": {
            "path": registry_path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(registry).hexdigest(),
        },
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "security_intelligence.py"
        ),
        "extension_sdk_contract": _bound_file(
            ROOT / "schemas" / "extension-sdk.v1.manifest.json"
        ),
        "generator": _bound_file(ROOT / "tools" / "security_intelligence_contracts.py"),
        "unit_tests": _bound_file(ROOT / "tests" / "test_security_intelligence.py"),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "documentation": _bound_file(ROOT / "docs" / "security-intelligence-extension.md"),
        "collection_mode": "offline_snapshot_only",
        "model_interface": "provider_neutral_optional_outside_core",
        "raw_content_retained": False,
        "evidence_provenance": "external_unreviewed",
        "json_schema_scope": "closed_shape_only_semantic_validation_in_python",
        "operational_authority": "none",
    }
    generated[ROOT / "schemas" / "security-intelligence.v1.manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return generated


def _bound_file(path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def generate() -> None:
    for path, content in generated_contracts().items():
        path.write_bytes(content)


def check() -> None:
    stale = [
        path.relative_to(ROOT).as_posix()
        for path, expected in generated_contracts().items()
        if not path.is_file() or path.read_bytes() != expected
    ]
    if stale:
        raise ValueError(f"security-intelligence contracts are stale: {', '.join(stale)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("generate", "check"))
    args = parser.parse_args()
    if args.mode == "generate":
        generate()
    else:
        check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
