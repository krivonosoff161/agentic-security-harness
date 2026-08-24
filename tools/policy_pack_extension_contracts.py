"""Generate or verify exact-pinned Policy Pack Extension V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.policy_pack_extension import (  # noqa: E402
    policy_pack_extension_v1_json_schemas,
    reviewed_policy_pack_source_v1,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in policy_pack_extension_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-policy-pack-extension-contract-manifest-v1.0",
        "contract_id": "harness-policy-pack-extension-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "policy_pack_extension.py"
        ),
        "public_api": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "__init__.py"
        ),
        "cli": _bound_file(ROOT / "src" / "agentic_security_harness" / "cli.py"),
        "extension_sdk_contract": _bound_file(
            ROOT / "schemas" / "extension-sdk.v1.manifest.json"
        ),
        "component_manifest": _bound_file(ROOT / "component.yaml"),
        "generator": _bound_file(ROOT / "tools" / "policy_pack_extension_contracts.py"),
        "unit_tests": _bound_file(ROOT / "tests" / "test_policy_pack_extension.py"),
        "cli_authority_tests": _bound_file(ROOT / "tests" / "test_cli_authority.py"),
        "cross_repository_tests": _bound_file(
            ROOT / "tests" / "test_cross_repo_policy_pack_compatibility.py"
        ),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "documentation": _bound_file(ROOT / "docs" / "policy-pack-extension.md"),
        "reviewed_source": reviewed_policy_pack_source_v1().model_dump(mode="json"),
        "integration_model": "explicit_caller_supplied_exact_canonical_data_only_pack",
        "signal_model": "caller_supplied_content_free_canonical_observation_binding",
        "missing_pack_disposition": "inconclusive",
        "semantic_drift_disposition": "fail_closed",
        "verdict_semantics": "advisory_only_no_allow_or_enforcement",
        "code_auto_discovery": False,
        "companion_package_imports_at_runtime": False,
        "companion_code_execution": False,
        "network_access": False,
        "subprocess_access": False,
        "raw_content_included": False,
        "credentials_supported": False,
        "may_authorize_effects": False,
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "policy-pack-extension.v1.manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return schemas


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
        raise ValueError(f"policy-pack extension contracts are stale: {', '.join(stale)}")


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
