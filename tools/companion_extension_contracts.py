"""Generate or verify the closed companion Extension V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.companion_extensions import (  # noqa: E402
    companion_extension_v1_json_schemas,
    reviewed_companion_sources_v1,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in companion_extension_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-companion-extension-contract-manifest-v1.0",
        "contract_id": "harness-companion-extensions-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "companion_extensions.py"
        ),
        "extension_sdk_contract": _bound_file(
            ROOT / "schemas" / "extension-sdk.v1.manifest.json"
        ),
        "generator": _bound_file(ROOT / "tools" / "companion_extension_contracts.py"),
        "unit_tests": _bound_file(ROOT / "tests" / "test_companion_extensions.py"),
        "cross_repository_tests": _bound_file(
            ROOT / "tests" / "test_cross_repo_extension_compatibility.py"
        ),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "documentation": _bound_file(ROOT / "docs" / "companion-extensions.md"),
        "integration_candidate": {
            "build_requirements_in": _bound_file(ROOT / "requirements" / "build.in"),
            "build_requirements_lock": _bound_file(ROOT / "requirements" / "build.txt"),
            "development_requirements_in": _bound_file(ROOT / "requirements" / "dev.in"),
            "development_requirements_lock": _bound_file(ROOT / "requirements" / "dev.txt"),
            "workflow": _bound_file(
                ROOT / ".github" / "workflows" / "ecosystem-integration.yml"
            ),
            "test": _bound_file(
                ROOT / "tests" / "test_ecosystem_integration_candidate.py"
            ),
            "documentation": _bound_file(
                ROOT / "docs" / "ecosystem-integration-candidate.md"
            ),
            "compatibility": _bound_file(ROOT / "ecosystem" / "compatibility.json"),
        },
        "reviewed_sources": list(reviewed_companion_sources_v1()),
        "contract_digest_semantics": "sha256_lf_normalized_text_v1",
        "json_schema_scope": "closed_shape_only_semantic_validation_in_python",
        "integration_model": "explicit_normalized_digest_bound_outputs",
        "code_auto_discovery": False,
        "companion_package_imports_at_runtime": False,
        "execution_model": "explicit_in_process_not_sandboxed",
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "companion-extensions.v1.manifest.json"] = (
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
        raise ValueError(f"companion extension contracts are stale: {', '.join(stale)}")


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
