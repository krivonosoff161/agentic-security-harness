"""Generate or verify Extension Operator Lifecycle V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.extension_lifecycle import (  # noqa: E402
    extension_lifecycle_v1_json_schemas,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in extension_lifecycle_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-extension-lifecycle-contract-manifest-v1.0",
        "contract_id": "harness-extension-operator-lifecycle-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "extension_lifecycle.py"
        ),
        "runtime_closure": [
            _bound_file(ROOT / path)
            for path in (
                "src/agentic_security_harness/__init__.py",
                "src/agentic_security_harness/cli.py",
                "src/agentic_security_harness/extension_distribution.py",
                "src/agentic_security_harness/extension_sdk.py",
                "src/agentic_security_harness/portfolio_contract.py",
                "src/agentic_security_harness/safe_io.py",
            )
        ],
        "generator": _bound_file(ROOT / "tools" / "extension_lifecycle_contracts.py"),
        "tests": _bound_file(ROOT / "tests" / "test_extension_lifecycle.py"),
        "documentation": _bound_file(ROOT / "docs" / "extension-operator-lifecycle.md"),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "component_manifest": _bound_file(ROOT / "component.yaml"),
        "inspection_semantics": "explicit_installed_distribution_metadata_only",
        "approval_semantics": "exact_reinspection_no_code_load",
        "disable_semantics": "metadata_only_application_enforcement_required",
        "rollback_semantics": "plan_only_construct_and_bind_target_required",
        "automatic_import": False,
        "automatic_download": False,
        "installed_state_discovery": False,
        "operator_authenticated": False,
        "sandboxed": False,
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "extension-lifecycle.v1.manifest.json"] = (
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
        raise ValueError(f"extension lifecycle contracts are stale: {', '.join(stale)}")


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
