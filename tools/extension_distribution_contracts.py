"""Generate or verify Extension Distribution Discovery V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.extension_distribution import (  # noqa: E402
    extension_distribution_v1_json_schemas,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in extension_distribution_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-extension-distribution-contract-manifest-v1.0",
        "contract_id": "harness-extension-distribution-discovery-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "extension_distribution.py"
        ),
        "runtime_closure": [
            _bound_file(ROOT / "src" / "agentic_security_harness" / path)
            for path in (
                "__init__.py",
                "extension_sdk.py",
                "portfolio_contract.py",
                "safe_io.py",
            )
        ],
        "generator": _bound_file(ROOT / "tools" / "extension_distribution_contracts.py"),
        "tests": _bound_file(ROOT / "tests" / "test_extension_distribution.py"),
        "documentation": _bound_file(ROOT / "docs" / "extension-distribution-discovery.md"),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "discovery_semantics": "explicit_distribution_and_extension_id_only",
        "approval_semantics": "exact_reinspection_before_object_binding",
        "code_auto_discovery": False,
        "code_loaded_by_contract": False,
        "package_download": False,
        "signature_verified": False,
        "sandboxed": False,
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "extension-distribution.v1.manifest.json"] = (
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
        raise ValueError(f"extension distribution contracts are stale: {', '.join(stale)}")


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
