"""Generate or verify exact-pinned receipt auditor V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.receipt_auditors import (  # noqa: E402
    receipt_auditor_v1_json_schemas,
    reviewed_receipt_sources_v1,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in receipt_auditor_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-receipt-auditor-contract-manifest-v1.0",
        "contract_id": "harness-receipt-auditors-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "receipt_auditors.py"
        ),
        "extension_sdk_contract": _bound_file(ROOT / "schemas" / "extension-sdk.v1.manifest.json"),
        "generator": _bound_file(ROOT / "tools" / "receipt_auditor_contracts.py"),
        "unit_tests": _bound_file(ROOT / "tests" / "test_receipt_auditors.py"),
        "cross_repository_tests": _bound_file(
            ROOT / "tests" / "test_cross_repo_receipt_compatibility.py"
        ),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "documentation": _bound_file(ROOT / "docs" / "receipt-auditor-extensions.md"),
        "reviewed_sources": list(reviewed_receipt_sources_v1()),
        "contract_digest_semantics": "sha256_lf_normalized_text_v1",
        "component_manifest_digest_semantics": "canonical_json_sha256_lf_v1",
        "json_schema_scope": "closed_shape_only_semantic_validation_in_python",
        "integration_model": "explicit_caller_supplied_canonical_receipt_bytes",
        "valid_accounting_disposition": "inconclusive_no_security_verdict",
        "missing_evidence_disposition": "inconclusive",
        "code_auto_discovery": False,
        "companion_package_imports_at_runtime": False,
        "network_access": False,
        "subprocess_access": False,
        "injected_callables": False,
        "may_lower_security_decision": False,
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "receipt-auditors.v1.manifest.json"] = (
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
        raise ValueError(f"receipt auditor contracts are stale: {', '.join(stale)}")


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
