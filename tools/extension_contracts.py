"""Generate or verify the closed Extension SDK V1 JSON Schemas."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.extension_sdk import extension_v1_json_schemas  # noqa: E402


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in extension_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-extension-contract-manifest-v1.0",
        "contract_id": "harness-extension-sdk-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "extension_sdk.py"
        ),
        "cli": _bound_file(ROOT / "src" / "agentic_security_harness" / "cli.py"),
        "generator": _bound_file(ROOT / "tools" / "extension_contracts.py"),
        "tests": _bound_file(ROOT / "tests" / "test_extension_sdk.py"),
        "execution_model": "explicit_in_process_not_sandboxed",
        "code_auto_discovery": False,
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "extension-sdk.v1.manifest.json"] = (
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
        raise ValueError(f"extension contract files are stale: {', '.join(stale)}")


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
