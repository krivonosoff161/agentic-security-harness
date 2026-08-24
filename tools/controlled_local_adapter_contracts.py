"""Generate or verify controlled local adapter V1 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.controlled_local_adapter import (  # noqa: E402
    controlled_local_adapter_v1_json_schemas,
)
from agentic_security_harness.runtime_gateway import (  # noqa: E402
    default_gateway_policy_v1,
)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in controlled_local_adapter_v1_json_schemas().items()
    }
    manifest = {
        "schema_version": "harness-controlled-local-adapter-contract-manifest-v1.0",
        "contract_id": "harness-controlled-local-adapter-v1.0",
        "harness_api": "1",
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "controlled_local_adapter.py"
        ),
        "public_api": _bound_file(ROOT / "src" / "agentic_security_harness" / "__init__.py"),
        "provider_tool_adapter": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "provider_tool_adapters.py"
        ),
        "runtime_gateway": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "runtime_gateway.py"
        ),
        "gateway_policy_sha256": default_gateway_policy_v1().sha256(),
        "generator": _bound_file(ROOT / "tools" / "controlled_local_adapter_contracts.py"),
        "unit_tests": _bound_file(ROOT / "tests" / "test_controlled_local_adapter.py"),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "documentation": _bound_file(ROOT / "docs" / "controlled-local-adapter.md"),
        "transport": {
            "scheme": "http",
            "hosts": ["127.0.0.1", "::1"],
            "path": "/v1/responses",
            "dns": False,
            "proxy_environment": False,
            "redirects": False,
            "credentials": False,
            "caller_headers": False,
            "streaming": False,
            "deadline_scope": "monotonic_connect_send_read_and_all_retries",
            "cancellation_scope": "before_request_and_in_flight_transport_and_post_response",
            "response_content_type": "application/json",
            "response_content_length_required": True,
        },
        "tool_host": {
            "normalizer": "provider_tool_adapters.openai_responses",
            "policy_before_dispatch": True,
            "executors": ["synthetic.lookup", "synthetic.sha256"],
            "arbitrary_tools": False,
            "upstream_mcp": False,
            "replay_guard": "in_memory_digest_reservation_fail_closed_at_4096",
        },
        "model_identity": "opaque_operator_selected_token_no_vendor_attestation",
        "receipt_retention": "digest_counters_fixed_codes_only",
        "json_schema_scope": "closed_shape_only_semantic_validation_in_python",
        "provider_authenticated": False,
        "external_provider_calls": False,
        "operational_authority": "none",
    }
    schemas[ROOT / "schemas" / "controlled-local-adapter.v1.manifest.json"] = (
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
        raise ValueError(f"controlled local adapter contracts are stale: {', '.join(stale)}")


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
