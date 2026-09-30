"""Fail the ancestry readiness gate on missing, skipped or failed required tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

LINK_NODES = (
    "tests/test_agent_host_adapter.py::test_reader_rejects_links_and_accepts_stable_regular_file",
    "tests/test_agent_host_workflow.py::test_bundle_symlinked_recording_directory_fails_before_read",
    "tests/test_corpus_packs.py::test_directory_loader_rejects_symlink_when_supported",
    "tests/test_run_manifest.py::test_validate_rejects_manifested_symbolic_link",
    "tests/test_run_manifest.py::test_validate_rejects_unmanifested_directory_link",
    "tests/test_safe_io.py::test_write_text_artifact_refuses_existing_symlink",
    "tests/test_safe_io.py::test_write_text_artifact_refuses_symlink_parent",
    "tests/test_trading_bot_stand.py::test_private_writer_rejects_parent_link_escape",
)
POSIX_NODE = (
    "tests/test_extension_distribution.py::"
    "test_posix_stable_read_retains_path_descriptor_identity_binding"
)
CHAIN_NODES = (
    "tests/test_ancestry_chain.py::"
    "test_exact_installed_chain_preserves_gateway_decision[project-status-completed-1]",
    "tests/test_ancestry_chain.py::"
    "test_exact_installed_chain_preserves_gateway_decision[unknown-public-key-denied-0]",
    "tests/test_ancestry_chain.py::"
    "test_malformed_or_scope_denied_zero_execution[{-scope0-rejected]",
    "tests/test_ancestry_chain.py::"
    "test_malformed_or_scope_denied_zero_execution[None-scope1-rejected]",
    "tests/test_ancestry_chain.py::test_no_request_is_typed_zero_execution",
)


def required_nodes(platform: str) -> tuple[str, ...]:
    if platform not in {"posix", "nt"}:
        raise ValueError("unsupported platform")
    return LINK_NODES + CHAIN_NODES + ((POSIX_NODE,) if platform == "posix" else ())


def verify_report(path: Path, platform: str) -> dict[str, object]:
    required = required_nodes(platform)
    raw = path.read_bytes()
    root = ET.fromstring(raw)
    if root.tag not in {"testsuites", "testsuite"}:
        raise ValueError("not a JUnit report")
    nodes: set[str] = set()
    for case in root.iter("testcase"):
        classname, name = case.get("classname"), case.get("name")
        if not classname or not name:
            raise ValueError("missing test identity")
        node = classname.replace(".", "/") + ".py::" + name
        if node in nodes:
            raise ValueError("duplicate test identity")
        nodes.add(node)
    if any(list(root.iter(tag)) for tag in ("skipped", "failure", "error")):
        raise ValueError("report contains skipped, failed or errored tests")
    if not set(required).issubset(nodes):
        raise ValueError("required test missing")
    return {
        "schema": "AncestryReadinessGate.v1",
        "status": "PASS",
        "platform": platform,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "passed_count": len(nodes),
        "required_passed": list(required),
        "skipped": 0,
        "model_calls": 0,
        "real_effects": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    result = verify_report(args.report, os.name)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {result['passed_count']} tests; all required nodes passed; zero skips")


if __name__ == "__main__":
    main()
