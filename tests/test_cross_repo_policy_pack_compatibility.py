from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentic_security_harness.policy_pack_extension import (
    POLICY_PACK_SOURCE_COMMIT,
    POLICY_PACK_SOURCE_TREE,
    PolicyPackSignalsV1,
    build_policy_pack_signal_binding_v1,
    decode_policy_pack_v1,
    evaluate_policy_pack_binding_v1,
    reviewed_policy_pack_source_v1,
    verify_policy_pack_source_artifacts_v1,
)
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1

ROOT = Path(__file__).resolve().parents[1]


def _playbooks_root() -> Path:
    configured = os.environ.get("ASH_POLICY_PACK_ROOT")
    if not configured:
        pytest.skip("exact llm-safety-playbooks checkout is not configured")
    root = Path(configured)
    if not root.is_dir():
        pytest.fail("ASH_POLICY_PACK_ROOT is not a checked-out directory")
    return root


def _event() -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": "a" * 64,
            "project_id": "agentic-security-harness",
            "repository_id": "example/cross-repo-policy-fixture",
            "repository_sha": "b" * 40,
            "occurred_at": datetime(2026, 8, 24, 1, 0, tzinfo=UTC),
            "producer_id_hash": "c" * 64,
            "producer_attestation": "unattested",
            "source_surface": "agent",
            "activity": "agent.observed",
            "entity_refs": (),
            "parent_event_ids": (),
            "data_envelope_ref": "d" * 64,
            "authority_envelope_ref": None,
            "telemetry_state": "complete",
            "operational_authority": "none",
        }
    )


def test_exact_playbooks_source_identity_and_artifact_closure() -> None:
    root = _playbooks_root()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head == POLICY_PACK_SOURCE_COMMIT
    assert tree == POLICY_PACK_SOURCE_TREE

    pin = reviewed_policy_pack_source_v1()
    pack = verify_policy_pack_source_artifacts_v1(
        pack_bytes=(root / "contracts/policy-pack.v1.json").read_bytes(),
        pack_schema_bytes=(root / "contracts/policy-pack.v1.schema.json").read_bytes(),
        pack_manifest_bytes=(root / "contracts/policy-pack.v1.manifest.json").read_bytes(),
        component_manifest_bytes=(root / "component.yaml").read_bytes(),
        input_schema_bytes=(root / "contracts/policy-input-receipt.v1.schema.json").read_bytes(),
        output_schema_bytes=(
            root / "contracts/policy-evaluation-receipt.v1.schema.json"
        ).read_bytes(),
        pin=pin,
    )
    assert pack.pack_sha256 == pin.pack_sha256
    assert pin.operational_authority == "none"


def test_exact_source_fixture_has_deterministic_result_parity_without_source_execution() -> None:
    root = _playbooks_root()
    fixture_bytes = (
        root / "tests/fixtures/policy-pack-v1/valid/mixed-signals.json"
    ).read_bytes()
    fixture = json.loads(fixture_bytes)
    signals = PolicyPackSignalsV1.model_validate(fixture["signals"])
    event = _event()
    binding = build_policy_pack_signal_binding_v1(
        event,
        signals=signals,
        source_class="synthetic_fixture",
    )
    pack = decode_policy_pack_v1(
        (root / "contracts/policy-pack.v1.json").read_bytes(),
        expected_file_sha256=reviewed_policy_pack_source_v1().pack_file_sha256,
    )
    evaluation = evaluate_policy_pack_binding_v1(pack, binding, event)
    expected = [
        ("untrusted_instructions_detected", "present", "challenge"),
        ("secret_exposure_risk", "absent", "observe"),
        ("generated_resource_unverified", "unknown", "challenge"),
        ("git_change_control_unclear", "absent", "observe"),
        ("handoff_verification_incomplete", "present", "challenge"),
        ("research_authorization_unclear", "absent", "observe"),
        ("observation_metadata_invalid", "absent", "observe"),
    ]
    assert [
        (item.signal, item.signal_state, item.advisory_disposition)
        for item in evaluation.results
    ] == expected
    assert evaluation.overall_advisory_disposition == "challenge"
    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "21373b3b151b451baf8b71ab0a9dd9f8303e9ab6239301b59046dfec2b087040"
    )


def test_production_boundary_never_imports_or_executes_playbooks_code() -> None:
    source = ROOT / "src/agentic_security_harness/policy_pack_extension.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert all("playbook" not in name for name in imported)
    forbidden_calls = {
        "compile",
        "eval",
        "exec",
        "execfile",
        "import_module",
        "run",
        "Popen",
        "system",
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert calls.isdisjoint(forbidden_calls)
