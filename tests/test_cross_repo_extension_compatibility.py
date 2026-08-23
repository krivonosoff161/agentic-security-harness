"""Synthetic contract test against exact checked-out companion repository code."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness.companion_extensions import (
    COMPANION_PIN_V1,
    CompanionContractPinV1,
    HandoffMetadataExtensionV1,
    PlaybookGuidanceExtensionV1,
    TransferVerifierExtensionV1,
    build_handoff_metadata_evidence_v1,
    build_playbook_guidance_config_v1,
    build_transfer_verification_evidence_v1,
)
from agentic_security_harness.extension_sdk import (
    build_extension_envelope_v1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1


def _companion_root(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        pytest.skip(f"{variable} is required for exact cross-repository compatibility")
    root = Path(value).resolve()
    if not (root / "component.yaml").is_file():
        raise AssertionError(f"invalid companion root for {variable}")
    return root


def _git_commit(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout.strip()


def _lf_sha(path: Path) -> str:
    payload = path.read_bytes()
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise AssertionError(f"bare CR is forbidden in reviewed contract: {path.name}")
    return hashlib.sha256(normalized).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    ).hexdigest()


def _component_manifest_sha(root: Path) -> str:
    return _canonical_sha(json.loads((root / "component.yaml").read_text(encoding="utf-8")))


def _pin(
    root: Path,
    *,
    component_id: str,
    contract_id: str,
    contract_version: str,
    contract_sha256: str,
) -> CompanionContractPinV1:
    return CompanionContractPinV1(
        schema_version=COMPANION_PIN_V1,
        component_id=component_id,
        source_commit=_git_commit(root),
        component_manifest_sha256=_component_manifest_sha(root),
        contract_id=contract_id,
        contract_version=contract_version,
        contract_sha256=contract_sha256,
        contract_digest_semantics="sha256_lf_normalized_text_v1",
        verification="exact_public_git_reviewed",
        operational_authority="none",
    )


def _harness_event(value: object) -> CanonicalObservationEventV1:
    to_dict = getattr(value, "to_dict", None)
    if not callable(to_dict):
        raise AssertionError("companion observation lacks to_dict")
    return CanonicalObservationEventV1.model_validate(to_dict())


def _reviewed_source(component_id: str) -> dict[str, str]:
    manifest = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "companion-extensions.v1.manifest.json"
        ).read_text(encoding="utf-8")
    )
    return next(
        item for item in manifest["reviewed_sources"] if item["component_id"] == component_id
    )


def _preflight_source(root: Path, source: dict[str, str]) -> None:
    assert _git(root, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert _git_commit(root) == source["commit"]
    assert _component_manifest_sha(root) == source["component_manifest_sha256"]
    contract_path = root / source["contract_path"]
    assert contract_path.is_file()
    assert _lf_sha(contract_path) == source["contract_sha256"]
    remote = _git(root, "remote", "get-url", "origin").removesuffix(".git")
    assert remote.casefold() == source["repository"].casefold()


def test_exact_companion_producers_flow_through_extension_sdk() -> None:
    transfer_root = _companion_root("ASH_TRANSFER_ROOT")
    handoff_root = _companion_root("ASH_HANDOFF_ROOT")
    playbooks_root = _companion_root("ASH_PLAYBOOKS_ROOT")
    transfer_source = _reviewed_source("agentic-transfer-verifier")
    handoff_source = _reviewed_source("ai-agent-handoff")
    playbooks_source = _reviewed_source("llm-safety-playbooks")
    _preflight_source(transfer_root, transfer_source)
    _preflight_source(handoff_root, handoff_source)
    _preflight_source(playbooks_root, playbooks_source)
    assert not any(
        name == "agent_guard"
        or name.startswith("agent_guard.")
        or name == "agentic_transfer_verifier"
        or name.startswith("agentic_transfer_verifier.")
        for name in sys.modules
    )
    sys.path.insert(0, str(transfer_root / "src"))
    sys.path.insert(0, str(handoff_root / "src"))

    from agent_guard.handoff_metadata import (  # noqa: PLC0415
        HandoffAdapterContext,
        build_handoff_metadata,
        project_handoff_metadata,
    )
    from agentic_transfer_verifier.models import (  # noqa: PLC0415
        ProvenanceStep,
        TransferEnvelope,
    )
    from agentic_transfer_verifier.portfolio_adapter import (  # noqa: PLC0415
        TransferAdapterContext,
        project_transfer_envelope,
    )
    from agentic_transfer_verifier.verifier import verify_envelope  # noqa: PLC0415

    loaded_modules = {
        "agent_guard.handoff_metadata": handoff_root / "src",
        "agentic_transfer_verifier.models": transfer_root / "src",
        "agentic_transfer_verifier.portfolio_adapter": transfer_root / "src",
        "agentic_transfer_verifier.verifier": transfer_root / "src",
    }
    for module_name, expected_root in loaded_modules.items():
        module_path = Path(sys.modules[module_name].__file__ or "").resolve()
        assert module_path.is_relative_to(expected_root.resolve())

    now = datetime(2026, 8, 24, 2, 30, tzinfo=UTC)
    transfer_sha = _git_commit(transfer_root)
    assert transfer_source["commit"] == transfer_sha
    assert transfer_source["component_manifest_sha256"] == _component_manifest_sha(
        transfer_root
    )
    transfer = TransferEnvelope(
        envelope_id="cross-repo-transfer-001",
        producer="synthetic-producer",
        consumer="synthetic-consumer",
        payload_kind="task",
        trust_level="verified",
        authority_scope="none",
        payload={"artifact_sha256": "1" * 64},
        provenance=[
            ProvenanceStep(
                actor="synthetic-producer",
                action="created",
                source="owned-fixture",
                timestamp=now.isoformat(),
            )
        ],
        created_at=now.isoformat(),
    )
    report = verify_envelope(transfer).to_dict()
    projected = project_transfer_envelope(
        transfer,
        TransferAdapterContext(
            project_id="agentic-transfer-verifier",
            repository_id="krivonosoff161/agentic-transfer-verifier",
            repository_sha=transfer_sha,
            source_surface="agent",
            data_envelope_ref="2" * 64,
        ),
    )
    transfer_event = _harness_event(projected.observation)
    transfer_contract_sha = _lf_sha(
        transfer_root / "src" / "agentic_transfer_verifier" / "verifier.py"
    )
    assert transfer_source["contract_sha256"] == transfer_contract_sha
    transfer_evidence = build_transfer_verification_evidence_v1(
        report,
        projected.observation.to_dict(),
        source_contract_sha256=transfer_contract_sha,
    )
    assert transfer_evidence.event_id == transfer_event.event_id
    transfer_extension = TransferVerifierExtensionV1(
        pin=_pin(
            transfer_root,
            component_id="agentic-transfer-verifier",
            contract_id="transfer-verification-report",
            contract_version="0.1",
            contract_sha256=transfer_contract_sha,
        ),
        evidence=(transfer_evidence,),
    )
    transfer_receipt = run_extension_v1(
        transfer_extension,
        build_extension_envelope_v1(
            source_component_id="agentic-transfer-verifier",
            source_commitment_sha256="3" * 64,
            events=(transfer_event,),
        ),
    )
    assert transfer_receipt.result.findings[0].outcome == "pass"

    handoff_sha = _git_commit(handoff_root)
    assert handoff_source["commit"] == handoff_sha
    assert handoff_source["component_manifest_sha256"] == _component_manifest_sha(
        handoff_root
    )
    first_metadata = build_handoff_metadata(
        artifact_kind="task",
        artifact_bytes=b"synthetic task v1",
        sequence=0,
        created_at=now,
        producer_id_hash="4" * 64,
    )
    first_projected = project_handoff_metadata(
        first_metadata,
        b"synthetic task v1",
        HandoffAdapterContext(
            project_id="ai-agent-handoff",
            repository_id="krivonosoff161/ai-agent-handoff",
            repository_sha=handoff_sha,
            source_surface="agent",
            data_envelope_ref="5" * 64,
        ),
    )
    second_metadata = build_handoff_metadata(
        artifact_kind="task",
        artifact_bytes=b"synthetic task v2",
        sequence=1,
        created_at=now + timedelta(microseconds=1),
        producer_id_hash="4" * 64,
        parent_artifact_sha256=first_metadata.artifact_sha256,
    )
    second_projected = project_handoff_metadata(
        second_metadata,
        b"synthetic task v2",
        HandoffAdapterContext(
            project_id="ai-agent-handoff",
            repository_id="krivonosoff161/ai-agent-handoff",
            repository_sha=handoff_sha,
            source_surface="agent",
            data_envelope_ref="5" * 64,
        ),
        previous=first_metadata,
        previous_observation=first_projected.observation,
    )
    handoff_contract_sha = _lf_sha(
        handoff_root / "contracts" / "handoff-metadata.v1.schema.json"
    )
    assert handoff_source["contract_sha256"] == handoff_contract_sha
    handoff_evidence = tuple(
        build_handoff_metadata_evidence_v1(
            metadata.to_dict(), source_contract_sha256=handoff_contract_sha
        )
        for metadata in (first_metadata, second_metadata)
    )
    handoff_events = tuple(
        _harness_event(item.observation) for item in (first_projected, second_projected)
    )
    assert tuple(item.event_id for item in handoff_evidence) == tuple(
        item.event_id for item in handoff_events
    )
    handoff_extension = HandoffMetadataExtensionV1(
        pin=_pin(
            handoff_root,
            component_id="ai-agent-handoff",
            contract_id="handoff-metadata",
            contract_version="1.0",
            contract_sha256=handoff_contract_sha,
        ),
        evidence=handoff_evidence,
    )
    handoff_receipt = run_extension_v1(
        handoff_extension,
        build_extension_envelope_v1(
            source_component_id="ai-agent-handoff",
            source_commitment_sha256="6" * 64,
            events=handoff_events,
        ),
    )
    assert [finding.outcome for finding in handoff_receipt.result.findings] == [
        "pass",
        "pass",
    ]

    guidance_mapping: dict[str, Any] = json.loads(
        (playbooks_root / "contracts" / "portfolio-observation-guidance.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert playbooks_source["commit"] == _git_commit(playbooks_root)
    assert playbooks_source["component_manifest_sha256"] == _component_manifest_sha(
        playbooks_root
    )
    guidance = build_playbook_guidance_config_v1(
        guidance_mapping,
        source_contract_sha256=_lf_sha(
            playbooks_root / "contracts" / "portfolio-observation-guidance.v1.json"
        ),
    )
    playbook_extension = PlaybookGuidanceExtensionV1(
        pin=_pin(
            playbooks_root,
            component_id="llm-safety-playbooks",
            contract_id="portfolio-observation-guidance",
            contract_version="1.0",
            contract_sha256=guidance.source_guidance_sha256,
        ),
        guidance=guidance,
    )
    playbook_receipt = run_extension_v1(
        playbook_extension,
        build_extension_envelope_v1(
            source_component_id="ai-agent-handoff",
            source_commitment_sha256="6" * 64,
            events=handoff_events,
        ),
    )
    assert all(
        finding.reason_code == "playbook.human_review_required"
        for finding in playbook_receipt.result.findings
    )
    assert playbook_receipt.result.operational_authority == "none"
