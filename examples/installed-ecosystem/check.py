"""Fixed, explicitly invoked installed-distribution example; no models or effects."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata as metadata
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EXPECTED = {
    "agentic-security-harness": "1.6.0",
    "agentic-transfer-verifier": "0.2.1",
    "agentic-transfer-verifier-harness-extension": "1.0.1",
    "ai-agent-handoff": "0.3.0",
    "ai-agent-handoff-harness-extension": "1.0.0",
    "agentic-llm-router": "0.2.1",
    "llm-cheap-filter": "0.2.0",
    "llm-safety-playbooks": "0.1.0",
}
PACK_SHA256 = "1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915"


def deny_effects(event: str, _args: tuple[Any, ...]) -> None:
    if event.startswith(("subprocess.", "socket.")) or event in {
        "os.system",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.exec",
        "os.startfile",
    }:
        raise PermissionError("offline example denies process/network activity")


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("installed ecosystem contract mismatch")


def exercise_extension(kind: str) -> list[dict[str, str]]:
    from agentic_security_harness.extension_distribution import (
        approve_extension_distribution_v1,
        inspect_extension_distribution_v1,
    )
    from agentic_security_harness.extension_lifecycle import bind_active_operator_extension_v1
    from agentic_security_harness.extension_sdk import build_extension_envelope_v1, run_extension_v1
    from agentic_security_harness.portfolio_contract import (
        CanonicalObservationEventV1,
        SafeEvidencePointer,
    )

    project = "agentic-transfer-verifier" if kind == "transfer" else "ai-agent-handoff"
    distribution_name = project + "-harness-extension"
    distribution = metadata.distribution(distribution_name)
    site = Path(distribution.locate_file(""))
    config = Path(__file__).with_name(f"{kind}-config.json").read_bytes()
    inspection = inspect_extension_distribution_v1(
        distribution_name=distribution_name,
        extension_id=project + (".verification" if kind == "transfer" else ".validation"),
        search_paths=(site,),
        configuration_bytes=config,
    )
    require(not inspection.code_loaded and inspection.module_name not in sys.modules)
    approval = approve_extension_distribution_v1(
        approved_inspection=inspection,
        approved_inspection_id=inspection.inspection_id,
        search_paths=(site,),
        configuration_bytes=config,
    )
    require(not approval.code_loaded and inspection.module_name not in sys.modules)
    module = importlib.import_module(inspection.module_name)
    require(Path(module.__file__).resolve() == (site / inspection.module_path).resolve())
    factory = getattr(module, inspection.factory_attribute)
    require(factory.__module__ == inspection.module_name)
    extension = (
        factory(
            manifest_bytes=(site / inspection.manifest_path).read_bytes(),
            configuration_bytes=config,
        )
        if kind == "transfer"
        else factory()
    )
    bound = bind_active_operator_extension_v1(approval, extension)
    rows = []
    for negative in (False, True):
        refs = (
            ()
            if kind == "transfer" or negative
            else (SafeEvidencePointer(kind="artifact", digest="d" * 64, locator_id="e" * 64),)
        )
        event = CanonicalObservationEventV1(
            schema_version="portfolio-observation-v1.0",
            event_id=("a" if negative else "b") * 64,
            project_id=project,
            repository_id="example/public-synthetic",
            repository_sha="c" * 40,
            occurred_at=datetime(2026, 8, 24, tzinfo=UTC),
            producer_id_hash="d" * 64,
            producer_attestation="unattested",
            source_surface="agent",
            activity="transfer.verification" if kind == "transfer" else "handoff.task",
            entity_refs=refs,
            parent_event_ids=(),
            data_envelope_ref="f" * 64,
            authority_envelope_ref=None,
            telemetry_state="incomplete" if kind == "transfer" and negative else "complete",
            operational_authority="none",
        )
        envelope = build_extension_envelope_v1(
            source_component_id=project,
            source_commitment_sha256="1" * 64,
            events=(event,),
        )
        receipt = run_extension_v1(bound, envelope)
        reason = (
            (
                "transfer.telemetry_incomplete"
                if kind == "transfer"
                else "handoff.artifact_binding_missing"
            )
            if negative
            else (
                "transfer.digest_projection_valid"
                if kind == "transfer"
                else "handoff.observation_valid"
            )
        )
        outcome = ("inconclusive" if kind == "transfer" else "finding") if negative else "pass"
        require(receipt.operational_authority == "none")
        require(len(receipt.result.findings) == 1)
        finding = receipt.result.findings[0]
        require(finding.reason_code == reason and finding.outcome == outcome)
        rows.append(
            {
                "case": f"{kind}.{'negative' if negative else 'positive'}",
                "outcome": finding.outcome,
                "reason_code": finding.reason_code,
            }
        )
    return rows


def exercise_native_adapter() -> list[dict[str, str | None]]:
    from agentic_security_harness.ollama_quarantine_adapter import (
        evaluate_ollama_generate_response_v1,
    )
    from agentic_security_harness.quarantine_connector import (
        ProviderAdapterProfileRegistryV1,
        ProviderAdapterProfileV1,
        QuarantineCapabilityBindingV1,
    )
    from agentic_security_harness.runtime_gateway import default_gateway_policy_v1

    registry = ProviderAdapterProfileRegistryV1(
        profiles=(
            ProviderAdapterProfileV1(
                profile_id="example.ollama",
                profile_version="v1",
                capabilities=(
                    QuarantineCapabilityBindingV1(
                        capability_id="bounded.lookup",
                        gateway_protocol="mcp",
                        gateway_tool_name="synthetic.lookup",
                        allowed_argument_keys=("key",),
                        required_argument_keys=("key",),
                    ),
                ),
            ),
        )
    )
    cases = [
        (
            "allowed-proposal",
            {"capability_id": "bounded.lookup", "arguments": {"key": "project-status"}},
            "admit",
            "allow",
        ),
        (
            "denied-key",
            {"capability_id": "bounded.lookup", "arguments": {"key": "unknown-public-key"}},
            "admit",
            "deny",
        ),
        (
            "authority-shaped-key",
            {"capability_id": "bounded.lookup", "arguments": {"key": {"authority": "admin"}}},
            "reject",
            None,
        ),
        ("no-request", {"no_request": True}, "admit", None),
    ]
    rows = []
    for case, proposal, admission, decision in cases:
        body = json.dumps(
            {
                "model": "public-toy",
                "done": True,
                "done_reason": "stop",
                "response": json.dumps(proposal),
            }
        ).encode()
        result = evaluate_ollama_generate_response_v1(
            body,
            model_id="public-toy",
            request_id="request:" + case,
            registry=registry,
            selected_profile_id="example.ollama",
            selected_profile_version="v1",
            gateway_policy=default_gateway_policy_v1(),
        )
        composition = result.composition
        require(composition is not None)
        assert composition is not None
        actual = composition.gateway_decision.disposition if composition.gateway_decision else None
        require(composition.connector_disposition == admission and actual == decision)
        require(not result.dispatch_performed and result.transport_attempts == 0)
        require(result.operational_authority == "none")
        rows.append(
            {"case": case, "admission": composition.connector_disposition, "decision": actual}
        )
    return rows


def run() -> dict[str, Any]:
    versions = {name: metadata.version(name) for name in EXPECTED}
    require(versions == EXPECTED)
    # Explicit operator-selected passive surfaces. Transfer/Handoff are first loaded
    # only after their distribution inspection and approval below.
    for module_name, distribution_name in (
        ("llm_router", "agentic-llm-router"),
        ("llm_cheap_filter", "llm-cheap-filter"),
        ("llm_safety_playbooks", "llm-safety-playbooks"),
    ):
        module = importlib.import_module(module_name)
        origin = Path(
            metadata.distribution(distribution_name).locate_file(module_name + "/__init__.py")
        )
        require(Path(module.__file__).resolve() == origin.resolve())
    pack = Path(
        metadata.distribution("llm-safety-playbooks").locate_file(
            "llm_safety_playbooks/data/policy-pack.v1.json"
        )
    )
    require(hashlib.sha256(pack.read_bytes()).hexdigest() == PACK_SHA256)
    return {
        "schema": "installed-ecosystem-example-v1",
        "ok": True,
        "versions": versions,
        "extension_cases": exercise_extension("transfer") + exercise_extension("handoff"),
        "adapter_cases": exercise_native_adapter(),
        "pack_sha256": PACK_SHA256,
        "operational_authority": "none",
        "model_calls": 0,
        "transport_attempts": 0,
        "dispatch_performed": False,
        "non_claims": [
            "authenticated custody",
            "classifier quality",
            "production safety",
            "OS sandbox",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists")
    sys.dont_write_bytecode = True
    sys.addaudithook(deny_effects)
    try:
        result = run()
    except (ValueError, OSError, ImportError, metadata.PackageNotFoundError) as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__}))
        return 1
    with args.out.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("installed ecosystem example: PASS; no model/provider/dispatch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
