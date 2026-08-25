"""Exact-source synthetic compatibility tests for receipt auditors.

Companion imports are intentionally test-only.  Production auditors accept canonical
bytes and cannot load or call these packages.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

from agentic_security_harness.extension_sdk import (
    build_extension_envelope_v1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    SafeEvidencePointer,
)
from agentic_security_harness.receipt_auditors import (
    CheapFilterReceiptAuditExtensionV1,
    RouterInvocationReceiptAuditExtensionV1,
    build_receipt_artifact_binding_v1,
    build_receipt_source_pin_v1,
    reviewed_receipt_sources_v1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _component_root(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        pytest.skip(f"{variable} is required for exact cross-repository compatibility")
    root = Path(value).resolve()
    if not (root / "component.yaml").is_file():
        raise AssertionError(f"invalid component root for {variable}")
    return root


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout.strip()


def _lf_sha(path: Path) -> str:
    payload = path.read_bytes().replace(b"\r\n", b"\n")
    if b"\r" in payload:
        raise AssertionError(f"bare CR in reviewed source: {path.name}")
    return hashlib.sha256(payload).hexdigest()


def _component_manifest_sha(root: Path) -> str:
    value = json.loads((root / "component.yaml").read_text(encoding="utf-8"))
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _source(component_id: str) -> dict[str, object]:
    return next(
        item for item in reviewed_receipt_sources_v1() if item["component_id"] == component_id
    )


def _load_exact_source_module(path: Path, name: str) -> ModuleType:
    """Load one reviewed dependency-free source file without package side effects."""

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load exact source module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _preflight(root: Path, source: dict[str, object]) -> None:
    assert _git(root, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert _git(root, "rev-parse", "HEAD") == source["commit"]
    assert _git(root, "show", "-s", "--format=%T", "HEAD") == source["tree"]
    assert _component_manifest_sha(root) == source["component_manifest_sha256"]
    assert _lf_sha(root / str(source["contract_path"])) == source["contract_sha256"]
    assert _lf_sha(root / str(source["implementation_path"])) == source["implementation_sha256"]
    if source["contract_manifest_path"] is not None:
        assert (
            _lf_sha(root / str(source["contract_manifest_path"]))
            == source["contract_manifest_sha256"]
        )
    remote = _git(root, "remote", "get-url", "origin").removesuffix(".git")
    assert remote.casefold() == str(source["repository"]).casefold()


def test_exact_router_receipt_flows_through_harness_auditor() -> None:
    root = _component_root("ASH_ROUTER_ROOT")
    source = _source("llm-router")
    _preflight(root, source)
    assert not any(name == "llm_router" or name.startswith("llm_router.") for name in sys.modules)
    router_module = _load_exact_source_module(
        root / str(source["implementation_path"]),
        "ash_exact_router_receipt_v1",
    )
    source_api = vars(router_module)
    InvocationAttemptV1 = source_api["InvocationAttemptV1"]
    build_invocation_receipt_v1 = source_api["build_invocation_receipt_v1"]
    encode_invocation_receipt_v1 = source_api["encode_invocation_receipt_v1"]
    module_path = Path(router_module.__file__ or "").resolve()
    assert module_path == (root / str(source["implementation_path"])).resolve()
    assert not any(name == "llm_router" or name.startswith("llm_router.") for name in sys.modules)
    occurred = datetime(2026, 8, 24, 2, 30, tzinfo=UTC)
    response_sha = hashlib.sha256(b"synthetic response envelope").hexdigest()
    output_sha = hashlib.sha256(b"synthetic output text").hexdigest()
    pricing_source_sha = hashlib.sha256(b"synthetic price table v1").hexdigest()
    receipt = build_invocation_receipt_v1(
        occurred_at=occurred.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        producer_id_hash=SHA_A,
        request_payload_sha256=SHA_B,
        provider_id="openai",
        model_id_sha256=SHA_C,
        role="cheap",
        attempts=(
            InvocationAttemptV1(
                attempt_index=1,
                outcome="success",
                http_status=200,
                reason_code="provider.success",
                response_payload_sha256=response_sha,
            ),
        ),
        terminal_status="success",
        response_payload_sha256=response_sha,
        output_text_sha256=output_sha,
        usage_provenance="provider_reported",
        input_tokens=100,
        output_tokens=25,
        total_tokens=125,
        pricing_source="operator_override",
        pricing_source_ref_sha256=pricing_source_sha,
        input_rate_usd_nanos_per_million=1_000_000_000,
        output_rate_usd_nanos_per_million=2_000_000_000,
    )
    payload = encode_invocation_receipt_v1(receipt)
    receipt_sha = hashlib.sha256(payload).hexdigest()
    event = CanonicalObservationEventV1(
        schema_version="portfolio-observation-v1.0",
        event_id=hashlib.sha256(b"synthetic router receipt event").hexdigest(),
        project_id="llm-router",
        repository_id="krivonosoff161/llm-router",
        repository_sha=str(source["commit"]),
        occurred_at=occurred,
        producer_id_hash=SHA_A,
        producer_attestation="unattested",
        source_surface="provider",
        activity="router.invocation_accounted",
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact",
                digest=receipt.receipt_id,
                locator_id=receipt_sha,
            ),
        ),
        parent_event_ids=(),
        data_envelope_ref=receipt_sha,
        authority_envelope_ref=None,
        telemetry_state="complete",
        operational_authority="none",
    )
    pin = build_receipt_source_pin_v1("llm-router")
    binding = build_receipt_artifact_binding_v1(
        pin=pin,
        event_id=event.event_id,
        payload=payload,
    )
    extension = RouterInvocationReceiptAuditExtensionV1(
        pin=pin,
        bindings=(binding,),
        receipt_payloads=(payload,),
    )
    envelope = build_extension_envelope_v1(
        source_component_id="llm-router",
        source_commitment_sha256=receipt_sha,
        events=(event,),
    )

    result = run_extension_v1(extension, envelope).result

    assert result.findings[0].outcome == "inconclusive"
    assert result.findings[0].reason_code == ("llm-router.accounting_bound_no_security_verdict")
    assert result.evidence_class == "producer_declared"
    assert result.operational_authority == "none"


def test_exact_filter_receipt_flows_through_harness_auditor() -> None:
    root = _component_root("ASH_FILTER_ROOT")
    source = _source("llm-cheap-filter")
    _preflight(root, source)
    assert not any(
        name == "llm_cheap_filter" or name.startswith("llm_cheap_filter.") for name in sys.modules
    )
    sys.path.insert(0, str(root / "src"))

    filter_module = importlib.import_module("llm_cheap_filter")
    source_api = vars(filter_module)
    EscalationPolicy = source_api["EscalationPolicy"]
    ItemResult = source_api["ItemResult"]
    PreFilter = source_api["PreFilter"]
    Report = source_api["Report"]
    build_triage_batch_receipt_v1 = source_api["build_triage_batch_receipt_v1"]
    encode_triage_batch_receipt_v1 = source_api["encode_triage_batch_receipt_v1"]
    escalation_policy_sha256 = source_api["escalation_policy_sha256"]
    prefilter_configuration_sha256 = source_api["prefilter_configuration_sha256"]

    module_path = Path(sys.modules["llm_cheap_filter.receipt"].__file__ or "").resolve()
    assert module_path.is_relative_to((root / "src").resolve())
    text = "synthetic cancelled triage item"
    prefilter = PreFilter()
    policy = EscalationPolicy()
    input_sha = hashlib.sha256(b"llm-cheap-filter/input/v1\0" + text.encode("utf-8")).hexdigest()
    report = Report(
        [
            ItemResult(
                text,
                "cancelled",
                0.6,
                reason="pipeline.cheap_callable_cancelled",
            )
        ],
        input_sha256s=(input_sha,),
        prefilter_configuration_sha256=prefilter_configuration_sha256(prefilter),
        escalation_policy_sha256=escalation_policy_sha256(policy),
    )
    receipt = build_triage_batch_receipt_v1(
        report,
        prefilter=prefilter,
        policy=policy,
    )
    payload = encode_triage_batch_receipt_v1(receipt)
    receipt_sha = hashlib.sha256(payload).hexdigest()
    event = CanonicalObservationEventV1(
        schema_version="portfolio-observation-v1.0",
        event_id=hashlib.sha256(b"synthetic filter receipt event").hexdigest(),
        project_id="llm-cheap-filter",
        repository_id="krivonosoff161/llm-cheap-filter",
        repository_sha=str(source["commit"]),
        occurred_at=datetime(2026, 8, 24, 2, 30, tzinfo=UTC),
        producer_id_hash=SHA_B,
        producer_attestation="unattested",
        source_surface="audit",
        activity="filter.triage_accounted",
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact",
                digest=receipt.receipt_id,
                locator_id=receipt_sha,
            ),
        ),
        parent_event_ids=(),
        data_envelope_ref=receipt_sha,
        authority_envelope_ref=None,
        telemetry_state="complete",
        operational_authority="none",
    )
    pin = build_receipt_source_pin_v1("llm-cheap-filter")
    binding = build_receipt_artifact_binding_v1(
        pin=pin,
        event_id=event.event_id,
        payload=payload,
    )
    extension = CheapFilterReceiptAuditExtensionV1(
        pin=pin,
        bindings=(binding,),
        receipt_payloads=(payload,),
    )
    envelope = build_extension_envelope_v1(
        source_component_id="llm-cheap-filter",
        source_commitment_sha256=receipt_sha,
        events=(event,),
    )

    result = run_extension_v1(extension, envelope).result

    assert result.findings[0].outcome == "inconclusive"
    assert result.findings[0].reason_code == (
        "llm-cheap-filter.accounting_bound_no_security_verdict"
    )
    assert result.evidence_class == "external_unreviewed"
    assert result.operational_authority == "none"
