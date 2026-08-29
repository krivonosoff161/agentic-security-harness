from __future__ import annotations

import ast
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentic_security_harness.extension_sdk import (
    ExtensionRunReceiptV1,
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
    receipt_auditor_v1_json_schemas,
    reviewed_receipt_sources_v1,
)

ROOT = Path(__file__).resolve().parents[1]
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
OCCURRED_AT = "2026-08-24T02:30:00.000000Z"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _domain_digest(domain: str, value: object) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + _canonical(value)).hexdigest()


def _router_payload() -> bytes:
    pricing = {
        "currency": "USD",
        "fx_rate_local_nanos_per_usd": 1_000_000_000,
        "fx_source": "identity",
        "fx_source_ref_sha256": hashlib.sha256(b"llm-router/fx-identity/v1\0USD=USD").hexdigest(),
        "input_rate_usd_nanos_per_million": 0,
        "output_rate_usd_nanos_per_million": 0,
        "pricing_source": "unpriced",
        "pricing_source_ref_sha256": None,
        "rounding_mode": "half_even",
    }
    receipt = {
        "attempts": [],
        "cost_local_nanos": 0,
        "cost_usd_nanos": 0,
        "currency": "USD",
        "fx_rate_local_nanos_per_usd": 1_000_000_000,
        "fx_source": "identity",
        "fx_source_ref_sha256": pricing["fx_source_ref_sha256"],
        "input_rate_usd_nanos_per_million": 0,
        "input_tokens": 0,
        "invoice_authoritative": False,
        "model_id_sha256": SHA_A,
        "occurred_at": OCCURRED_AT,
        "operational_authority": "none",
        "output_rate_usd_nanos_per_million": 0,
        "output_text_sha256": None,
        "output_tokens": 0,
        "pricing_ref_sha256": _domain_digest("llm-router/pricing-reference/v1", pricing),
        "pricing_source": "unpriced",
        "pricing_source_ref_sha256": None,
        "producer_id_hash": SHA_B,
        "provider_id": "openai",
        "request_payload_sha256": SHA_C,
        "response_payload_sha256": None,
        "role": "cheap",
        "rounding_mode": "half_even",
        "schema_version": "llm-router-invocation-receipt-v1.0",
        "terminal_reason_code": "router.missing_configuration",
        "terminal_status": "missing_configuration",
        "total_tokens": 0,
        "usage_provenance": "absent",
    }
    receipt["receipt_id"] = hashlib.sha256(
        b"llm-router/invocation-receipt/v1\0" + _canonical(receipt)
    ).hexdigest()
    return _canonical(receipt) + b"\n"


def _filter_payload() -> bytes:
    input_rows: list[dict[str, object]] = []
    receipt = {
        "escalation_policy_sha256": SHA_A,
        "input_batch_sha256": hashlib.sha256(
            b"llm-cheap-filter/triage-input-batch/v1\0" + _canonical(input_rows)
        ).hexdigest(),
        "may_lower_security_decision": False,
        "operational_authority": "none",
        "prefilter_configuration_sha256": SHA_B,
        "results": [],
        "schema_version": "llm-cheap-filter-triage-batch-receipt-v1.0",
        "summary": {
            "cancelled": 0,
            "cheap_drop": 0,
            "cheap_keep": 0,
            "chief": 0,
            "error": 0,
            "input_count": 0,
            "prefilter_drop": 0,
            "total_cost_usd": 0.0,
            "total_tokens": 0,
        },
        "verdict_semantics": "triage_accounting_only_no_security_verdict",
    }
    receipt["receipt_id"] = hashlib.sha256(
        b"llm-cheap-filter/triage-batch-receipt/v1\0" + _canonical(receipt)
    ).hexdigest()
    return _canonical(receipt) + b"\n"


def _event(payload: bytes, *, event_id: str = SHA_A) -> CanonicalObservationEventV1:
    decoded = json.loads(payload)
    receipt_sha = hashlib.sha256(payload).hexdigest()
    return CanonicalObservationEventV1(
        schema_version="portfolio-observation-v1.0",
        event_id=event_id,
        project_id="llm-router",
        repository_id="krivonosoff161/llm-router",
        repository_sha="87bc037b5c31cb110f7f253fb6bdcde0fa0c0f22",
        occurred_at=datetime.fromisoformat(OCCURRED_AT.replace("Z", "+00:00")),
        producer_id_hash=SHA_B,
        producer_attestation="unattested",
        source_surface="provider",
        activity="router.invocation_accounted",
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact",
                digest=decoded["receipt_id"],
                locator_id=receipt_sha,
            ),
        ),
        parent_event_ids=(),
        data_envelope_ref=receipt_sha,
        authority_envelope_ref=None,
        telemetry_state="complete",
        operational_authority="none",
    )


def _run(payload: bytes, event: CanonicalObservationEventV1 | None = None) -> ExtensionRunReceiptV1:
    event = event or _event(payload)
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
        source_commitment_sha256=SHA_C,
        events=(event,),
    )
    return run_extension_v1(extension, envelope)


def _filter_event(payload: bytes) -> CanonicalObservationEventV1:
    decoded = json.loads(payload)
    receipt_sha = hashlib.sha256(payload).hexdigest()
    return CanonicalObservationEventV1(
        schema_version="portfolio-observation-v1.0",
        event_id=SHA_C,
        project_id="llm-cheap-filter",
        repository_id="krivonosoff161/llm-cheap-filter",
        repository_sha="8d4dcf282a5408e04151ec550f69bc7c5065621f",
        occurred_at=datetime(2026, 8, 24, 2, 30, tzinfo=UTC),
        producer_id_hash=SHA_B,
        producer_attestation="unattested",
        source_surface="audit",
        activity="filter.triage_accounted",
        entity_refs=(
            SafeEvidencePointer(
                kind="artifact",
                digest=decoded["receipt_id"],
                locator_id=receipt_sha,
            ),
        ),
        parent_event_ids=(),
        data_envelope_ref=receipt_sha,
        authority_envelope_ref=None,
        telemetry_state="complete",
        operational_authority="none",
    )


def _run_filter(payload: bytes) -> ExtensionRunReceiptV1:
    event = _filter_event(payload)
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
        source_commitment_sha256=hashlib.sha256(payload).hexdigest(),
        events=(event,),
    )
    return run_extension_v1(extension, envelope)


def test_valid_router_accounting_never_becomes_pass_or_allow() -> None:
    run = _run(_router_payload())
    finding = run.result.findings[0]

    assert finding.outcome == "inconclusive"
    assert finding.severity == "none"
    assert finding.reason_code == "llm-router.accounting_bound_no_security_verdict"
    assert run.result.evidence_class == "producer_declared"
    assert run.result.operational_authority == "none"


def test_valid_filter_accounting_never_becomes_pass_or_allow() -> None:
    run = _run_filter(_filter_payload())
    finding = run.result.findings[0]

    assert finding.outcome == "inconclusive"
    assert finding.severity == "none"
    assert finding.reason_code == "llm-cheap-filter.accounting_bound_no_security_verdict"
    assert run.result.evidence_class == "external_unreviewed"
    assert run.result.operational_authority == "none"


def test_event_receipt_binding_drift_is_a_finding() -> None:
    payload = _router_payload()
    changed = _event(payload).model_copy(update={"data_envelope_ref": SHA_A})

    finding = _run(payload, changed).result.findings[0]

    assert finding.outcome == "finding"
    assert finding.reason_code == "llm-router.event_receipt_binding_drift"


def test_missing_receipt_evidence_is_inconclusive() -> None:
    payload = _router_payload()
    event = _event(payload, event_id=SHA_C)
    pin = build_receipt_source_pin_v1("llm-router")
    other_binding = build_receipt_artifact_binding_v1(
        pin=pin,
        event_id=SHA_A,
        payload=payload,
    )
    extension = RouterInvocationReceiptAuditExtensionV1(
        pin=pin,
        bindings=(other_binding,),
        receipt_payloads=(payload,),
    )
    envelope = build_extension_envelope_v1(
        source_component_id="llm-router",
        source_commitment_sha256=SHA_B,
        events=(event,),
    )

    finding = run_extension_v1(extension, envelope).result.findings[0]

    assert finding.outcome == "inconclusive"
    assert finding.reason_code == "llm-router.receipt_evidence_missing"


def test_malformed_and_accounting_drift_are_findings() -> None:
    payload = _router_payload()
    decoded = json.loads(payload)
    decoded["total_tokens"] = 1
    malformed = _canonical(decoded) + b"\n"
    event = _event(payload).model_copy(
        update={
            "data_envelope_ref": hashlib.sha256(malformed).hexdigest(),
            "entity_refs": (
                SafeEvidencePointer(
                    kind="artifact",
                    digest=decoded["receipt_id"],
                    locator_id=hashlib.sha256(malformed).hexdigest(),
                ),
            ),
        }
    )

    finding = _run(malformed, event).result.findings[0]

    assert finding.outcome == "finding"
    assert finding.reason_code == "llm-router.receipt_malformed"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("role", []),
        ("terminal_status", []),
        ("usage_provenance", []),
        ("pricing_source", []),
        (
            "attempts",
            [
                {
                    "attempt_index": 1,
                    "http_status": 200,
                    "outcome": [],
                    "reason_code": "provider.success",
                    "response_payload_sha256": SHA_A,
                }
            ],
        ),
    ),
)
def test_unhashable_router_semantic_values_are_sanitized_as_malformed(
    field: str, value: object
) -> None:
    payload = _router_payload()
    decoded = json.loads(payload)
    decoded[field] = value
    malformed = _canonical(decoded) + b"\n"

    binding = build_receipt_artifact_binding_v1(
        pin=build_receipt_source_pin_v1("llm-router"),
        event_id=SHA_A,
        payload=malformed,
    )

    assert binding.audit_state == "malformed"
    assert binding.reason_code == "llm-router.receipt_malformed"


def test_filter_negative_zero_and_unhashable_semantics_are_malformed() -> None:
    payload = _filter_payload()
    decoded = json.loads(payload)
    result = {
        "cost_usd": -0.0,
        "decision_sha256": SHA_A,
        "flagged": None,
        "input_index": 0,
        "input_sha256": SHA_B,
        "may_lower_security_decision": False,
        "operational_authority": "none",
        "reason_codes": ["prefilter.too_short"],
        "score": 0.0,
        "stage": [],
        "total_tokens": 0,
    }
    decoded["results"] = [result]
    malformed = _canonical(decoded) + b"\n"

    # The final source pin is added only after its manifest repair is exact-green.  The
    # private semantic parser must still reduce hostile JSON types to the closed error.
    from agentic_security_harness.receipt_auditors import (  # noqa: PLC0415
        ReceiptAuditContractError,
        _audit_filter_receipt,
    )

    with pytest.raises(ReceiptAuditContractError):
        _audit_filter_receipt(malformed)


def test_malformed_receipt_cannot_bypass_static_event_source_binding() -> None:
    payload = _router_payload()
    decoded = json.loads(payload)
    decoded["role"] = []
    malformed = _canonical(decoded) + b"\n"
    malformed_sha = hashlib.sha256(malformed).hexdigest()
    event = _event(payload).model_copy(
        update={
            "project_id": "attacker-project",
            "repository_id": "attacker/repository",
            "repository_sha": SHA_C,
            "data_envelope_ref": malformed_sha,
            "entity_refs": (),
        }
    )

    finding = _run(malformed, event).result.findings[0]

    assert finding.outcome == "finding"
    assert finding.reason_code == "llm-router.event_receipt_binding_drift"


def test_receipt_replay_is_rejected_before_extension_execution() -> None:
    payload = _router_payload()
    pin = build_receipt_source_pin_v1("llm-router")
    first = build_receipt_artifact_binding_v1(pin=pin, event_id=SHA_A, payload=payload)
    second = first.model_copy(update={"event_id": SHA_B})

    with pytest.raises(ValueError, match="replay"):
        RouterInvocationReceiptAuditExtensionV1(
            pin=pin,
            bindings=(first, second),
            receipt_payloads=(payload, payload),
        )


def test_source_pin_and_generated_schemas_are_closed() -> None:
    sources = {item["component_id"]: item for item in reviewed_receipt_sources_v1()}
    router = sources["llm-router"]
    assert router["commit"] == "87bc037b5c31cb110f7f253fb6bdcde0fa0c0f22"
    assert router["tree"] == "641f3fa10f10188eff250fa77264f25e0f51071c"
    assert router["component_manifest_sha256"] == (
        "940cf8536aefc5bb79b29c005c962140dc589eadfd40f8b88cd306cfd17c1596"
    )
    filter_source = sources["llm-cheap-filter"]
    assert filter_source["commit"] == "8d4dcf282a5408e04151ec550f69bc7c5065621f"
    assert filter_source["tree"] == "ed587047da7364ac3bce4cb269553abee9a5e4d9"
    assert filter_source["component_manifest_sha256"] == (
        "dec67b4b1e4a3f98b46d915e24cb063b502dc569f8343a502b7d613cdc580dcd"
    )
    assert all(
        schema["additionalProperties"] is False
        for schema in receipt_auditor_v1_json_schemas().values()
    )


def test_generated_manifest_binds_sources_and_forbids_execution_authority() -> None:
    manifest = json.loads(
        (ROOT / "schemas" / "receipt-auditors.v1.manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["reviewed_sources"] == list(reviewed_receipt_sources_v1())
    assert manifest["valid_accounting_disposition"] == ("inconclusive_no_security_verdict")
    assert manifest["missing_evidence_disposition"] == "inconclusive"
    assert manifest["companion_package_imports_at_runtime"] is False
    assert manifest["network_access"] is False
    assert manifest["subprocess_access"] is False
    assert manifest["injected_callables"] is False
    assert manifest["may_lower_security_decision"] is False
    assert manifest["operational_authority"] == "none"


def test_production_module_has_no_companion_import_or_execution_boundary() -> None:
    path = ROOT / "src" / "agentic_security_harness" / "receipt_auditors.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(
        name == "llm_router"
        or name.startswith("llm_router.")
        or name == "llm_cheap_filter"
        or name.startswith("llm_cheap_filter.")
        for name in imports
    )
    forbidden = {"socket", "subprocess", "importlib", "urllib", "httpx", "aiohttp"}
    assert not imports & forbidden
    assert "callable(" not in path.read_text(encoding="utf-8")


def test_router_timestamp_binding_uses_exact_utc_instant() -> None:
    payload = _router_payload()
    event = _event(payload).model_copy(
        update={"occurred_at": datetime(2026, 8, 24, 2, 30, 1, tzinfo=UTC)}
    )
    assert _run(payload, event).result.findings[0].outcome == "finding"
