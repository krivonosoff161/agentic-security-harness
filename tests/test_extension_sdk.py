from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.extension_contracts import generated_contracts

from agentic_security_harness.cli import _main
from agentic_security_harness.extension_sdk import (
    EXTENSION_ENVELOPE_V1,
    MAX_EXTENSION_PAYLOAD_BYTES,
    ExtensionContractError,
    ExtensionContractRefV1,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    StaticExtensionRegistryV1,
    build_extension_envelope_v1,
    decode_extension_manifest_v1,
    encode_extension_envelope_v1,
    encode_extension_manifest_v1,
    extension_manifest_sha256,
    extension_v1_json_schemas,
    read_extension_manifest_v1,
    run_extension_pipeline_v1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 24, 1, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SOURCE_COMMITMENT = "e" * 64
REPOSITORY_SHA = "f" * 40


def _manifest(extension_id: str = "example.telemetry-check") -> ExtensionManifestV1:
    return ExtensionManifestV1(
        schema_version="harness-extension-manifest-v1.0",
        extension_id=extension_id,
        extension_version="1.0.0",
        component_id="agentic-security-harness",
        implementation_sha256="1" * 64,
        configuration_sha256="2" * 64,
        harness_api="1",
        kind="check_extension",
        capabilities=("observation.read", "finding.emit"),
        consumes=(
            ExtensionContractRefV1(
                contract_id="portfolio-observation", version="1.0", required=True
            ),
        ),
        produces=(
            ExtensionContractRefV1(
                contract_id="extension-finding", version="1.0", required=True
            ),
        ),
        deterministic=True,
        network_mode="off",
        raw_data_policy="digests_only",
        execution_model="in_process_operator_approved_not_sandboxed",
        operational_authority="none",
    )


def _event(
    event_id: str = SHA_A,
    *,
    occurred_at: datetime = NOW,
    parent_event_ids: tuple[str, ...] = (),
    telemetry_state: str = "complete",
) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/owned-agent-host",
            "repository_sha": REPOSITORY_SHA,
            "occurred_at": occurred_at,
            "producer_id_hash": SHA_B,
            "producer_attestation": "unattested",
            "source_surface": "agent",
            "activity": "agent.observed",
            "entity_refs": (),
            "parent_event_ids": parent_event_ids,
            "data_envelope_ref": SHA_C,
            "authority_envelope_ref": None,
            "telemetry_state": telemetry_state,
            "operational_authority": "none",
        }
    )


def _envelope() -> ExtensionObservationEnvelopeV1:
    return build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256=SOURCE_COMMITMENT,
        events=(
            _event(),
            _event(
                SHA_D,
                occurred_at=NOW + timedelta(microseconds=1),
                parent_event_ids=(SHA_A,),
            ),
        ),
    )


class _CheckExtension:
    def __init__(self, extension_id: str = "example.telemetry-check") -> None:
        self.manifest = _manifest(extension_id)

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        complete = all(event.telemetry_state == "complete" for event in envelope.events)
        return (
            ExtensionFindingV1(
                check_id=f"{self.manifest.extension_id}.complete",
                outcome="pass" if complete else "finding",
                severity="none" if complete else "medium",
                reason_code="telemetry.complete" if complete else "telemetry.incomplete",
                evidence_event_ids=tuple(event.event_id for event in envelope.events),
            ),
        )


class _MutatingExtension(_CheckExtension):
    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        envelope.events[0].activity = "agent.mutated"
        return super().evaluate(envelope)


class _FailingExtension(_CheckExtension):
    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        raise RuntimeError("raw extension failure must not become a result")


class _UnknownEvidenceExtension(_CheckExtension):
    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        return (
            ExtensionFindingV1(
                check_id="example.unknown-evidence",
                outcome="inconclusive",
                severity="none",
                reason_code="evidence.missing",
                evidence_event_ids=("0" * 64,),
            ),
        )


class _ManifestDriftExtension(_CheckExtension):
    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        findings = super().evaluate(envelope)
        self.manifest = _manifest("example.replaced-manifest")
        return findings


class _InvalidFindingExtension(_CheckExtension):
    def evaluate(  # type: ignore[override]
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[dict[str, object], ...]:
        return ({"credential": "must-not-escape-through-validation"},)


def test_manifest_and_envelope_are_canonical_and_content_bound() -> None:
    manifest = _manifest()
    envelope = _envelope()

    assert json.loads(encode_extension_manifest_v1(manifest))["harness_api"] == "1"
    assert len(extension_manifest_sha256(manifest)) == 64
    assert envelope.schema_version == EXTENSION_ENVELOPE_V1
    assert len(envelope.envelope_id) == 64
    assert len(envelope.events) == len(envelope.event_commitments) == 2
    assert encode_extension_envelope_v1(envelope).endswith(b"\n")
    assert b"raw_prompt" not in encode_extension_envelope_v1(envelope)

    values = envelope.model_dump(mode="python")
    with pytest.raises(ValidationError, match="envelope_id"):
        type(envelope).model_validate({**values, "envelope_id": "0" * 64})


def test_manifest_decoder_reader_and_cli_are_fail_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    encoded = encode_extension_manifest_v1(_manifest())
    path = tmp_path / "extension.json"
    path.write_bytes(encoded)

    assert decode_extension_manifest_v1(encoded) == _manifest()
    assert read_extension_manifest_v1(path) == _manifest()
    assert _main(["extension-inspect", str(path), "--format", "json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["extension_id"] == _manifest().extension_id
    assert output["implementation_sha256"] == "1" * 64
    assert output["configuration_sha256"] == "2" * 64
    assert output["code_loaded"] is False
    assert output["operational_authority"] == "none"

    duplicate = encoded.replace(
        b'{"capabilities"',
        b'{"schema_version":"harness-extension-manifest-v1.0","capabilities"',
        1,
    )
    with pytest.raises(ExtensionContractError, match="duplicate"):
        decode_extension_manifest_v1(duplicate)
    with pytest.raises(ExtensionContractError, match="size"):
        decode_extension_manifest_v1(b"{" + b"x" * MAX_EXTENSION_PAYLOAD_BYTES)

    hardlink = tmp_path / "hardlink.json"
    os.link(path, hardlink)
    with pytest.raises(ExtensionContractError, match="single-link"):
        read_extension_manifest_v1(path)

    unsafe = tmp_path / "untrusted-token-name.json"
    unsafe.write_text('{"credential":"must-not-print"}', encoding="utf-8")
    assert _main(["extension-inspect", str(unsafe)]) == 1
    failure = capsys.readouterr().out
    assert failure == "Error: invalid Extension SDK V1 manifest\n"
    assert unsafe.name not in failure
    assert "credential" not in failure


def test_pipeline_runs_explicit_extensions_and_binds_every_transition() -> None:
    registry = StaticExtensionRegistryV1(
        (
            _CheckExtension("example.first"),
            _CheckExtension("example.second"),
        )
    )
    envelope = _envelope()
    receipt = run_extension_pipeline_v1(
        registry, ("example.first", "example.second"), envelope
    )

    assert receipt.input_envelope_id == envelope.envelope_id
    assert receipt.final_envelope_id == receipt.runs[-1].output_envelope.envelope_id
    assert receipt.runs[0].output_envelope.extension_chain == ("example.first",)
    assert receipt.runs[1].output_envelope.extension_chain == (
        "example.first",
        "example.second",
    )
    assert all(run.result.findings[0].outcome == "pass" for run in receipt.runs)
    assert all(run.result.operational_authority == "none" for run in receipt.runs)
    assert all(
        run.execution_semantics == "explicit_in_process_not_sandboxed"
        for run in receipt.runs
    )

    values = receipt.model_dump(mode="python")
    with pytest.raises(ValidationError, match="pipeline_id"):
        type(receipt).model_validate({**values, "pipeline_id": "0" * 64})


def test_runner_detects_mutation_failure_and_unknown_evidence() -> None:
    envelope = _envelope()

    with pytest.raises(ExtensionContractError, match="mutated"):
        run_extension_v1(_MutatingExtension(), envelope)
    assert envelope.events[0].activity == "agent.observed"

    with pytest.raises(ExtensionContractError, match="evaluation failed") as failure:
        run_extension_v1(_FailingExtension(), envelope)
    assert "raw extension failure" not in str(failure.value)

    with pytest.raises(ExtensionContractError, match="unknown event"):
        run_extension_v1(_UnknownEvidenceExtension(), envelope)

    with pytest.raises(ExtensionContractError, match="manifest changed"):
        run_extension_v1(_ManifestDriftExtension(), envelope)

    with pytest.raises(ExtensionContractError, match="findings violate V1") as invalid:
        run_extension_v1(_InvalidFindingExtension(), envelope)  # type: ignore[arg-type]
    assert "must-not-escape" not in str(invalid.value)


def test_registry_and_pipeline_fail_closed_on_duplicates_and_missing_ids() -> None:
    extension = _CheckExtension()
    registry = StaticExtensionRegistryV1((extension,))

    with pytest.raises(ExtensionContractError, match="already registered"):
        registry.register(extension)
    with pytest.raises(ExtensionContractError, match="not registered"):
        registry.get("missing.extension")
    with pytest.raises(ExtensionContractError, match="must be unique"):
        run_extension_pipeline_v1(
            registry,
            (extension.manifest.extension_id, extension.manifest.extension_id),
            _envelope(),
        )


def test_manifest_rejects_authority_network_and_contract_drift() -> None:
    values = _manifest().model_dump(mode="python")

    with pytest.raises(ValidationError):
        ExtensionManifestV1.model_validate({**values, "operational_authority": "allow"})
    with pytest.raises(ValidationError, match="network_mode off"):
        ExtensionManifestV1.model_validate({**values, "network_mode": "local_only"})
    with pytest.raises(ValidationError, match="at least 1 item"):
        ExtensionManifestV1.model_validate({**values, "consumes": ()})
    with pytest.raises(ValidationError, match="Extra inputs"):
        ExtensionManifestV1.model_validate({**values, "credential": "forbidden"})
    with pytest.raises(ValidationError):
        ExtensionManifestV1.model_validate(
            {**values, "implementation_sha256": "not-a-digest"}
        )


def test_envelope_rejects_graph_identity_and_commitment_drift() -> None:
    first = _event()
    child = _event(
        SHA_D,
        occurred_at=NOW + timedelta(microseconds=1),
        parent_event_ids=(SHA_A,),
    )

    with pytest.raises(ValidationError, match="parents must precede"):
        build_extension_envelope_v1(
            source_component_id="agentic-security-harness",
            source_commitment_sha256=SOURCE_COMMITMENT,
            events=(child, first),
        )
    with pytest.raises(ValidationError, match="repository identity"):
        build_extension_envelope_v1(
            source_component_id="agentic-security-harness",
            source_commitment_sha256=SOURCE_COMMITMENT,
            events=(first, child.model_copy(update={"repository_sha": "1" * 40})),
        )

    envelope = _envelope()
    values = envelope.model_dump(mode="python")
    commitments = list(envelope.event_commitments)
    commitments[0] = commitments[0].model_copy(update={"content_sha256": "0" * 64})
    with pytest.raises(ValidationError, match="commitment does not bind"):
        type(envelope).model_validate(
            {**values, "event_commitments": tuple(commitments)}
        )


def test_json_schemas_are_closed_and_committed() -> None:
    generated = extension_v1_json_schemas()
    assert set(generated) == {
        "extension-manifest.v1.schema.json",
        "extension-envelope.v1.schema.json",
        "extension-result.v1.schema.json",
        "extension-run-receipt.v1.schema.json",
        "extension-pipeline-receipt.v1.schema.json",
    }
    for name, schema in generated.items():
        assert schema["additionalProperties"] is False
        path = ROOT / "schemas" / name
        assert json.loads(path.read_text(encoding="utf-8")) == schema
        assert hashlib.sha256(path.read_bytes()).hexdigest()

    contract_manifest = json.loads(
        (ROOT / "schemas" / "extension-sdk.v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract_manifest["code_auto_discovery"] is False
    assert contract_manifest["operational_authority"] == "none"
    for binding in (
        contract_manifest["schemas"]
        + [
            contract_manifest["implementation"],
            contract_manifest["cli"],
            contract_manifest["generator"],
            contract_manifest["tests"],
        ]
    ):
        bound_path = ROOT / binding["path"]
        assert hashlib.sha256(bound_path.read_bytes()).hexdigest() == binding["sha256"]

    for path, expected in generated_contracts().items():
        assert path.read_bytes() == expected


def test_sdk_does_not_discover_plugins_or_open_external_surfaces() -> None:
    source = (
        ROOT / "src" / "agentic_security_harness" / "extension_sdk.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        "import socket",
        "import subprocess",
        "import requests",
        "import httpx",
        "import importlib",
        "entry_points(",
        "urlopen(",
        ".load(",
    )
    assert all(token not in source for token in forbidden)
