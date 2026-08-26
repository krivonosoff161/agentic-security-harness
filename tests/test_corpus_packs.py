from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.corpus_pack_contracts import example_manifest_bytes, generated_contracts

from agentic_security_harness.corpus import V1_PATTERN_IDS, corpus_manifest_sha256
from agentic_security_harness.corpus_packs import (
    CORPUS_PACK_FILENAME_V1,
    MAX_CORPUS_PACK_BYTES,
    ComposedCorpusV1,
    CorpusPackContractError,
    CorpusPackManifestV1,
    CorpusPackObservationRequirementsV1,
    CorpusPackPatternV1,
    CorpusPackSourceV1,
    CorpusPackTerminalSemanticsV1,
    assess_corpus_pack_evidence_v1,
    build_corpus_pack_manifest_v1,
    compose_corpus_packs_v1,
    corpus_pack_manifest_sha256,
    corpus_pack_v1_json_schemas,
    decode_corpus_pack_manifest_v1,
    encode_corpus_pack_manifest_v1,
    load_corpus_pack_directory_v1,
)
from agentic_security_harness.extension_sdk import (
    ExtensionObservationEnvelopeV1,
    build_extension_envelope_v1,
)
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    SourceSurface,
    TelemetryState,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _requirements(
    *,
    surfaces: tuple[SourceSurface, ...] = ("agent", "tool"),
    activities: tuple[str, ...] = ("agent.observed", "tool.observed"),
    terminal_activity: str = "tool.observed",
) -> CorpusPackObservationRequirementsV1:
    return CorpusPackObservationRequirementsV1(
        observation_schema_version="portfolio-observation-v1.0",
        extension_envelope_schema_version="harness-extension-envelope-v1.0",
        required_envelope_fields=(
            "envelope_id",
            "event_commitments",
            "events",
            "extension_chain",
            "operational_authority",
            "schema_version",
            "source_commitment_sha256",
            "source_component_id",
            "verdict_semantics",
        ),
        required_source_surfaces=surfaces,
        required_activities=activities,
        terminal_activity=terminal_activity,
        minimum_event_count=2,
        requires_complete_telemetry=True,
        requires_parent_link=True,
        requires_authority_envelope_ref=False,
        evidence_semantics="declared_requirements_only_not_proof_of_presence_or_security",
    )


def _terminal() -> CorpusPackTerminalSemanticsV1:
    return CorpusPackTerminalSemanticsV1(
        invariant_preserved="pass",
        invariant_violated="finding",
        evidence_missing="inconclusive",
        contract_invalid="error",
        verdict_scope="declared_pattern_only_not_security_certification",
        may_lower_security_decision=False,
        operational_authority="none",
    )


def _pattern(
    pack_id: str = "example.boundaries",
    suffix: str = "tool_output_recipient",
) -> CorpusPackPatternV1:
    return CorpusPackPatternV1(
        pattern_id=f"{pack_id}.{suffix}",
        invariant_id="recipient.scope.preserved",
        category="data_boundary",
        severity="high",
        boundary_surface="tool",
        data_boundary_fields=("allowed_recipients", "can_forward"),
        control_ids=("recipient.allowlist", "tool.output.untrusted"),
        observation_requirements=_requirements(),
        terminal_semantics=_terminal(),
        payload_policy="metadata_and_digests_only_no_raw_or_private_payloads",
    )


def _manifest(
    pack_id: str = "example.boundaries",
    *,
    version: str = "1.0.0",
    pattern: CorpusPackPatternV1 | None = None,
    source_commit: str = "1" * 40,
) -> CorpusPackManifestV1:
    return build_corpus_pack_manifest_v1(
        pack_id=pack_id,
        pack_version=version,
        source=CorpusPackSourceV1(
            component_id="synthetic-corpus-pack",
            repository_id="example/synthetic-corpus-pack",
            source_commit=source_commit,
            component_manifest_sha256="2" * 64,
            implementation_sha256="3" * 64,
            distribution_sha256="4" * 64,
            producer_attestation="unattested",
        ),
        supported_platforms=("linux", "windows"),
        tested_platforms=("linux", "windows"),
        patterns=(pattern or _pattern(pack_id),),
    )


def _pins(*manifests: CorpusPackManifestV1) -> dict[str, str]:
    return {
        manifest.pack_id: corpus_pack_manifest_sha256(manifest)
        for manifest in manifests
    }


def _event(
    event_id: str,
    *,
    surface: SourceSurface,
    activity: str,
    occurred_at: datetime,
    parent_event_ids: tuple[str, ...] = (),
    telemetry_state: TelemetryState = "complete",
) -> CanonicalObservationEventV1:
    return CanonicalObservationEventV1.model_validate(
        {
            "schema_version": "portfolio-observation-v1.0",
            "event_id": event_id,
            "project_id": "agentic-security-harness",
            "repository_id": "example/owned-agent",
            "repository_sha": "f" * 40,
            "occurred_at": occurred_at,
            "producer_id_hash": SHA_B,
            "producer_attestation": "unattested",
            "source_surface": surface,
            "activity": activity,
            "entity_refs": (),
            "parent_event_ids": parent_event_ids,
            "data_envelope_ref": SHA_C,
            "authority_envelope_ref": None,
            "telemetry_state": telemetry_state,
            "operational_authority": "none",
        }
    )


def _envelope(*, incomplete: bool = False) -> ExtensionObservationEnvelopeV1:
    return build_extension_envelope_v1(
        source_component_id="agentic-security-harness",
        source_commitment_sha256=SHA_E,
        events=(
            _event(
                SHA_A,
                surface="agent",
                activity="agent.observed",
                occurred_at=NOW,
            ),
            _event(
                SHA_D,
                surface="tool",
                activity="tool.observed",
                occurred_at=NOW + timedelta(microseconds=1),
                parent_event_ids=(SHA_A,),
                telemetry_state="incomplete" if incomplete else "complete",
            ),
        ),
    )


def test_manifest_round_trip_binds_core_source_and_platforms() -> None:
    before_ids = V1_PATTERN_IDS
    before_digest = corpus_manifest_sha256()
    manifest = _manifest()
    encoded = encode_corpus_pack_manifest_v1(manifest)

    assert decode_corpus_pack_manifest_v1(encoded) == manifest
    assert encoded.endswith(b"\n") and b"\r\n" not in encoded
    assert manifest.core_corpus_version == "1.0.0"
    assert manifest.core_corpus_manifest_sha256 == before_digest
    assert manifest.source.source_commit == "1" * 40
    assert manifest.supported_platforms == ("linux", "windows")
    assert manifest.tested_platforms == ("linux", "windows")
    assert manifest.operational_authority == "none"
    assert corpus_pack_manifest_sha256(manifest) == hashlib.sha256(encoded).hexdigest()
    assert V1_PATTERN_IDS == before_ids
    assert corpus_manifest_sha256() == before_digest


def test_decoder_rejects_unknown_duplicate_noncanonical_and_digest_drift() -> None:
    encoded = encode_corpus_pack_manifest_v1(_manifest())
    payload = json.loads(encoded)
    payload["raw_prompt"] = "forbidden"
    with pytest.raises(CorpusPackContractError, match="values violate"):
        decode_corpus_pack_manifest_v1(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )

    duplicate = encoded.replace(
        b'{"core_corpus_manifest_sha256"',
        b'{"pack_id":"example.boundaries","core_corpus_manifest_sha256"',
        1,
    )
    with pytest.raises(CorpusPackContractError, match="duplicate"):
        decode_corpus_pack_manifest_v1(duplicate)

    with pytest.raises(CorpusPackContractError, match="not canonical"):
        decode_corpus_pack_manifest_v1(encoded.replace(b"\n", b"\r\n"))
    pretty = (json.dumps(json.loads(encoded), indent=2, sort_keys=True) + "\n").encode()
    with pytest.raises(CorpusPackContractError, match="not canonical"):
        decode_corpus_pack_manifest_v1(pretty)

    drifted = json.loads(encoded)
    drifted["patterns"][0]["category"] = "authority_boundary"
    with pytest.raises(CorpusPackContractError, match="values violate"):
        decode_corpus_pack_manifest_v1(
            (json.dumps(drifted, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
    with pytest.raises(CorpusPackContractError, match="size"):
        decode_corpus_pack_manifest_v1(b"{" + b"x" * MAX_CORPUS_PACK_BYTES)
    with pytest.raises(CorpusPackContractError, match="integer exceeds"):
        decode_corpus_pack_manifest_v1(b'{"n":' + b"9" * 5_000 + b"}\n")
    with pytest.raises(CorpusPackContractError, match="integer exceeds"):
        decode_corpus_pack_manifest_v1(b'{"n":12345678901}\n')
    nested = b'{"n":' + b"[" * 33 + b"0" + b"]" * 33 + b"}\n"
    with pytest.raises(CorpusPackContractError, match="nesting exceeds"):
        decode_corpus_pack_manifest_v1(nested)
    with pytest.raises(CorpusPackContractError, match="non-finite"):
        decode_corpus_pack_manifest_v1(b'{"n":NaN}\n')


def test_manifest_rejects_namespace_core_override_and_terminal_redefinition() -> None:
    values = _manifest().model_dump(mode="python")
    pattern = values["patterns"][0]
    pattern["pattern_id"] = "other.namespace.pattern"
    with pytest.raises(ValidationError, match="namespaced"):
        CorpusPackManifestV1.model_validate(values)

    core_override = _pattern("audit", "hash_chain_tamper")
    with pytest.raises(ValidationError, match="override"):
        _manifest("audit", pattern=core_override)

    terminal = _terminal().model_dump(mode="python")
    terminal["evidence_missing"] = "pass"
    with pytest.raises(ValidationError):
        CorpusPackTerminalSemanticsV1.model_validate(terminal)
    with pytest.raises(ValidationError, match="Extra inputs"):
        CorpusPackPatternV1.model_validate(
            {**_pattern().model_dump(mode="python"), "private_payload": "forbidden"}
        )


def test_composer_is_order_independent_and_rejects_replay_or_collision() -> None:
    first = _manifest("example.alpha", pattern=_pattern("example.alpha"))
    second = _manifest(
        "example.beta", pattern=_pattern("example.beta"), source_commit="5" * 40
    )
    pins = _pins(first, second)
    left = compose_corpus_packs_v1((second, first), expected_manifest_sha256s=pins)
    right = compose_corpus_packs_v1((first, second), expected_manifest_sha256s=pins)

    assert left == right
    assert left.composition_id == right.composition_id
    assert left.core_pattern_ids == V1_PATTERN_IDS
    assert tuple(item.pack_id for item in left.pack_commitments) == (
        "example.alpha",
        "example.beta",
    )
    assert tuple(item.pattern_id for item in left.patterns[: len(V1_PATTERN_IDS)]) == (
        V1_PATTERN_IDS
    )
    assert all(
        item.operational_authority == "none" for item in left.pack_commitments
    )

    with pytest.raises(CorpusPackContractError, match="duplicate or replayed"):
        compose_corpus_packs_v1(
            (first, first), expected_manifest_sha256s=_pins(first)
        )

    bypassed = first.model_copy(
        update={
            "patterns": (
                first.patterns[0].model_copy(
                    update={"pattern_id": V1_PATTERN_IDS[0]}
                ),
            )
        }
    )
    with pytest.raises(CorpusPackContractError, match="object violates"):
        compose_corpus_packs_v1(
            (bypassed,), expected_manifest_sha256s={bypassed.pack_id: "0" * 64}
        )

    with pytest.raises(CorpusPackContractError, match="pins must match"):
        compose_corpus_packs_v1((first,), expected_manifest_sha256s={})
    with pytest.raises(CorpusPackContractError, match="does not match expected"):
        compose_corpus_packs_v1(
            (first,), expected_manifest_sha256s={first.pack_id: "0" * 64}
        )

    values = left.model_dump(mode="python")
    values["composition_id"] = "0" * 64
    with pytest.raises(ValidationError, match="identity drift"):
        ComposedCorpusV1.model_validate(values)

    missing_ref = left.model_dump(mode="python")
    missing_ref["pack_commitments"][0]["pattern_count"] = 2
    with pytest.raises(ValidationError, match="pattern count drift"):
        ComposedCorpusV1.model_validate(missing_ref)

    changed_ref = left.model_dump(mode="python")
    changed_ref["patterns"][-1]["pattern_sha256"] = "9" * 64
    with pytest.raises(ValidationError, match="reference digest drift"):
        ComposedCorpusV1.model_validate(changed_ref)

    first_commitment = left.pack_commitments[0]
    forged_commitment = type(first_commitment).model_construct(
        **{
            **first_commitment.model_dump(mode="python"),
            "supported_platforms": (),
            "tested_platforms": (),
        }
    )
    import agentic_security_harness.corpus_packs as module

    provisional = left.model_copy(
        update={
            "composition_id": "0" * 64,
            "pack_commitments": (forged_commitment, *left.pack_commitments[1:]),
        }
    )
    forged_platforms = provisional.model_dump(mode="python")
    forged_platforms["composition_id"] = module._composition_digest(provisional)
    with pytest.raises(ValidationError, match="at least 1 item"):
        ComposedCorpusV1.model_validate(forged_platforms)

    oversized = left.model_dump(mode="python")
    oversized["patterns"] = oversized["patterns"] + (
        oversized["patterns"][-1],
    ) * 2_049
    with pytest.raises(ValidationError, match="at most 2072 items"):
        ComposedCorpusV1.model_validate(oversized)


def test_source_or_pattern_digest_drift_changes_composition_identity() -> None:
    original = _manifest()
    changed_source = build_corpus_pack_manifest_v1(
        pack_id=original.pack_id,
        pack_version=original.pack_version,
        source=original.source.model_copy(update={"implementation_sha256": "9" * 64}),
        supported_platforms=original.supported_platforms,
        tested_platforms=original.tested_platforms,
        patterns=original.patterns,
    )
    changed_pattern = build_corpus_pack_manifest_v1(
        pack_id=original.pack_id,
        pack_version=original.pack_version,
        source=original.source,
        supported_platforms=original.supported_platforms,
        tested_platforms=original.tested_platforms,
        patterns=(original.patterns[0].model_copy(update={"severity": "critical"}),),
    )

    identities = {
        compose_corpus_packs_v1(
            (candidate,), expected_manifest_sha256s=_pins(candidate)
        ).composition_id
        for candidate in (original, changed_source, changed_pattern)
    }
    assert len(identities) == 3


def test_evidence_assessment_is_extension_compatible_and_never_a_verdict() -> None:
    pattern = _pattern()
    ready = assess_corpus_pack_evidence_v1(pattern, _envelope())
    incomplete = assess_corpus_pack_evidence_v1(pattern, _envelope(incomplete=True))

    assert ready.evidence_state == "ready_for_rule_evaluation"
    assert ready.missing_requirement_codes == ()
    assert ready.terminal_disposition == "inconclusive"
    assert ready.verdict_semantics == "evidence_readiness_only_no_security_verdict"
    assert ready.operational_authority == "none"
    assert incomplete.evidence_state == "incomplete"
    assert incomplete.missing_requirement_codes == ("telemetry.complete",)
    assert incomplete.terminal_disposition == "inconclusive"

    bypassed = pattern.model_copy(
        update={
            "observation_requirements": pattern.observation_requirements.model_copy(
                update={"required_activities": ("not canonical",)}
            )
        }
    )
    with pytest.raises(CorpusPackContractError, match="inputs violate"):
        assess_corpus_pack_evidence_v1(bypassed, _envelope())

    mutated_envelope = _envelope()
    mutated_envelope.events[0].activity = "not canonical"
    with pytest.raises(CorpusPackContractError, match="inputs violate"):
        assess_corpus_pack_evidence_v1(pattern, mutated_envelope)


def test_max_valid_requirements_remain_bounded_inconclusive() -> None:
    activities = tuple(f"activity.required_{index:02d}" for index in range(32))
    requirements = CorpusPackObservationRequirementsV1(
        observation_schema_version="portfolio-observation-v1.0",
        extension_envelope_schema_version="harness-extension-envelope-v1.0",
        required_envelope_fields=_requirements().required_envelope_fields,
        required_source_surfaces=(
            "agent",
            "app",
            "audit",
            "document",
            "environment",
            "mcp",
            "memory",
            "model",
            "provider",
            "retrieval",
            "sensor",
            "tool",
            "user",
        ),
        required_activities=activities,
        terminal_activity=activities[-1],
        minimum_event_count=2_048,
        requires_complete_telemetry=True,
        requires_parent_link=True,
        requires_authority_envelope_ref=True,
        evidence_semantics="declared_requirements_only_not_proof_of_presence_or_security",
    )
    pattern = _pattern().model_copy(update={"observation_requirements": requirements})
    result = assess_corpus_pack_evidence_v1(pattern, _envelope())

    assert result.evidence_state == "incomplete"
    assert 16 < len(result.missing_requirement_codes) <= 50
    assert result.terminal_disposition == "inconclusive"


def test_directory_loader_is_fixed_path_stable_and_link_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "pack"
    root.mkdir()
    manifest_path = root / CORPUS_PACK_FILENAME_V1
    manifest_bytes = encode_corpus_pack_manifest_v1(_manifest())
    manifest_path.write_bytes(manifest_bytes)
    expected_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    assert (
        load_corpus_pack_directory_v1(
            root, expected_manifest_sha256=expected_sha256
        )
        == _manifest()
    )

    wrong_root = tmp_path / "wrong"
    wrong_root.mkdir()
    (tmp_path / CORPUS_PACK_FILENAME_V1).write_bytes(example_manifest_bytes())
    with pytest.raises(CorpusPackContractError, match="does not exist"):
        load_corpus_pack_directory_v1(
            wrong_root, expected_manifest_sha256=expected_sha256
        )

    hardlink_root = tmp_path / "hardlink"
    hardlink_root.mkdir()
    os.link(manifest_path, hardlink_root / CORPUS_PACK_FILENAME_V1)
    with pytest.raises(CorpusPackContractError, match="single-link"):
        load_corpus_pack_directory_v1(
            hardlink_root, expected_manifest_sha256=expected_sha256
        )

    import agentic_security_harness.corpus_packs as module

    monkeypatch.setattr(module, "is_link_or_reparse", lambda _path: True)
    with pytest.raises(CorpusPackContractError, match="link or reparse"):
        load_corpus_pack_directory_v1(
            root, expected_manifest_sha256=expected_sha256
        )


def test_directory_loader_rejects_symlink_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    manifest_bytes = encode_corpus_pack_manifest_v1(_manifest())
    (target / CORPUS_PACK_FILENAME_V1).write_bytes(manifest_bytes)
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(CorpusPackContractError, match="link or reparse"):
        load_corpus_pack_directory_v1(
            linked, expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest()
        )


def test_directory_loader_rejects_transient_same_identity_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.corpus_packs as module

    root = tmp_path / "transient"
    root.mkdir()
    baseline = encode_corpus_pack_manifest_v1(_manifest())
    transient = encode_corpus_pack_manifest_v1(_manifest(source_commit="5" * 40))
    assert len(transient) == len(baseline)
    (root / CORPUS_PACK_FILENAME_V1).write_bytes(baseline)

    reads = iter((transient, b"", baseline, b""))
    monkeypatch.setattr(module.os, "read", lambda _descriptor, _size: next(reads))
    monkeypatch.setattr(module, "_file_identity", lambda _info: (1, 1, 1, 1, 1, 1, 1))

    with pytest.raises(CorpusPackContractError, match="changed while being read"):
        load_corpus_pack_directory_v1(
            root, expected_manifest_sha256=hashlib.sha256(baseline).hexdigest()
        )


def test_directory_loader_rejects_persistent_same_identity_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentic_security_harness.corpus_packs as module

    root = tmp_path / "persistent"
    root.mkdir()
    baseline = encode_corpus_pack_manifest_v1(_manifest())
    replacement = encode_corpus_pack_manifest_v1(_manifest(source_commit="5" * 40))
    assert len(replacement) == len(baseline)
    (root / CORPUS_PACK_FILENAME_V1).write_bytes(baseline)

    reads = iter((replacement, b"", replacement, b""))
    monkeypatch.setattr(module.os, "read", lambda _descriptor, _size: next(reads))
    monkeypatch.setattr(module, "_file_identity", lambda _info: (1, 1, 1, 1, 1, 1, 1))

    with pytest.raises(CorpusPackContractError, match="does not match expected"):
        load_corpus_pack_directory_v1(
            root, expected_manifest_sha256=hashlib.sha256(baseline).hexdigest()
        )


def test_schemas_fixture_and_generated_manifest_are_closed_and_current() -> None:
    generated = corpus_pack_v1_json_schemas()
    assert set(generated) == {
        "corpus-composition.v1.schema.json",
        "corpus-pack-evidence-assessment.v1.schema.json",
        "corpus-pack-manifest.v1.schema.json",
    }
    for name, schema in generated.items():
        assert schema["additionalProperties"] is False
        assert json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")) == schema

    contract = json.loads(
        (ROOT / "schemas" / "corpus-pack-sdk.v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract["code_auto_discovery"] is False
    assert contract["package_code_loading"] is False
    assert contract["network_access"] is False
    assert contract["raw_or_private_payload_fields"] is False
    assert contract["may_lower_security_decision"] is False
    assert contract["operational_authority"] == "none"
    assert {binding["path"] for binding in contract["runtime_closure"]} == {
        "src/agentic_security_harness/__init__.py",
        "src/agentic_security_harness/corpus.py",
        "src/agentic_security_harness/extension_sdk.py",
        "src/agentic_security_harness/models.py",
        "src/agentic_security_harness/portfolio_contract.py",
        "src/agentic_security_harness/safe_io.py",
    }
    for binding in (
        contract["schemas"]
        + contract["runtime_closure"]
        + [
            contract["core_corpus"],
            contract["extension_sdk_contract"],
            contract["synthetic_fixture"],
            contract["implementation"],
            contract["generator"],
            contract["tests"],
            contract["workflow"],
            contract["documentation"],
        ]
    ):
        path = ROOT / binding["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == binding["sha256"]

    fixture = ROOT / "examples" / "corpus-packs" / "example-boundary-pack"
    fixture_bytes = (fixture / CORPUS_PACK_FILENAME_V1).read_bytes()
    assert (
        load_corpus_pack_directory_v1(
            fixture,
            expected_manifest_sha256=hashlib.sha256(fixture_bytes).hexdigest(),
        ).pack_id
        == "example.boundaries"
    )
    for path, expected in generated_contracts().items():
        assert path.read_bytes() == expected


def test_module_has_no_discovery_execution_network_or_subprocess_surface() -> None:
    source = (ROOT / "src" / "agentic_security_harness" / "corpus_packs.py").read_text(
        encoding="utf-8"
    )
    forbidden = (
        "import socket",
        "import subprocess",
        "import requests",
        "import httpx",
        "import importlib",
        "entry_points(",
        "urlopen(",
        ".load(",
        "exec(",
        "eval(",
    )
    assert all(token not in source for token in forbidden)
