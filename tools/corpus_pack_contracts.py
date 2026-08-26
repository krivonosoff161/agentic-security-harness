"""Generate or verify the closed Corpus Pack SDK V1 public contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security_harness.corpus_packs import (  # noqa: E402
    CorpusPackObservationRequirementsV1,
    CorpusPackPatternV1,
    CorpusPackSourceV1,
    CorpusPackTerminalSemanticsV1,
    build_corpus_pack_manifest_v1,
    corpus_pack_v1_json_schemas,
    encode_corpus_pack_manifest_v1,
)


def example_manifest_bytes() -> bytes:
    """Return a sanitized, unattested fixture illustrating the portable contract."""

    requirement = CorpusPackObservationRequirementsV1(
        observation_schema_version="portfolio-observation-v1.0",
        extension_envelope_schema_version="harness-extension-envelope-v1.0",
        required_envelope_fields=tuple(
            sorted(
                {
                    "envelope_id",
                    "event_commitments",
                    "events",
                    "extension_chain",
                    "operational_authority",
                    "schema_version",
                    "source_commitment_sha256",
                    "source_component_id",
                    "verdict_semantics",
                }
            )
        ),
        required_source_surfaces=("agent", "tool"),
        required_activities=("agent.observed", "tool.observed"),
        terminal_activity="tool.observed",
        minimum_event_count=2,
        requires_complete_telemetry=True,
        requires_parent_link=True,
        requires_authority_envelope_ref=False,
        evidence_semantics="declared_requirements_only_not_proof_of_presence_or_security",
    )
    terminal = CorpusPackTerminalSemanticsV1(
        invariant_preserved="pass",
        invariant_violated="finding",
        evidence_missing="inconclusive",
        contract_invalid="error",
        verdict_scope="declared_pattern_only_not_security_certification",
        may_lower_security_decision=False,
        operational_authority="none",
    )
    manifest = build_corpus_pack_manifest_v1(
        pack_id="example.boundaries",
        pack_version="1.0.0",
        source=CorpusPackSourceV1(
            component_id="synthetic-corpus-pack",
            repository_id="example/synthetic-corpus-pack",
            source_commit="1" * 40,
            component_manifest_sha256="2" * 64,
            implementation_sha256="3" * 64,
            distribution_sha256="4" * 64,
            producer_attestation="unattested",
        ),
        supported_platforms=("linux", "windows"),
        tested_platforms=("linux", "windows"),
        patterns=(
            CorpusPackPatternV1(
                pattern_id="example.boundaries.tool_output_recipient",
                invariant_id="recipient.scope.preserved",
                category="data_boundary",
                severity="high",
                boundary_surface="tool",
                data_boundary_fields=("allowed_recipients", "can_forward"),
                control_ids=("recipient.allowlist", "tool.output.untrusted"),
                observation_requirements=requirement,
                terminal_semantics=terminal,
                payload_policy="metadata_and_digests_only_no_raw_or_private_payloads",
            ),
        ),
    )
    return encode_corpus_pack_manifest_v1(manifest)


def generated_contracts() -> dict[Path, bytes]:
    schemas = {
        ROOT / "schemas" / name: (
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, schema in corpus_pack_v1_json_schemas().items()
    }
    fixture_path = (
        ROOT
        / "examples"
        / "corpus-packs"
        / "example-boundary-pack"
        / "corpus-pack.v1.json"
    )
    fixture = example_manifest_bytes()
    generated: dict[Path, bytes] = {**schemas, fixture_path: fixture}
    manifest = {
        "schema_version": "harness-corpus-pack-contract-manifest-v1.0",
        "contract_id": "harness-corpus-pack-sdk-v1.0",
        "harness_api": "1",
        "core_corpus": _bound_file(ROOT / "schemas" / "corpus-manifest.v1.json"),
        "extension_sdk_contract": _bound_file(
            ROOT / "schemas" / "extension-sdk.v1.manifest.json"
        ),
        "schemas": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for path, content in sorted(schemas.items())
        ],
        "synthetic_fixture": {
            "path": fixture_path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(fixture).hexdigest(),
            "producer_attestation": "unattested",
        },
        "implementation": _bound_file(
            ROOT / "src" / "agentic_security_harness" / "corpus_packs.py"
        ),
        "runtime_closure": [
            _bound_file(ROOT / "src" / "agentic_security_harness" / path)
            for path in (
                "__init__.py",
                "corpus.py",
                "extension_sdk.py",
                "models.py",
                "portfolio_contract.py",
                "safe_io.py",
            )
        ],
        "generator": _bound_file(ROOT / "tools" / "corpus_pack_contracts.py"),
        "tests": _bound_file(ROOT / "tests" / "test_corpus_packs.py"),
        "workflow": _bound_file(ROOT / ".github" / "workflows" / "ecosystem-docs.yml"),
        "documentation": _bound_file(ROOT / "docs" / "corpus-pack-sdk.md"),
        "loading_model": "explicit_canonical_bytes_or_fixed_manifest_path",
        "composition_model": "deterministic_registry_only_core_preserved",
        "observation_contract": "harness-extension-envelope-v1.0",
        "code_auto_discovery": False,
        "package_code_loading": False,
        "network_access": False,
        "raw_or_private_payload_fields": False,
        "may_lower_security_decision": False,
        "operational_authority": "none",
    }
    generated[ROOT / "schemas" / "corpus-pack-sdk.v1.manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return generated


def _bound_file(path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def generate() -> None:
    for path, content in generated_contracts().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def check() -> None:
    stale = [
        path.relative_to(ROOT).as_posix()
        for path, expected in generated_contracts().items()
        if not path.is_file() or path.read_bytes() != expected
    ]
    if stale:
        raise ValueError(f"corpus pack contract files are stale: {', '.join(stale)}")


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
