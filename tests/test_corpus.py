import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.corpus_contract import MANIFEST_PATH, SCHEMA_PATH, build_outputs

from agentic_security_harness.corpus import (
    CORPUS_MANIFEST_SCHEMA_VERSION,
    DEPRECATED_PATTERN_IDS,
    PATTERN_REPLACEMENTS,
    V1_PATTERN_IDS,
    CorpusManifestV1,
    corpus_contract,
    corpus_contract_json,
    corpus_manifest,
    corpus_manifest_sha256,
    parse_corpus_contract_json,
    parse_corpus_contract_payload,
)
from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.protected_demo_agent import ProtectedDemoAgentTarget
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard

ROOT = Path(__file__).resolve().parent.parent


def test_manifest_has_twenty_four_implemented_entries() -> None:
    manifest = corpus_manifest()
    assert len(manifest) == 24
    assert all(entry.implemented for entry in manifest)


def test_v1_contract_freezes_exact_ids_order_and_empty_deprecation_registry() -> None:
    contract = corpus_contract()
    assert contract.schema_version == CORPUS_MANIFEST_SCHEMA_VERSION == "1.0"
    assert contract.corpus_version == "1.0.0"
    assert contract.pattern_count == len(V1_PATTERN_IDS) == 24
    assert tuple(entry.pattern_id for entry in contract.patterns) == V1_PATTERN_IDS
    assert contract.deprecated_pattern_ids == DEPRECATED_PATTERN_IDS == ()
    assert contract.pattern_replacements == PATTERN_REPLACEMENTS == ()


def test_contract_is_deeply_immutable() -> None:
    contract = corpus_contract()
    with pytest.raises(ValidationError, match="frozen"):
        contract.pattern_count = 25
    with pytest.raises(ValidationError, match="frozen"):
        contract.patterns[0].name = "renamed"
    assert isinstance(contract.patterns[0].owasp_agentic, tuple)


def test_committed_contract_and_schema_equal_the_generator() -> None:
    outputs = build_outputs()
    assert (ROOT / MANIFEST_PATH).read_bytes() == outputs[MANIFEST_PATH]
    assert (ROOT / SCHEMA_PATH).read_bytes() == outputs[SCHEMA_PATH]
    assert parse_corpus_contract_json(outputs[MANIFEST_PATH]) == corpus_contract()
    assert (ROOT / MANIFEST_PATH).read_text(encoding="utf-8") == corpus_contract_json()


def test_manifest_digest_is_canonical_and_bound_to_committed_semantics() -> None:
    payload = corpus_contract().model_dump(mode="json")
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert corpus_manifest_sha256() == hashlib.sha256(canonical).hexdigest()
    assert corpus_manifest_sha256() == (
        "487a35d2e91b9a8e76a92a18079262cc99319f96f5be76750395ad697496ff85"
    )


@pytest.mark.parametrize("field", list(CorpusManifestV1.model_fields))
def test_external_contract_rejects_missing_top_level_field(field: str) -> None:
    payload = corpus_contract().model_dump(mode="json")
    del payload[field]
    with pytest.raises(ValueError, match="fields differ"):
        parse_corpus_contract_payload(payload)


def test_external_contract_rejects_unknown_duplicate_and_missing_entry_fields() -> None:
    payload = corpus_contract().model_dump(mode="json")
    payload["unknown"] = True
    with pytest.raises(ValueError, match="fields differ"):
        parse_corpus_contract_payload(payload)

    duplicate = corpus_contract_json().replace(
        '"schema_version": "1.0",',
        '"schema_version": "1.0",\n  "schema_version": "1.0",',
        1,
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        parse_corpus_contract_json(duplicate)

    missing_entry = corpus_contract().model_dump(mode="json")
    del missing_entry["patterns"][0]["mitre_atlas"]
    with pytest.raises(ValueError, match="pattern 0 fields differ"):
        parse_corpus_contract_payload(missing_entry)


@pytest.mark.parametrize("mutation", ["renamed", "reordered", "duplicated"])
def test_frozen_v1_identifier_drift_is_rejected(mutation: str) -> None:
    payload = copy.deepcopy(corpus_contract().model_dump(mode="json"))
    patterns = payload["patterns"]
    if mutation == "renamed":
        patterns[0]["pattern_id"] = "renamed_pattern"
    elif mutation == "reordered":
        patterns[0], patterns[1] = patterns[1], patterns[0]
    else:
        patterns[1]["pattern_id"] = patterns[0]["pattern_id"]
    with pytest.raises(ValidationError):
        parse_corpus_contract_payload(payload)


def test_deprecation_and_replacement_rules_fail_closed() -> None:
    payload = corpus_contract().model_dump(mode="json")
    payload["deprecated_pattern_ids"] = [V1_PATTERN_IDS[0]]
    payload["pattern_replacements"] = [
        {
            "deprecated_pattern_id": V1_PATTERN_IDS[0],
            "replacement_pattern_id": V1_PATTERN_IDS[1],
        }
    ]
    assert parse_corpus_contract_payload(payload).deprecated_pattern_ids == (
        V1_PATTERN_IDS[0],
    )

    payload["pattern_replacements"][0]["replacement_pattern_id"] = V1_PATTERN_IDS[0]
    with pytest.raises(ValidationError, match="different active pattern id"):
        parse_corpus_contract_payload(payload)


def test_manifest_ids_match_seed_patterns_in_order() -> None:
    manifest_ids = [entry.pattern_id for entry in corpus_manifest()]
    seed_ids = [pattern.pattern_id for pattern in seed_patterns()]
    assert manifest_ids == seed_ids


def test_no_duplicate_pattern_ids() -> None:
    ids = [entry.pattern_id for entry in corpus_manifest()]
    assert len(ids) == len(set(ids))


def test_manifest_severity_and_broke_at_match_baseline() -> None:
    by_id = {entry.pattern_id: entry for entry in corpus_manifest()}
    traces = {t.pattern_id: t for t in HarnessRunner(DemoAgentTarget()).run_many(seed_patterns())}
    for pid, entry in by_id.items():
        finding = traces[pid].findings[0]
        assert finding.severity == entry.severity
        assert finding.broke_at == entry.broke_at


def test_baseline_and_protected_outcomes_match_manifest() -> None:
    patterns = seed_patterns()
    base = build_scorecard(HarnessRunner(DemoAgentTarget()).run_many(patterns))
    prot = build_scorecard(HarnessRunner(ProtectedDemoAgentTarget()).run_many(patterns))
    for entry in corpus_manifest():
        assert entry.baseline_expected == "FAIL"
        assert entry.protected_expected == "PASS"
        assert entry.pattern_id in base.failed_patterns
        assert entry.pattern_id in prot.passed_patterns


def test_agentic_standards_mapping_is_present_for_implemented_patterns() -> None:
    for entry in corpus_manifest():
        assert entry.owasp_agentic
        assert all(item.startswith("ASI") for item in entry.owasp_agentic)
        assert entry.owasp_llm == ()
        assert entry.mitre_atlas == ()
