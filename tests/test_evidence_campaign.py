"""Tests for the bounded evidence campaign calculations."""

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.evidence_campaign import (
    CAMPAIGN_MODES,
    EvidenceCampaignSummary,
    build_evidence_campaign,
    declared_campaign_cases,
    render_campaign_report,
    write_evidence_campaign_artifacts,
)
from agentic_security_harness.validation import validate_path


def _boom(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("network should not be used")


def test_campaign_covers_four_claim_families_and_case_kinds() -> None:
    cases = declared_campaign_cases()

    assert {case.claim_family for case in cases} == {
        "data_boundary",
        "authority_delegation",
        "memory_governance",
        "bounded_swarm",
    }
    assert {case.case_kind for case in cases} >= {
        "attack",
        "benign",
        "bypass",
        "malformed",
        "multihop",
    }
    for family in {case.claim_family for case in cases}:
        family_cases = [case for case in cases if case.claim_family == family]
        assert any(case.ground_truth == "unsafe" for case in family_cases), family
        assert any(case.ground_truth == "safe" for case in family_cases), family
    assert len({case.case_id for case in cases}) == len(cases)


def test_campaign_confusion_metrics_are_calculated_from_observations() -> None:
    summary = build_evidence_campaign(created_at="2026-06-23T00:00:00Z")

    assert summary.metrics.cases == 24
    assert summary.metrics.observations == 24 * len(CAMPAIGN_MODES)
    assert summary.metrics.claim_families == 4

    monolith = summary.metrics.by_mode["monolith"]
    naive = summary.metrics.by_mode["naive_swarm"]
    bounded = summary.metrics.by_mode["bounded_swarm"]

    assert monolith.false_negative == 16
    assert naive.false_negative == 16
    assert bounded.true_positive == 16
    assert bounded.false_negative == 0
    assert bounded.false_positive == 0
    assert bounded.true_negative == 7
    assert bounded.inconclusive == 1
    assert bounded.attack_block_rate == 1.0
    assert bounded.benign_pass_rate == 1.0
    assert bounded.failure_rate == 0.0
    assert naive.failure_rate > bounded.failure_rate
    assert summary.metrics.control_effect_naive_to_bounded == naive.failure_rate
    assert summary.metrics.usability_cost_naive_to_bounded == 0.0


def test_campaign_family_metrics_keep_control_effect_and_usability_cost() -> None:
    summary = build_evidence_campaign()

    for family, metrics in summary.metrics.by_family.items():
        bounded = metrics.by_mode["bounded_swarm"]
        naive = metrics.by_mode["naive_swarm"]
        assert bounded.false_negative == 0, family
        assert bounded.false_positive == 0, family
        assert metrics.control_effect_naive_to_bounded == pytest.approx(
            naive.failure_rate - bounded.failure_rate
        )
        assert metrics.usability_cost_naive_to_bounded == 0.0


def test_campaign_ablation_matrix_shows_control_contribution() -> None:
    summary = build_evidence_campaign()

    assert summary.ablation_metrics.controls == 4
    assert summary.ablation_metrics.observations == summary.metrics.cases
    assert summary.ablation_metrics.unsafe_cases == 16
    assert summary.ablation_metrics.safe_cases == 7
    assert summary.ablation_metrics.unsafe_regressions == 16
    assert summary.ablation_metrics.benign_regressions == 0
    assert summary.ablation_metrics.unsafe_regression_rate == 1.0
    assert summary.ablation_metrics.benign_regression_rate == 0.0
    assert summary.ablation_metrics.regression_by_control == {
        "authority_verifier": 4,
        "envelope_verifier": 5,
        "memory_governance": 4,
        "swarm_verifier_auditor": 3,
    }
    assert all(
        item.ablated_confusion == "FN"
        for item in summary.ablation_observations
        if item.ground_truth == "unsafe"
    )
    assert all(
        item.ablated_confusion == "TN"
        for item in summary.ablation_observations
        if item.ground_truth == "safe"
    )


def test_campaign_report_keeps_non_claims_and_private_boundary() -> None:
    summary = build_evidence_campaign()
    text = render_campaign_report(summary)

    assert "Private/Public Boundary" in text
    assert "Raw model responses" in text
    assert "not a production safety proof" in text
    assert "No live multi-agent framework is certified" in text
    assert "Failure rate" in text
    assert "Control Ablation" in text
    assert "Unsafe regression rate" in text
    assert "`bounded_swarm`" in text


def test_campaign_artifacts_validate_and_digest_is_private_ready(tmp_path: Path) -> None:
    out = tmp_path / "campaign"
    summary = build_evidence_campaign(created_at="2026-06-23T00:00:00Z")
    paths = write_evidence_campaign_artifacts(out, summary)

    assert [path.name for path in paths] == [
        "evidence_campaign_summary.json",
        "evidence_campaign_report.md",
        "evidence_campaign_digest.json",
        "run_index.json",
    ]
    result = validate_path(out)
    assert result.ok
    assert result.evidence_campaign_dirs == ["campaign"]
    loaded = EvidenceCampaignSummary.model_validate_json(
        (out / "evidence_campaign_summary.json").read_text(encoding="utf-8")
    )
    assert loaded.metrics.by_mode["bounded_swarm"].false_negative == 0
    assert loaded.ablation_metrics.unsafe_regressions == 16
    digest = (out / "evidence_campaign_digest.json").read_text(encoding="utf-8")
    assert "artifact_hashes" in digest
    assert "ablation_metrics" in digest
    assert "Raw model responses" not in digest


def test_validator_recomputes_campaign_metrics(tmp_path: Path) -> None:
    out = tmp_path / "campaign-metric-tamper"
    summary = build_evidence_campaign(created_at="")
    summary.metrics.control_effect_naive_to_bounded += 0.1
    write_evidence_campaign_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("metrics do not match recomputed" in error for error in result.errors)


def test_validator_binds_observation_hashes_to_row_content(tmp_path: Path) -> None:
    out = tmp_path / "campaign-hash-tamper"
    summary = build_evidence_campaign(created_at="")
    summary.observations[0].decision = "review"
    summary.observations[0].confusion = "INCONCLUSIVE"
    write_evidence_campaign_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("result_hash mismatch" in error for error in result.errors)


def test_evidence_digest_cannot_omit_artifact_hash(tmp_path: Path) -> None:
    out = tmp_path / "campaign-digest-omission"
    write_evidence_campaign_artifacts(out, build_evidence_campaign(created_at=""))
    digest_path = out / "evidence_campaign_digest.json"
    digest = json.loads(digest_path.read_text(encoding="utf-8"))
    digest["artifact_hashes"].pop("observations")
    digest_path.write_text(json.dumps(digest), encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("digest projection mismatch" in error for error in result.errors)


def test_evidence_campaign_rejects_shipped_corpus_redefinition(tmp_path: Path) -> None:
    out = tmp_path / "campaign-corpus-redefinition"
    summary = build_evidence_campaign(created_at="")
    summary.cases[0].expected_safe_behavior += " rewritten"
    write_evidence_campaign_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert any(
        "summary does not match the shipped campaign specification" in error
        for error in result.errors
    )


def test_evidence_campaign_rejects_report_tamper_after_hash_rewrite(
    tmp_path: Path,
) -> None:
    out = tmp_path / "campaign-report-rewrite"
    write_evidence_campaign_artifacts(out, build_evidence_campaign(created_at=""))
    report_path = out / "evidence_campaign_report.md"
    report_path.write_text(
        report_path.read_text(encoding="utf-8") + "\nOverstated claim.\n",
        encoding="utf-8",
    )
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"][report_path.name] = hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("report projection mismatch" in error for error in result.errors)


def test_evidence_campaign_rejects_manifest_semantic_rewrite(tmp_path: Path) -> None:
    out = tmp_path / "campaign-manifest-rewrite"
    write_evidence_campaign_artifacts(out, build_evidence_campaign(created_at=""))
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outcomes"]["bounded_false_negative"] = 1
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("outcomes does not match summary projection" in error for error in result.errors)


def test_cli_evidence_campaign_dry_run_uses_no_network(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect", side_effect=_boom
    ):
        rc = cli.main(["evidence-campaign", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_evidence_campaign_writes_valid_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "written"
    rc = cli.main(["evidence-campaign", "--write", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok


def test_public_sanitized_evidence_campaign_example_validates() -> None:
    result = validate_path(Path("examples/evidence-campaign-sanitized"))

    assert result.ok
    assert result.evidence_campaign_dirs == ["evidence-campaign-sanitized"]
