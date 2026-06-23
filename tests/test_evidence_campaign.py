"""Tests for the bounded evidence campaign calculations."""

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

    assert summary.metrics.cases == 16
    assert summary.metrics.observations == 16 * len(CAMPAIGN_MODES)
    assert summary.metrics.claim_families == 4

    monolith = summary.metrics.by_mode["monolith"]
    naive = summary.metrics.by_mode["naive_swarm"]
    bounded = summary.metrics.by_mode["bounded_swarm"]

    assert monolith.false_negative == 11
    assert naive.false_negative == 11
    assert bounded.true_positive == 11
    assert bounded.false_negative == 0
    assert bounded.false_positive == 0
    assert bounded.true_negative == 4
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


def test_campaign_report_keeps_non_claims_and_private_boundary() -> None:
    summary = build_evidence_campaign()
    text = render_campaign_report(summary)

    assert "Private/Public Boundary" in text
    assert "Raw model responses" in text
    assert "not a production safety proof" in text
    assert "No live multi-agent framework is certified" in text
    assert "Failure rate" in text
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
    digest = (out / "evidence_campaign_digest.json").read_text(encoding="utf-8")
    assert "artifact_hashes" in digest
    assert "Raw model responses" not in digest


def test_cli_evidence_campaign_dry_run_uses_no_network(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch("urllib.request.urlopen", side_effect=_boom):
        rc = cli.main(["evidence-campaign", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_evidence_campaign_writes_valid_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "written"
    rc = cli.main(["evidence-campaign", "--write", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok
