import hashlib
import json
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.context_consent_campaign import (
    _build_control_effects,
    _build_metrics,
    build_context_consent_campaign,
    declared_context_consent_cases,
    declared_context_consent_controls,
    render_context_consent_summary,
    write_context_consent_artifacts,
)
from agentic_security_harness.run_manifest import (
    load_validated_run_manifests,
    load_validated_run_records,
)
from agentic_security_harness.rundb import index_runs, list_db_runs
from agentic_security_harness.stats import build_run_stats
from agentic_security_harness.validation import validate_path


def test_context_consent_cases_define_fifth_boundary_family() -> None:
    cases = declared_context_consent_cases()
    controls = declared_context_consent_controls()

    assert len(cases) == 5
    assert len({case.case_id for case in cases}) == len(cases)
    assert len({case.scenario_id for case in cases}) == len(cases)
    assert all(case.required_controls for case in cases)
    assert {control.control_id for control in controls} == {
        control for case in cases for control in case.required_controls
    }


def test_context_consent_metrics_are_deterministic() -> None:
    summary = build_context_consent_campaign(created_at="")
    metrics = summary.metrics

    assert metrics.cases == 5
    assert metrics.controls == 6
    assert metrics.deterministic_rows == 45
    assert metrics.control_effect_rows == 6
    assert metrics.naive_acceptances == 5
    assert metrics.bounded_acceptances == 0
    assert metrics.ablation_acceptances == 18
    assert metrics.benign_acceptances == 5
    assert metrics.benign_false_blocks == 0
    assert metrics.control_attribution_rate == 1.0


def test_context_consent_ablation_attributes_controls() -> None:
    summary = build_context_consent_campaign(created_at="")
    effects = {effect.control_id: effect for effect in summary.control_effects}

    assert effects["current_user_intent"].required_by_cases == 5
    assert effects["current_user_intent"].ablation_acceptances == 5
    assert effects["consent_receipt"].required_by_cases == 4
    assert effects["consent_receipt"].ablation_acceptances == 4
    assert effects["freshness_window"].required_by_cases == 1
    assert effects["freshness_window"].ablation_acceptances == 1
    assert all(effect.bounded_acceptances == 0 for effect in effects.values())
    assert all(
        effect.blocked_by_full_contract == effect.required_by_cases
        for effect in effects.values()
    )


def test_context_consent_rows_preserve_benign_path() -> None:
    summary = build_context_consent_campaign(created_at="")
    rows = summary.deterministic_results

    assert all(
        not row.risky_action_allowed for row in rows if row.mode == "bounded"
    )
    assert all(row.benign_passed for row in rows if row.mode == "benign")
    assert all(
        row.verifier_decision == "allow" for row in rows if row.mode == "benign"
    )
    assert all(row.context_fingerprint for row in rows)


def test_context_consent_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    out = tmp_path / "context-consent"
    summary = build_context_consent_campaign(created_at="")

    paths = write_context_consent_artifacts(out, summary)
    result = validate_path(out)

    assert result.ok, result.errors
    assert result.context_consent_campaign_dirs == ["context-consent"]
    assert {path.name for path in paths} == {
        "context_consent_summary.json",
        "context_consent_report.md",
        "context_consent_digest.json",
        "run_index.json",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert '"raw_prompt"' not in text
        assert '"raw_response"' not in text
        assert '"approval_token"' not in text
        assert ".internal" not in text


def test_valid_bounded_regression_is_expectation_failure_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "context-consent-regression"
    summary = build_context_consent_campaign(created_at="")
    bounded = next(
        row for row in summary.deterministic_results if row.mode == "bounded"
    )
    bounded.risky_action_allowed = True
    bounded.verifier_decision = "allow"
    bounded.blocked_by = []
    bounded.first_failure_step = "bounded consent gate failed"
    summary.control_effects = _build_control_effects(
        summary.cases,
        summary.deterministic_results,
    )
    summary.metrics = _build_metrics(
        summary.cases,
        summary.control_catalog,
        summary.deterministic_results,
        summary.control_effects,
    )

    write_context_consent_artifacts(out, summary)
    result = validate_path(out)

    assert not result.ok
    assert result.integrity_ok
    assert not result.expectations_ok
    assert result.errors == []
    assert any(
        "bounded accepted risky action" in mismatch
        for mismatch in result.expectation_mismatches
    )
    discovered = load_validated_run_manifests(tmp_path)
    assert [path.parent for path, _manifest in discovered] == [out]
    records = load_validated_run_records(tmp_path)
    assert len(records) == 1
    assert records[0].expectations_ok is False
    assert records[0].expectation_mismatch_count == 1
    assert records[0].manifest_sha256 == hashlib.sha256(
        (out / "run_index.json").read_bytes()
    ).hexdigest()
    assert len(records[0].validator_source_fingerprint) == 64
    db = tmp_path / "runs.db"
    assert index_runs(tmp_path, db) == 1
    indexed = list_db_runs(db)
    assert indexed[0]["expectation_status"] == "mismatch"
    assert indexed[0]["expectation_mismatch_count"] == 1
    assert "bounded accepted risky action" not in json.dumps(indexed)
    stats = build_run_stats(tmp_path)
    assert stats.by_expectation_status == {"mismatch": 1}
    assert stats.sources[0].expectation_status == "mismatch"
    assert stats.sources[0].expectation_mismatch_count == 1
    assert cli.main(["list-runs", "--root", str(tmp_path)]) == 0
    assert "expectations=mismatch(1)" in capsys.readouterr().out


def test_context_consent_validator_recomputes_control_effects(tmp_path: Path) -> None:
    out = tmp_path / "context-consent-effect-tamper"
    summary = build_context_consent_campaign(created_at="")
    summary.control_effects[0].bounded_acceptances += 1

    write_context_consent_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]
    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert result.expectations_ok
    assert any("control_effects do not match" in error for error in result.errors)


def test_context_consent_publisher_refuses_invalid_generation(tmp_path: Path) -> None:
    out = tmp_path / "context-consent-invalid-publication"
    summary = build_context_consent_campaign(created_at="")
    summary.control_effects[0].bounded_acceptances += 1

    with pytest.raises(ValueError, match="refusing to publish invalid evidence bundle"):
        write_context_consent_artifacts(out, summary)

    assert not out.exists()
    assert list(tmp_path.glob(".context-consent-invalid-publication.ash-staging-*")) == []


def test_context_consent_rejects_self_consistent_claim_contract_rewrite(
    tmp_path: Path,
) -> None:
    out = tmp_path / "context-consent-claim-rewrite"
    summary = build_context_consent_campaign(created_at="")
    summary.claim_boundary = "This rewritten claim overstates empirical effectiveness."
    write_context_consent_artifacts.__wrapped__(out, summary)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert any(
        "claim_boundary does not match the shipped campaign contract" in error
        for error in result.errors
    )


def test_context_consent_digest_cannot_omit_metric(tmp_path: Path) -> None:
    out = tmp_path / "context-consent-digest-omission"
    write_context_consent_artifacts(
        out,
        build_context_consent_campaign(created_at=""),
    )
    digest_path = out / "context_consent_digest.json"
    digest = json.loads(digest_path.read_text(encoding="utf-8"))
    digest["metrics"].pop("bounded_acceptances")
    digest_path.write_text(json.dumps(digest), encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("metrics fields mismatch" in error for error in result.errors)


def test_context_consent_public_validation_rejects_private_artifact(
    tmp_path: Path,
) -> None:
    out = tmp_path / "context-consent"
    write_context_consent_artifacts(out, build_context_consent_campaign(created_at=""))
    (out / "context_consent_private.json").write_text(
        json.dumps({"raw_prompt": "private approval token"}),
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert any("private context-consent artifact" in error for error in result.errors)


def test_context_consent_report_contains_non_claims() -> None:
    report = render_context_consent_summary(build_context_consent_campaign(created_at=""))

    assert "Context Consent Campaign" in report
    assert "Control Ablation Matrix" in report
    assert "No local or external models are called." in report
    assert "not proof that a deployed agent preserves consent" in report


def test_context_consent_cli_write(tmp_path: Path) -> None:
    out = tmp_path / "context-consent"

    rc = cli.main(["context-consent-campaign", "--write", "--out", str(out)])

    assert rc == 0
    data = json.loads((out / "context_consent_summary.json").read_text())
    assert data["metrics"]["bounded_acceptances"] == 0
    assert validate_path(out).ok
