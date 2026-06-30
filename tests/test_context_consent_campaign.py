import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.context_consent_campaign import (
    build_context_consent_campaign,
    declared_context_consent_cases,
    declared_context_consent_controls,
    render_context_consent_summary,
    write_context_consent_artifacts,
)
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
