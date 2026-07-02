import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.memory_rehydration_campaign import (
    build_memory_rehydration_campaign,
    declared_memory_rehydration_cases,
    declared_memory_rehydration_controls,
    render_memory_rehydration_summary,
    write_memory_rehydration_artifacts,
)
from agentic_security_harness.validation import validate_path


def test_memory_rehydration_cases_define_agentic_recall_family() -> None:
    cases = declared_memory_rehydration_cases()
    controls = declared_memory_rehydration_controls()

    assert len(cases) == 7
    assert len({case.case_id for case in cases}) == len(cases)
    assert len({case.scenario_id for case in cases}) == len(cases)
    assert all(len(case.propagation_path) >= 4 for case in cases)
    assert all(case.no_red_flag_path for case in cases)
    assert all(case.required_controls for case in cases)
    assert {control.control_id for control in controls} == {
        control for case in cases for control in case.required_controls
    }


def test_memory_rehydration_metrics_are_deterministic() -> None:
    summary = build_memory_rehydration_campaign(created_at="")
    metrics = summary.metrics

    assert metrics.cases == 7
    assert metrics.controls == 10
    assert metrics.pressure_axes == 9
    assert metrics.deterministic_rows == 91
    assert metrics.control_effect_rows == 10
    assert metrics.propagation_paths == 7
    assert metrics.naive_acceptances == 7
    assert metrics.bounded_acceptances == 0
    assert metrics.ablation_acceptances == 32
    assert metrics.benign_acceptances == 7
    assert metrics.benign_false_blocks == 0
    assert metrics.control_attribution_rate == 1.0


def test_memory_rehydration_ablation_attributes_controls() -> None:
    summary = build_memory_rehydration_campaign(created_at="")
    effects = {effect.control_id: effect for effect in summary.control_effects}

    expected = {
        "memory_source_provenance": 6,
        "memory_scope_binding": 3,
        "memory_ttl_enforcement": 2,
        "trust_level_preservation": 3,
        "current_user_intent_anchor": 4,
        "rehydration_authority_gate": 7,
        "recipient_scope_check": 3,
        "merge_source_isolation": 2,
        "handoff_revalidation": 1,
        "dependency_revalidation_gate": 1,
    }
    assert {
        control: effect.required_by_cases for control, effect in effects.items()
    } == expected
    assert {
        control: effect.ablation_acceptances for control, effect in effects.items()
    } == expected
    assert all(effect.bounded_acceptances == 0 for effect in effects.values())
    assert all(
        effect.blocked_by_full_contract == effect.required_by_cases
        for effect in effects.values()
    )


def test_memory_rehydration_rows_preserve_benign_path() -> None:
    summary = build_memory_rehydration_campaign(created_at="")
    rows = summary.deterministic_results

    assert all(
        not row.unsafe_chain_allowed for row in rows if row.mode == "bounded"
    )
    assert all(row.benign_passed for row in rows if row.mode == "benign")
    assert all(
        row.verifier_decision == "allow" for row in rows if row.mode == "benign"
    )
    assert all(row.context_fingerprint for row in rows)
    assert all(row.propagation_steps_observed >= 4 for row in rows)


def test_memory_rehydration_artifacts_validate_and_stay_sanitized(
    tmp_path: Path,
) -> None:
    out = tmp_path / "memory-rehydration"
    summary = build_memory_rehydration_campaign(created_at="")

    paths = write_memory_rehydration_artifacts(out, summary)
    result = validate_path(out)

    assert result.ok, result.errors
    assert result.memory_rehydration_campaign_dirs == ["memory-rehydration"]
    assert {path.name for path in paths} == {
        "memory_rehydration_summary.json",
        "memory_rehydration_report.md",
        "memory_rehydration_digest.json",
        "run_index.json",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert '"raw_prompt"' not in text
        assert '"raw_response"' not in text
        assert ".internal" not in text
    digest = json.loads((out / "memory_rehydration_digest.json").read_text())
    assert digest["live_memory_stores_present"] is False


def test_memory_rehydration_public_validation_rejects_private_artifact(
    tmp_path: Path,
) -> None:
    out = tmp_path / "memory-rehydration"
    write_memory_rehydration_artifacts(
        out,
        build_memory_rehydration_campaign(created_at=""),
    )
    (out / "memory_rehydration_private.json").write_text(
        json.dumps({"private_memory_chain": "private calculation notes"}),
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert any("private memory rehydration artifact" in error for error in result.errors)


def test_memory_rehydration_report_contains_agentic_non_claims() -> None:
    report = render_memory_rehydration_summary(
        build_memory_rehydration_campaign(created_at="")
    )

    assert "Memory Rehydration Authority Campaign" in report
    assert "Attacker Model" in report
    assert "Control Ablation Matrix" in report
    assert "No local or external models are called." in report
    assert "not proof that a deployed memory agent is safe" in report


def test_memory_rehydration_cli_write(tmp_path: Path) -> None:
    out = tmp_path / "memory-rehydration"

    rc = cli.main(["memory-rehydration-campaign", "--write", "--out", str(out)])

    assert rc == 0
    data = json.loads((out / "memory_rehydration_summary.json").read_text())
    assert data["metrics"]["bounded_acceptances"] == 0
    assert validate_path(out).ok
