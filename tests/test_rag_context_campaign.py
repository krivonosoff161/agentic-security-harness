import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.rag_context_campaign import (
    build_rag_context_campaign,
    declared_rag_context_cases,
    declared_rag_context_controls,
    render_rag_context_summary,
    write_rag_context_artifacts,
)
from agentic_security_harness.validation import validate_path


def test_rag_context_cases_define_agentic_propagation_family() -> None:
    cases = declared_rag_context_cases()
    controls = declared_rag_context_controls()

    assert len(cases) == 7
    assert len({case.case_id for case in cases}) == len(cases)
    assert len({case.scenario_id for case in cases}) == len(cases)
    assert all(len(case.propagation_path) >= 4 for case in cases)
    assert all(case.no_red_flag_path for case in cases)
    assert all(case.required_controls for case in cases)
    assert {control.control_id for control in controls} == {
        control for case in cases for control in case.required_controls
    }


def test_rag_context_metrics_are_deterministic() -> None:
    summary = build_rag_context_campaign(created_at="")
    metrics = summary.metrics

    assert metrics.cases == 7
    assert metrics.controls == 10
    assert metrics.pressure_axes == 8
    assert metrics.deterministic_rows == 91
    assert metrics.control_effect_rows == 10
    assert metrics.propagation_paths == 7
    assert metrics.naive_acceptances == 7
    assert metrics.bounded_acceptances == 0
    assert metrics.ablation_acceptances == 30
    assert metrics.benign_acceptances == 7
    assert metrics.benign_false_blocks == 0
    assert metrics.control_attribution_rate == 1.0


def test_rag_context_ablation_attributes_controls() -> None:
    summary = build_rag_context_campaign(created_at="")
    effects = {effect.control_id: effect for effect in summary.control_effects}

    expected = {
        "source_provenance": 7,
        "retrieval_trust_label": 2,
        "context_instruction_split": 4,
        "rank_is_not_authority": 2,
        "citation_permission_split": 3,
        "summary_provenance_preservation": 2,
        "planner_authority_gate": 6,
        "cross_document_independence": 1,
        "memory_quarantine": 1,
        "handoff_revalidation": 2,
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


def test_rag_context_rows_preserve_benign_path() -> None:
    summary = build_rag_context_campaign(created_at="")
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


def test_rag_context_artifacts_validate_and_stay_sanitized(tmp_path: Path) -> None:
    out = tmp_path / "rag-context"
    summary = build_rag_context_campaign(created_at="")

    paths = write_rag_context_artifacts(out, summary)
    result = validate_path(out)

    assert result.ok, result.errors
    assert result.rag_context_campaign_dirs == ["rag-context"]
    assert {path.name for path in paths} == {
        "rag_context_summary.json",
        "rag_context_report.md",
        "rag_context_digest.json",
        "run_index.json",
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert '"raw_prompt"' not in text
        assert '"raw_response"' not in text
        assert '"live_rag_system"' not in text
        assert ".internal" not in text


def test_rag_context_public_validation_rejects_private_artifact(
    tmp_path: Path,
) -> None:
    out = tmp_path / "rag-context"
    write_rag_context_artifacts(out, build_rag_context_campaign(created_at=""))
    (out / "rag_context_private.json").write_text(
        json.dumps({"private_payload_chain": "private calculation notes"}),
        encoding="utf-8",
    )

    result = validate_path(out)

    assert not result.ok
    assert any("private RAG context artifact" in error for error in result.errors)


def test_rag_context_report_contains_agentic_non_claims() -> None:
    report = render_rag_context_summary(build_rag_context_campaign(created_at=""))

    assert "RAG Context Authority Campaign" in report
    assert "Attacker Model" in report
    assert "Control Ablation Matrix" in report
    assert "No local or external models are called." in report
    assert "not proof that a deployed RAG agent is safe" in report


def test_rag_context_cli_write(tmp_path: Path) -> None:
    out = tmp_path / "rag-context"

    rc = cli.main(["rag-context-campaign", "--write", "--out", str(out)])

    assert rc == 0
    data = json.loads((out / "rag_context_summary.json").read_text())
    assert data["metrics"]["bounded_acceptances"] == 0
    assert validate_path(out).ok
