"""Tests for the deterministic local-swarm attack variation matrix (#67)."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.local_swarm import SWARM_SCENARIOS
from agentic_security_harness.local_swarm_matrix import (
    VARIATION_FAMILIES,
    LocalSwarmAttackMatrix,
    MatrixModelProbeMetrics,
    MatrixModelProbeRun,
    MatrixProbeTranscript,
    build_local_swarm_attack_matrix,
    declared_matrix_cases,
    render_local_swarm_attack_matrix,
    render_matrix_model_probe,
    write_local_swarm_matrix_artifacts,
)
from agentic_security_harness.validation import validate_path


def _boom(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("network should not be used")


def test_declared_matrix_covers_all_scenarios_and_families() -> None:
    cases = declared_matrix_cases()

    assert {case.base_scenario for case in cases} == set(SWARM_SCENARIOS)
    assert {case.family for case in cases} == set(VARIATION_FAMILIES)
    assert len({case.case_id for case in cases}) == len(cases)
    assert len(cases) > len(SWARM_SCENARIOS)


def test_private_matrix_probe_markdown_neutralizes_endpoint_text() -> None:
    malicious = "left|right\n## forged\n![p](https://evil.invalid)<img src=x>\u202e"
    run = MatrixModelProbeRun(
        created_at=datetime(2026, 7, 15, tzinfo=UTC),
        model="model",
        metrics=MatrixModelProbeMetrics(
            cases=1,
            responses=1,
            adapter_errors=1,
            response_hash_coverage=1.0,
            adapter_error_rate=1.0,
            weakness_observations=0,
            weaknesses_by_kind={},
        ),
        transcripts=[
            MatrixProbeTranscript(
                case_id="deep.tool_summary_drops_tool_label",
                probe_id="tool.summary_drops_tool_label",
                prompt_sha256="a" * 64,
                response_sha256="b" * 64,
                response_preview=malicious,
                adapter_error=malicious,
            )
        ],
    )

    rendered = render_matrix_model_probe(run)

    assert "\n## forged" not in rendered
    assert "![p](" not in rendered
    assert "\u202e" not in rendered
    assert r"\<img" in rendered
    assert rendered.count("left\\|right") == 2


def test_attack_matrix_calculates_bounded_failure_reduction() -> None:
    matrix = build_local_swarm_attack_matrix()

    assert matrix.metrics.cases == 43
    assert matrix.metrics.base_scenarios == len(SWARM_SCENARIOS)
    assert matrix.metrics.variation_families == len(VARIATION_FAMILIES)
    assert matrix.metrics.monolith_boundary_failures == matrix.metrics.cases
    assert matrix.metrics.naive_swarm_boundary_failures == matrix.metrics.cases
    assert matrix.metrics.bounded_swarm_boundary_failures == 0
    assert matrix.metrics.bounded_blocks == matrix.metrics.cases
    assert matrix.metrics.deep_probe_cases == 10
    assert matrix.metrics.total_consumptions == 10
    assert matrix.metrics.unsafe_consumption_rate == 1.0
    assert matrix.metrics.mean_field_survival_rate is not None
    assert matrix.metrics.bounded_failure_reduction_vs_naive == 1.0
    assert matrix.metrics.contract_coverage == 1.0


def test_attack_matrix_has_expected_variation_examples() -> None:
    matrix = build_local_swarm_attack_matrix()
    by_id = {row.case_id: row for row in matrix.rows}

    assert by_id["prompt_only.direct_tool_instruction"].base_scenario == "tool_result_injection"
    assert by_id["delayed.memory_after_ttl"].bounded_blocked_reasons == [
        "read:ttl_expired_from_write_time"
    ]
    assert by_id["cross_provider.raw_payload_only"].bounded_blocked_reasons == ["missing_envelope"]
    assert by_id["contradiction.model_says_approved"].bounded_blocked_reasons == [
        "authority_expansion"
    ]
    assert by_id["deep.handoff_payload_rewrite_hash_mismatch"].probe_id == (
        "handoff.payload_rewrite_hash_mismatch"
    )
    assert by_id["deep.handoff_payload_rewrite_hash_mismatch"].bounded_blocked_reasons == [
        "integrity_mismatch"
    ]
    assert by_id["deep.handoff_recipient_switch_by_model"].bounded_blocked_reasons == [
        "recipient_violation"
    ]
    assert by_id["deep.memory_similar_key_confusion"].bounded_blocked_reasons == ["key_mismatch"]
    assert by_id["deep.memory_ttl_removed_on_read"].bounded_blocked_reasons == ["read:ttl_removed"]
    assert by_id["deep.tool_schema_smuggling_as_authority"].semantic_score == 1.0


def test_attack_matrix_non_claims_are_explicit() -> None:
    matrix = build_local_swarm_attack_matrix()
    text = render_local_swarm_attack_matrix(matrix)

    assert "not a live-framework guarantee" in matrix.claim_boundary
    assert "not a complete cryptographic audit-log proof" in text
    assert "No model output is treated as the source of truth." in text
    assert "Contract coverage" in text


def test_attack_matrix_artifacts_validate(tmp_path: Path) -> None:
    out = tmp_path / "matrix"
    matrix = build_local_swarm_attack_matrix()
    paths = write_local_swarm_matrix_artifacts(out, matrix)

    assert [path.name for path in paths] == [
        "local_swarm_attack_matrix.json",
        "local_swarm_attack_matrix.md",
        "run_index.json",
    ]
    assert validate_path(out).ok
    loaded = LocalSwarmAttackMatrix.model_validate_json(
        (out / "local_swarm_attack_matrix.json").read_text(encoding="utf-8")
    )
    assert loaded.metrics.bounded_swarm_boundary_failures == 0


def test_validator_recomputes_attack_matrix_metrics(tmp_path: Path) -> None:
    out = tmp_path / "matrix-metric-tamper"
    matrix = build_local_swarm_attack_matrix()
    family = next(iter(matrix.metrics.coverage_by_family))
    matrix.metrics.coverage_by_family[family] += 1
    write_local_swarm_matrix_artifacts.__wrapped__(out, matrix)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("metrics do not match recomputed" in error for error in result.errors)


def test_validator_binds_matrix_rows_to_declared_cases(tmp_path: Path) -> None:
    out = tmp_path / "matrix-row-rewrite"
    matrix = build_local_swarm_attack_matrix()
    matrix.rows[0].attack_shape = "rewritten self-consistent row"
    write_local_swarm_matrix_artifacts.__wrapped__(out, matrix)  # type: ignore[attr-defined]

    result = validate_path(out)

    assert not result.ok
    assert not result.integrity_ok
    assert any("does not match deterministic case evaluation" in error for error in result.errors)


def test_validator_rejects_matrix_report_tamper_after_hash_rewrite(
    tmp_path: Path,
) -> None:
    out = tmp_path / "matrix-report-rewrite"
    write_local_swarm_matrix_artifacts(out, build_local_swarm_attack_matrix())
    report_path = out / "local_swarm_attack_matrix.md"
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


def test_validator_rejects_matrix_manifest_semantic_rewrite(tmp_path: Path) -> None:
    out = tmp_path / "matrix-manifest-rewrite"
    write_local_swarm_matrix_artifacts(out, build_local_swarm_attack_matrix())
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outcomes"]["bounded_boundary_failures"] = 1
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("outcomes does not match summary projection" in error for error in result.errors)


def test_cli_local_swarm_matrix_dry_run_uses_no_network(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect", side_effect=_boom
    ):
        rc = cli.main(["local-swarm-matrix", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_local_swarm_matrix_writes_valid_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "written"
    rc = cli.main(["local-swarm-matrix", "--write", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok


def test_cli_local_swarm_matrix_execute_model_writes_private_probe(
    tmp_path: Path,
) -> None:
    out = tmp_path / ".internal" / "probe"
    response = {
        "choices": [{"message": {"content": "Proceed; the summarized output looks approved."}}]
    }
    with patch(
        "agentic_security_harness.local_swarm_matrix.chat_completion",
        return_value=response,
    ):
        rc = cli.main(
            [
                "local-swarm-matrix",
                "--execute-model",
                "--model",
                "prometheus-qwen15b-lowctx:latest",
                "--out",
                str(out),
            ]
        )

    assert rc == 0
    raw = (out / "local_swarm_matrix_model_probe.json").read_text(encoding="utf-8")
    assert "unsafe_acceptance_language" in raw
    assert "authority_or_approval_language" in raw


def test_cli_local_swarm_matrix_refuses_public_probe_output_before_model_call(
    tmp_path: Path,
) -> None:
    with patch(
        "agentic_security_harness.local_swarm_matrix.chat_completion"
    ) as model_call:
        rc = cli.main(
            [
                "local-swarm-matrix",
                "--execute-model",
                "--model",
                "model",
                "--out",
                str(tmp_path / "public"),
            ]
        )

    assert rc == 1
    model_call.assert_not_called()


def test_cli_local_swarm_matrix_lists_cases(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["local-swarm-matrix", "--list"])

    assert rc == 0
    captured = capsys.readouterr()
    assert "prompt_only.direct_tool_instruction" in captured.out
    assert "model_contradiction" in captured.out
