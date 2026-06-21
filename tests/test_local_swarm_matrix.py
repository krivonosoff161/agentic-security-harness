"""Tests for the deterministic local-swarm attack variation matrix (#67)."""

from pathlib import Path
from unittest.mock import patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.local_swarm import SWARM_SCENARIOS
from agentic_security_harness.local_swarm_matrix import (
    VARIATION_FAMILIES,
    LocalSwarmAttackMatrix,
    build_local_swarm_attack_matrix,
    declared_matrix_cases,
    render_local_swarm_attack_matrix,
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


def test_attack_matrix_calculates_bounded_failure_reduction() -> None:
    matrix = build_local_swarm_attack_matrix()

    assert matrix.metrics.cases == 33
    assert matrix.metrics.base_scenarios == len(SWARM_SCENARIOS)
    assert matrix.metrics.variation_families == len(VARIATION_FAMILIES)
    assert matrix.metrics.monolith_boundary_failures == matrix.metrics.cases
    assert matrix.metrics.naive_swarm_boundary_failures == matrix.metrics.cases
    assert matrix.metrics.bounded_swarm_boundary_failures == 0
    assert matrix.metrics.bounded_blocks == matrix.metrics.cases
    assert matrix.metrics.bounded_failure_reduction_vs_naive == 1.0
    assert matrix.metrics.contract_coverage == 1.0


def test_attack_matrix_has_expected_variation_examples() -> None:
    matrix = build_local_swarm_attack_matrix()
    by_id = {row.case_id: row for row in matrix.rows}

    assert by_id["prompt_only.direct_tool_instruction"].base_scenario == "tool_result_injection"
    assert by_id["delayed.memory_after_ttl"].bounded_blocked_reasons == [
        "read:ttl_expired_from_write_time"
    ]
    assert by_id["cross_provider.raw_payload_only"].bounded_blocked_reasons == [
        "missing_envelope"
    ]
    assert by_id["contradiction.model_says_approved"].bounded_blocked_reasons == [
        "authority_expansion"
    ]


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


def test_cli_local_swarm_matrix_dry_run_uses_no_network(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch("urllib.request.urlopen", side_effect=_boom):
        rc = cli.main(["local-swarm-matrix", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_local_swarm_matrix_writes_valid_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "written"
    rc = cli.main(["local-swarm-matrix", "--write", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok


def test_cli_local_swarm_matrix_lists_cases(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["local-swarm-matrix", "--list"])

    assert rc == 0
    captured = capsys.readouterr()
    assert "prompt_only.direct_tool_instruction" in captured.out
    assert "model_contradiction" in captured.out
