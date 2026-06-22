"""Tests for bounded-swarm control ablation."""

from pathlib import Path
from unittest.mock import patch

from agentic_security_harness import cli
from agentic_security_harness.local_swarm import SWARM_SCENARIOS
from agentic_security_harness.local_swarm_ablation import (
    SwarmAblationMatrix,
    build_local_swarm_ablation_matrix,
    write_local_swarm_ablation_artifacts,
)
from agentic_security_harness.validation import validate_path


def _boom(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("network should not be used")


def test_ablation_matrix_maps_every_scenario_to_a_primary_control() -> None:
    matrix = build_local_swarm_ablation_matrix(created_at="")

    assert matrix.metrics.scenarios == len(SWARM_SCENARIOS)
    assert matrix.metrics.rows == len(SWARM_SCENARIOS)
    assert matrix.metrics.bounded_blocks == len(SWARM_SCENARIOS)
    assert matrix.metrics.vulnerable_when_primary_removed == len(SWARM_SCENARIOS)
    assert matrix.metrics.controls >= 5
    assert "authority_non_expansion" in matrix.metrics.coverage_by_control
    assert "label_provenance" in matrix.metrics.coverage_by_control


def test_ablation_artifacts_validate(tmp_path: Path) -> None:
    out = tmp_path / "ablation"
    matrix = build_local_swarm_ablation_matrix(created_at="")
    paths = write_local_swarm_ablation_artifacts(out, matrix)

    assert [path.name for path in paths] == [
        "local_swarm_ablation_matrix.json",
        "local_swarm_ablation_matrix.md",
        "run_index.json",
    ]
    assert validate_path(out).ok
    loaded = SwarmAblationMatrix.model_validate_json(
        (out / "local_swarm_ablation_matrix.json").read_text(encoding="utf-8")
    )
    assert loaded.metrics.bounded_blocks == loaded.metrics.rows


def test_cli_ablation_dry_run_uses_no_network(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch("urllib.request.urlopen", side_effect=_boom):
        rc = cli.main(["local-swarm-ablation", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_ablation_writes_valid_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "written"
    rc = cli.main(["local-swarm-ablation", "--write", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok
