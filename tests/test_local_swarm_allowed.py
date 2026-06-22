"""Tests for benign allowed-flow utility checks in the bounded swarm."""

from pathlib import Path
from unittest.mock import patch

from agentic_security_harness import cli
from agentic_security_harness.local_swarm_allowed import (
    ALLOWED_FLOW_IDS,
    AllowedFlowSuite,
    build_allowed_flow_suite,
    write_allowed_flow_artifacts,
)
from agentic_security_harness.validation import validate_path


def _boom(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("network should not be used")


def test_allowed_flow_suite_passes_all_benign_cases() -> None:
    suite = build_allowed_flow_suite(created_at="")

    assert suite.metrics.flows == len(ALLOWED_FLOW_IDS)
    assert suite.metrics.allowed_passes == suite.metrics.flows
    assert suite.metrics.unexpected_blocks == 0
    assert suite.metrics.false_positive_rate == 0.0
    assert {result.boundary_kind for result in suite.results} == {"handoff", "memory"}


def test_allowed_flow_artifacts_validate(tmp_path: Path) -> None:
    out = tmp_path / "allowed"
    suite = build_allowed_flow_suite(created_at="")
    paths = write_allowed_flow_artifacts(out, suite)

    assert [path.name for path in paths] == [
        "local_swarm_allowed_flows.json",
        "local_swarm_allowed_flows.md",
        "run_index.json",
    ]
    assert validate_path(out).ok
    loaded = AllowedFlowSuite.model_validate_json(
        (out / "local_swarm_allowed_flows.json").read_text(encoding="utf-8")
    )
    assert loaded.metrics.unexpected_blocks == 0


def test_cli_allowed_flow_dry_run_uses_no_network(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch("urllib.request.urlopen", side_effect=_boom):
        rc = cli.main(["local-swarm-allowed", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_allowed_flow_writes_valid_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "written"
    rc = cli.main(["local-swarm-allowed", "--write", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok
