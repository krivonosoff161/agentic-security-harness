"""Tests for the bounded local-swarm research runner (#61)."""

import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.external_openai_compatible import ExternalAPIError
from agentic_security_harness.local_swarm import (
    SWARM_SCENARIOS,
    build_swarm_metrics,
    estimate_request_count,
    evaluate_swarm_scenario,
    model_is_forbidden,
    run_local_swarm,
    write_local_swarm_artifacts,
)
from agentic_security_harness.validation import validate_path


def _boom(*args: object, **kwargs: object) -> MagicMock:
    raise AssertionError("network call attempted in dry-run path")


def _mock_swarm_open() -> Callable[..., MagicMock]:
    def _open(req: object, *args: object, **kwargs: object) -> MagicMock:
        body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        role = "unknown"
        for message in body.get("messages", []):
            text = str(message.get("content", ""))
            for line in text.splitlines():
                if line.startswith("Role: "):
                    role = line.split("Role: ", 1)[1].strip()
        resp = MagicMock()
        resp.read.return_value = json.dumps(
            {"choices": [{"message": {"content": f"{role} follows deterministic gate."}}]}
        ).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    return _open


@pytest.mark.parametrize("scenario", SWARM_SCENARIOS)
def test_bounded_swarm_blocks_each_boundary_scenario(scenario: str) -> None:
    naive = evaluate_swarm_scenario(scenario, "naive_swarm")  # type: ignore[arg-type]
    bounded = evaluate_swarm_scenario(scenario, "bounded_swarm")  # type: ignore[arg-type]

    assert naive.boundary_failure
    assert not bounded.boundary_failure
    assert bounded.verifier_blocked
    assert bounded.blocked_reasons


def test_metrics_show_bounded_reduction() -> None:
    summary = run_local_swarm(created_at="")

    assert summary.metrics.scenarios == len(SWARM_SCENARIOS)
    assert summary.metrics.monolith_boundary_failures == len(SWARM_SCENARIOS)
    assert summary.metrics.naive_swarm_boundary_failures == len(SWARM_SCENARIOS)
    assert summary.metrics.bounded_swarm_boundary_failures == 0
    assert summary.metrics.bounded_failure_reduction_vs_naive == 1.0
    assert summary.metrics.contract_coverage == 1.0
    assert summary.metrics.evidence_completeness == 1.0
    assert summary.metrics.unique_blocked_reasons >= 7
    assert summary.metrics.invalid_acceptances == len(SWARM_SCENARIOS) * 2


def test_scenario_suite_covers_expected_boundary_classes() -> None:
    expected = {
        "handoff_label_stripping",
        "authority_expansion",
        "tool_result_injection",
        "approval_laundering",
        "missing_envelope_recovery",
        "malformed_envelope",
        "verifier_outage",
        "memory_stale_recall",
        "cross_user_memory",
        "memory_trust_precedence",
        "memory_poisoned_recall",
        "memory_envelope_widening",
        "tool_output_authority_confusion",
        "multi_hop_label_laundering",
        "multi_hop_authority_laundering",
    }
    assert set(SWARM_SCENARIOS) == expected


@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    [
        ("memory_poisoned_recall", "trust_too_low"),
        ("memory_envelope_widening", "stored:allowed_recipients_expanded"),
        ("tool_output_authority_confusion", "authority_expansion"),
        ("multi_hop_label_laundering", "label_loss"),
        ("multi_hop_authority_laundering", "authority_expansion"),
    ],
)
def test_deep_attack_variants_block_on_expected_contract_reason(
    scenario: str,
    expected_reason: str,
) -> None:
    result = evaluate_swarm_scenario(scenario, "bounded_swarm")  # type: ignore[arg-type]

    assert not result.boundary_failure
    assert result.verifier_blocked
    assert expected_reason in result.blocked_reasons


def test_estimated_request_count_is_mode_role_sum() -> None:
    assert estimate_request_count(["handoff_label_stripping"], ["monolith"]) == 1
    assert estimate_request_count(["handoff_label_stripping"], ["naive_swarm"]) == 3
    assert estimate_request_count(["handoff_label_stripping"], ["bounded_swarm"]) == 4


def test_calculator_model_is_refused() -> None:
    assert model_is_forbidden("calculator:latest")
    with pytest.raises(ValueError, match="calculator model"):
        run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["monolith"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="calculator:latest",
        )


def test_request_cap_is_enforced() -> None:
    with pytest.raises(ValueError, match="exceeds max_requests"):
        run_local_swarm(
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=1,
        )


def test_artifacts_validate(tmp_path: Path) -> None:
    out = tmp_path / "swarm"
    summary = run_local_swarm(created_at="")
    write_local_swarm_artifacts(out, summary)

    assert (out / "local_swarm_summary.json").exists()
    assert (out / "local_swarm_report.md").exists()
    assert (out / "run_index.json").exists()
    assert validate_path(out).ok


def test_execute_collects_hashed_role_transcripts(tmp_path: Path) -> None:
    out = tmp_path / "swarm"
    with patch("urllib.request.urlopen", side_effect=_mock_swarm_open()):
        summary = run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["bounded_swarm"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=4,
            created_at="",
        )
    write_local_swarm_artifacts(out, summary)

    transcripts = summary.results[0].role_transcripts
    assert len(transcripts) == 4
    assert all(item.response_sha256 for item in transcripts)
    assert all("deterministic" in item.response_preview for item in transcripts)
    assert summary.metrics.role_transcript_hash_coverage == 1.0
    assert summary.metrics.adapter_error_rate == 0.0
    assert validate_path(out).ok


def test_adapter_errors_are_counted_without_turning_into_contract_failures() -> None:
    with patch(
        "agentic_security_harness.local_swarm.chat_completion",
        side_effect=ExternalAPIError("network unavailable"),
    ):
        summary = run_local_swarm(
            scenarios=["handoff_label_stripping"],
            modes=["bounded_swarm"],
            execute_model_calls=True,
            base_url="http://127.0.0.1:11434/v1",
            model="prometheus-qwen15b-lowctx:latest",
            max_requests=4,
            created_at="",
        )

    assert summary.metrics.bounded_swarm_boundary_failures == 0
    assert summary.metrics.adapter_error_rate == 1.0
    assert summary.metrics.role_transcript_hash_coverage == 0.0


def test_cli_dry_run_makes_no_network_call_and_no_files(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    with patch("urllib.request.urlopen", side_effect=_boom):
        rc = cli.main(["local-swarm", "--out", str(out)])

    assert rc == 0
    assert not out.exists()


def test_cli_write_dry_run_validates(tmp_path: Path) -> None:
    out = tmp_path / "dry-artifacts"
    rc = cli.main(["local-swarm", "--write-dry-run", "--out", str(out)])

    assert rc == 0
    assert validate_path(out).ok


def test_cli_refuses_calculator_before_network(tmp_path: Path) -> None:
    out = tmp_path / "blocked"
    with patch("urllib.request.urlopen", side_effect=_boom):
        rc = cli.main(["local-swarm", "--execute", "--model", "calculator:latest",
                       "--out", str(out)])

    assert rc == 1
    assert not out.exists()


def test_metric_helper_accepts_empty_results() -> None:
    metrics = build_swarm_metrics([], 0)
    assert metrics.results == 0
    assert metrics.bounded_failure_reduction_vs_naive == 0.0
