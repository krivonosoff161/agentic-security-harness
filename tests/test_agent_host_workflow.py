from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentic_security_harness.agent_host_evaluator import (
    ADAPTER_ERROR_ACTIVITY,
    FINDING_ACTIVITY,
    PASS_ACTIVITY,
)
from agentic_security_harness.agent_host_workflow import (
    AgentHostSessionV1,
    AgentHostWorkflowContractError,
    SyntheticOwnedAgentWorkflowV1,
    build_agent_host_quickstart_v1,
    decode_agent_host_summary_v1,
    encode_agent_host_summary_v1,
    run_owned_agent_workflow_v1,
    validate_agent_host_bundle_v1,
    write_agent_host_quickstart_v1,
)
from agentic_security_harness.cli import _main
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.validation import validate_artifact_path

NOW = datetime(2026, 1, 1, tzinfo=UTC)
GIT_SHA = "1" * 40
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "agent-host-run-summary.v1.schema.json"
MANIFEST_PATH = ROOT / "schemas" / "agent-host-run-summary.v1.manifest.json"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "agent-host-run-summary-v1"


def test_quickstart_covers_every_pattern_in_both_modes() -> None:
    summary, results = build_agent_host_quickstart_v1()

    assert summary.case_count == 48
    assert summary.outcomes == {
        "pass": 24,
        "finding": 24,
        "inconclusive": 0,
        "adapter_error": 0,
    }
    assert len(results) == 48
    assert [case.pattern_id for case in summary.cases[::2]] == [
        pattern.pattern_id for pattern in seed_patterns()
    ]
    assert all(case.mode == "protected" for case in summary.cases[::2])
    assert all(case.mode == "vulnerable" for case in summary.cases[1::2])
    assert all(result.evaluation.outcome == "pass" for result in results[::2])
    assert all(result.evaluation.outcome == "finding" for result in results[1::2])
    assert all(result.recording.events[-1].activity == PASS_ACTIVITY for result in results[::2])
    assert all(
        result.recording.events[-1].activity == FINDING_ACTIVITY for result in results[1::2]
    )


def test_public_quickstart_contains_no_raw_payload_or_authority() -> None:
    summary, results = build_agent_host_quickstart_v1()
    payload = encode_agent_host_summary_v1(summary) + b"".join(
        event.model_dump_json().encode("utf-8")
        for result in results
        for event in result.recording.events
    )
    lowered = payload.lower()

    for forbidden in (
        b'"raw_prompt":',
        b'"tool_arguments":',
        b'"tool_output":',
        b'"api_key":',
        b'"credential":',
        b'"base_url":',
        b'"authorization":',
        b"c:\\",
        b"/home/",
    ):
        assert forbidden not in lowered
    assert summary.network_mode == "off"
    assert summary.raw_payload_policy == "digests_only"
    assert summary.operational_authority == "none"
    assert summary.producer_attestation == "unattested"


def test_owned_workflow_exception_becomes_sanitized_adapter_error() -> None:
    class FailingWorkflow:
        def run(self, pattern: object, session: AgentHostSessionV1) -> None:
            session.observe(
                source_surface="app",
                activity="agent_host.task_received",
                data_commitment_sha256="2" * 64,
            )
            raise RuntimeError("SECRET-SENTINEL raw provider response")

    result = run_owned_agent_workflow_v1(
        pattern=seed_patterns()[0],
        workflow=FailingWorkflow(),
        repository_sha=GIT_SHA,
        occurred_at=NOW,
    )
    encoded = result.recording.model_dump_json().encode("utf-8")

    assert result.recording.terminal_status == "adapter_error"
    assert result.recording.events[-1].activity == ADAPTER_ERROR_ACTIVITY
    assert result.evaluation.outcome == "adapter_error"
    assert b"SECRET-SENTINEL" not in encoded
    assert b"provider response" not in encoded


def test_session_is_append_only_after_terminal() -> None:
    session = AgentHostSessionV1(
        pattern_id=seed_patterns()[0].pattern_id,
        repository_sha=GIT_SHA,
        occurred_at=NOW,
    )
    session.boundary_preserved()

    with pytest.raises(AgentHostWorkflowContractError, match="terminal"):
        session.observe(
            source_surface="tool",
            activity="tool.requested",
            data_commitment_sha256="3" * 64,
        )


def test_exception_after_terminal_fails_closed_without_returning_pass() -> None:
    class InvalidWorkflow:
        def run(self, pattern: object, session: AgentHostSessionV1) -> None:
            session.boundary_preserved()
            raise RuntimeError("raw secret-like failure")

    with pytest.raises(AgentHostWorkflowContractError, match="after recording"):
        run_owned_agent_workflow_v1(
            pattern=seed_patterns()[0],
            workflow=InvalidWorkflow(),
            repository_sha=GIT_SHA,
            occurred_at=NOW,
        )


def test_summary_canonical_round_trip_and_duplicate_rejection() -> None:
    summary, _ = build_agent_host_quickstart_v1()
    encoded = encode_agent_host_summary_v1(summary)
    assert decode_agent_host_summary_v1(encoded) == summary

    duplicate = encoded.replace(b'{"case_count":48,', b'{"case_count":48,"case_count":48,')
    with pytest.raises(AgentHostWorkflowContractError):
        decode_agent_host_summary_v1(duplicate)


def test_quickstart_bundle_is_atomic_validated_and_content_bound(tmp_path: Path) -> None:
    out = tmp_path / "agent-host"
    summary = write_agent_host_quickstart_v1(out)

    assert out.is_dir()
    assert validate_agent_host_bundle_v1(out) == summary
    result = validate_artifact_path(out)
    assert result.ok, result.errors
    assert result.agent_host_dirs == ["agent-host"]
    manifest = json.loads((out / "run_index.json").read_text(encoding="utf-8"))
    assert manifest["run_kind"] == "agent_host"
    assert manifest["metadata"]["raw_payload_policy"] == "digests_only"
    assert len(manifest["artifacts"]) == 98


@pytest.mark.parametrize(
    "relative_path",
    (
        "agent_host_summary.json",
        "recordings/indirect_prompt_injection_via_tool_output.protected.json",
        "evaluations/indirect_prompt_injection_via_tool_output.protected.json",
        "run_index.json",
    ),
)
def test_bundle_tamper_fails_validation(tmp_path: Path, relative_path: str) -> None:
    out = tmp_path / "agent-host"
    write_agent_host_quickstart_v1(out)
    path = out / relative_path
    if relative_path == "run_index.json":
        path.write_bytes(
            path.read_bytes().replace(
                b'"run_kind": "agent_host"',
                b'"run_kind": "run"',
            )
        )
    else:
        path.write_bytes(path.read_bytes() + b" ")

    result = validate_artifact_path(out)
    assert not result.integrity_ok


def test_bundle_extra_file_fails_validation(tmp_path: Path) -> None:
    out = tmp_path / "agent-host"
    write_agent_host_quickstart_v1(out)
    (out / "extra.json").write_text("{}\n", encoding="utf-8")

    result = validate_artifact_path(out)
    assert not result.integrity_ok


def test_bundle_hardlinked_recording_fails_before_content_acceptance(tmp_path: Path) -> None:
    out = tmp_path / "agent-host"
    write_agent_host_quickstart_v1(out)
    path = out / "recordings/indirect_prompt_injection_via_tool_output.protected.json"
    replacement = tmp_path / "replacement.json"
    path.chmod(0o600)
    path.unlink()
    os.link(out / "agent_host_summary.json", replacement)
    os.link(replacement, path)

    with pytest.raises(AgentHostWorkflowContractError, match="single-link"):
        validate_agent_host_bundle_v1(out)


def test_bundle_symlinked_recording_directory_fails_before_read(tmp_path: Path) -> None:
    out = tmp_path / "agent-host"
    write_agent_host_quickstart_v1(out)
    recordings = out / "recordings"
    moved = out / "recordings-real"
    recordings.rename(moved)
    try:
        recordings.symlink_to(moved, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable on this host")

    with pytest.raises(AgentHostWorkflowContractError, match="traverse"):
        validate_agent_host_bundle_v1(out)


def test_quickstart_refuses_existing_destination(tmp_path: Path) -> None:
    out = tmp_path / "agent-host"
    out.mkdir()
    with pytest.raises(ValueError, match="must not already exist"):
        write_agent_host_quickstart_v1(out)


def test_cli_writes_valid_bundle_without_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "agent-host"
    assert _main(["agent-host-quickstart", "--out", str(out)]) == 0
    terminal = capsys.readouterr().out

    assert "cases: 48" in terminal
    assert "network: off" in terminal
    assert "operational authority: none" in terminal
    assert validate_artifact_path(out).ok


def test_source_has_no_dynamic_plugin_process_or_network_surface() -> None:
    source = Path(
        "src/agentic_security_harness/agent_host_workflow.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        "subprocess",
        "socket",
        "requests",
        "httpx",
        "import_module",
        "entry_points",
        "eval(",
        "exec(",
    )
    assert not any(token in source for token in forbidden)


def test_reference_workflow_is_explicit_python_api() -> None:
    pattern = seed_patterns()[0]
    result = run_owned_agent_workflow_v1(
        pattern=pattern,
        workflow=SyntheticOwnedAgentWorkflowV1("protected"),
        repository_sha=GIT_SHA,
        occurred_at=NOW,
    )
    assert result.evaluation.outcome == "pass"


def test_schema_manifest_and_fixtures_are_content_bound() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == (
        "agent-host-run-summary-contract-manifest-v1.0"
    )
    assert manifest["case_count"] == 48
    assert manifest["pattern_count"] == 24
    assert manifest["network_mode"] == "off"
    assert manifest["raw_payload_policy"] == "digests_only"
    assert manifest["operational_authority"] == "none"
    assert manifest["schema"]["sha256"] == hashlib.sha256(
        SCHEMA_PATH.read_bytes()
    ).hexdigest()
    for section in (
        "recording_contract",
        "evaluation_contract",
        "producer",
        "bundle_validator",
        "public_api",
        "cli",
        "fixture_runner",
    ):
        item = manifest[section]
        assert item["sha256"] == hashlib.sha256(
            (ROOT / item["path"]).read_bytes()
        ).hexdigest()
    expected_paths = sorted(
        path.relative_to(ROOT).as_posix() for path in FIXTURE_ROOT.rglob("*.json")
    )
    assert sorted(item["path"] for item in manifest["fixtures"]) == expected_paths
    for item in manifest["fixtures"]:
        content = (ROOT / item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(content).hexdigest()
        if item["expected"] == "accept":
            decode_agent_host_summary_v1(content)
        else:
            with pytest.raises(AgentHostWorkflowContractError):
                decode_agent_host_summary_v1(content)
