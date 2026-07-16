"""Fail-closed authority defaults for every CLI side-effect class."""

import argparse
import ast
import re
from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.cli import build_parser

ROOT = Path(__file__).resolve().parent.parent

READ_ONLY_COMMANDS = {
    "validate",
    "targets",
    "scenarios",
    "external-presets",
    "list-runs",
}
COMMAND_AUTHORIZES_BOUNDED_WRITES = {
    "run",
    "compare",
    "run-matrix",
    "index-runs",
    "diff-runs",
    "compare-models",
    "evidence-quality",
    "stats",
    "report",
    "showcase",
}
MODE_AUTHORIZES_BOUNDED_PRIVATE_WRITES = {"trading-stand"}


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    action = next(
        item
        for item in parser._actions
        if isinstance(item, argparse._SubParsersAction)
    )
    return action.choices


def test_sensitive_cli_actions_are_disabled_by_default() -> None:
    parser = build_parser()
    cases = {
        "run-external": (
            ["run-external", "--base-url", "http://localhost/v1", "--model", "m"],
            ("execute",),
        ),
        "external-check": (
            ["external-check", "--base-url", "http://localhost/v1", "--model", "m"],
            ("live",),
        ),
        "local-suite": (["local-suite"], ("execute", "run_showcase")),
        "local-swarm": (["local-swarm"], ("execute", "write_dry_run")),
        "local-swarm-matrix": (
            ["local-swarm-matrix"],
            ("write", "execute_model"),
        ),
        "evidence-campaign": (["evidence-campaign"], ("write",)),
        "secret-leak-campaign": (
            ["secret-leak-campaign"],
            ("write", "execute_model", "execute_variations"),
        ),
        "semantic-drift-campaign": (
            ["semantic-drift-campaign"],
            ("write", "execute"),
        ),
        "semantic-propagation-campaign": (
            ["semantic-propagation-campaign"],
            ("write", "execute"),
        ),
        "swarm-defense-contour": (["swarm-defense-contour"], ("write",)),
        "swarm-defense-live-campaign": (["swarm-defense-live-campaign"], ("execute",)),
        "marketing-web-injection-campaign": (
            ["marketing-web-injection-campaign"],
            ("write",),
        ),
        "swarm-resilience-campaign": (["swarm-resilience-campaign"], ("write",)),
        "context-consent-campaign": (["context-consent-campaign"], ("write",)),
        "tool-authority-campaign": (["tool-authority-campaign"], ("write",)),
        "rag-context-campaign": (["rag-context-campaign"], ("write",)),
        "planner-task-campaign": (["planner-task-campaign"], ("write",)),
        "memory-rehydration-campaign": (["memory-rehydration-campaign"], ("write",)),
        "marketing-web-live-campaign": (["marketing-web-live-campaign"], ("execute",)),
        "doctor": (["doctor"], ("live_local",)),
        "retention": (["retention"], ("apply", "accept_unsigned_chronology")),
    }

    for command, (argv, attributes) in cases.items():
        args = parser.parse_args(argv)
        for attribute in attributes:
            assert getattr(args, attribute) is False, (command, attribute)

    classified = (
        READ_ONLY_COMMANDS
        | COMMAND_AUTHORIZES_BOUNDED_WRITES
        | MODE_AUTHORIZES_BOUNDED_PRIVATE_WRITES
        | set(cases)
    )
    assert set(_subcommands(parser)) == classified


def test_every_optional_boolean_cli_action_is_false_by_default() -> None:
    for command, parser in _subcommands(build_parser()).items():
        for action in parser._actions:
            if isinstance(action, argparse._StoreTrueAction):
                assert action.default is False, (command, action.dest)


def test_every_model_request_refuses_implicit_route_expansion() -> None:
    callsites: list[str] = []
    for path in sorted((ROOT / "src" / "agentic_security_harness").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name != "chat_completion":
                continue
            redirect = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "allow_redirects"),
                None,
            )
            assert isinstance(redirect, ast.Constant), (path.name, node.lineno)
            assert redirect.value is False, (path.name, node.lineno)
            proxy = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "allow_env_proxy"),
                None,
            )
            assert isinstance(proxy, ast.Constant), (path.name, node.lineno)
            assert proxy.value is False, (path.name, node.lineno)
            callsites.append(f"{path.name}:{node.lineno}")

    assert len(callsites) == 11


@pytest.mark.parametrize(
    "argv",
    [
        ["local-suite", "--execute"],
        ["local-swarm", "--execute"],
        ["local-swarm-matrix", "--execute-model", "--model", "m"],
        ["secret-leak-campaign", "--execute-model"],
        ["secret-leak-campaign", "--execute-variations"],
        ["semantic-drift-campaign", "--execute"],
        ["semantic-propagation-campaign", "--execute"],
        ["doctor", "--live-local"],
    ],
)
def test_local_named_cli_execution_refuses_remote_override(
    argv: list[str],
    tmp_path: Path,
) -> None:
    from unittest.mock import patch

    command = argv[0]
    full_argv = [*argv, "--base-url", "https://models.example.invalid/v1"]
    if command in {
        "secret-leak-campaign",
        "semantic-drift-campaign",
        "semantic-propagation-campaign",
    }:
        full_argv.extend(["--out", str(tmp_path / ".internal" / command)])
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        assert cli.main(full_argv) == 1
    mock_open.assert_not_called()


@pytest.mark.parametrize(
    ("argv", "call_target"),
    [
        (
            ["swarm-defense-live-campaign", "--execute"],
            "agentic_security_harness.swarm_defense_live_campaign.run_live_defense_campaign",
        ),
        (
            ["marketing-web-injection-campaign", "--write"],
            "agentic_security_harness.marketing_web_injection_campaign.write_marketing_web_private_artifacts",
        ),
        (
            ["swarm-resilience-campaign", "--write"],
            "agentic_security_harness.swarm_resilience_campaign.write_resilience_private_artifacts",
        ),
        (
            ["marketing-web-live-campaign", "--execute"],
            "agentic_security_harness.marketing_web_live_campaign.run_live_marketing_web_campaign",
        ),
    ],
)
def test_private_public_campaigns_refuse_overlapping_output_roots_before_writes(
    argv: list[str],
    call_target: str,
    tmp_path: Path,
) -> None:
    from unittest.mock import patch

    mixed = tmp_path / ".internal" / "mixed"
    with patch(call_target) as side_effect:
        rc = cli.main(
            [*argv, "--out", str(mixed), "--summary-out", str(mixed)]
        )

    assert rc == 1
    side_effect.assert_not_called()


@pytest.mark.parametrize(
    ("argv", "call_target"),
    [
        (
            ["local-swarm-matrix", "--execute-model", "--model", "m", "--write"],
            "agentic_security_harness.local_swarm_matrix.chat_completion",
        ),
        (
            ["secret-leak-campaign", "--execute-model", "--write"],
            "agentic_security_harness.secret_leak_campaign.run_secret_model_probe",
        ),
        (
            ["semantic-drift-campaign", "--execute", "--write"],
            "agentic_security_harness.semantic_drift_campaign.run_semantic_drift_probe",
        ),
        (
            ["semantic-propagation-campaign", "--execute", "--write"],
            "agentic_security_harness.semantic_propagation_campaign.run_semantic_propagation_probe",
        ),
    ],
)
def test_cli_refuses_private_and_sanitized_same_root_combined_modes(
    argv: list[str],
    call_target: str,
    tmp_path: Path,
) -> None:
    from unittest.mock import patch

    with patch(call_target) as model_call:
        rc = cli.main([*argv, "--out", str(tmp_path / ".internal" / "mixed")])

    assert rc == 1
    model_call.assert_not_called()


@pytest.mark.parametrize(
    ("argv", "call_target", "private_child", "needs_summary"),
    [
        (
            ["local-swarm", "--execute", "--model", "m"],
            "agentic_security_harness.local_swarm.run_local_swarm",
            "",
            False,
        ),
        (
            ["local-swarm-matrix", "--execute-model", "--model", "m"],
            "agentic_security_harness.local_swarm_matrix.run_matrix_model_probe",
            "",
            False,
        ),
        (
            ["secret-leak-campaign", "--execute-model", "--model", "m"],
            "agentic_security_harness.secret_leak_campaign.run_secret_model_probe",
            "private_model_probe",
            False,
        ),
        (
            ["semantic-drift-campaign", "--execute"],
            "agentic_security_harness.semantic_drift_campaign.run_semantic_drift_probe",
            "private_semantic_drift_probe",
            True,
        ),
        (
            ["semantic-propagation-campaign", "--execute"],
            "agentic_security_harness.semantic_propagation_campaign.run_semantic_propagation_probe",
            "private_semantic_propagation_probe",
            True,
        ),
        (
            ["swarm-defense-live-campaign", "--execute"],
            "agentic_security_harness.swarm_defense_live_campaign.run_live_defense_campaign",
            "",
            True,
        ),
        (
            ["marketing-web-live-campaign", "--execute"],
            "agentic_security_harness.marketing_web_live_campaign.run_live_marketing_web_campaign",
            "",
            True,
        ),
    ],
)
def test_precreated_empty_output_is_rejected_before_model_execution(
    argv: list[str],
    call_target: str,
    private_child: str,
    needs_summary: bool,
    tmp_path: Path,
) -> None:
    from unittest.mock import patch

    out = tmp_path / ".internal" / "existing"
    blocked = out / private_child if private_child else out
    blocked.mkdir(parents=True)
    full_argv = [*argv, "--out", str(out)]
    if needs_summary:
        full_argv.extend(["--summary-out", str(tmp_path / "public-summary")])

    with patch(call_target) as model_call:
        rc = cli.main(full_argv)

    assert rc == 1
    model_call.assert_not_called()


def _code_fence_commands(text: str) -> list[str]:
    commands: list[str] = []
    in_fence = False
    pending = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            if pending:
                commands.append(pending)
                pending = ""
            in_fence = not in_fence
            continue
        if not in_fence or not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith(("\\", "`"))
        part = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {part}".strip()
        if not continued:
            commands.append(pending)
            pending = ""
    if pending:
        commands.append(pending)
    return commands


def test_documented_run_external_commands_choose_dry_run_or_execute() -> None:
    markdown_paths = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    runnable = re.compile(
        r"(?:^|[;&]\s*)(?:(?:python\s+-m\s+agentic_security_harness\.cli|ash)\s+)?"
        r"run-external\b"
    )
    offenders: list[str] = []
    for path in markdown_paths:
        for command in _code_fence_commands(path.read_text(encoding="utf-8")):
            if not runnable.search(command) or "--help" in command:
                continue
            if "--dry-run" not in command and "--execute" not in command:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}: {command}")

    assert offenders == []
