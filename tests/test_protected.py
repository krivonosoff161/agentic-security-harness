from pathlib import Path

import pytest

from agentic_security_harness import cli
from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.protected_demo_agent import ProtectedDemoAgentTarget
from agentic_security_harness.reporting import (
    build_comparison_md,
    scorecard_to_json,
    traces_to_json,
)
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
PROTECTED_EXAMPLE = _EXAMPLES / "protected-demo-agent-report"
COMPARISON_EXAMPLE = _EXAMPLES / "comparison-report"

SEED_IDS = {
    "indirect_prompt_injection_via_tool_output",
    "data_boundary_recipient_confusion",
    "memory_poisoning_sanitized",
}


def _protected_traces() -> list[ExploitTrace]:
    return HarnessRunner(ProtectedDemoAgentTarget()).run_many(seed_patterns())


def _baseline_traces() -> list[ExploitTrace]:
    return HarnessRunner(DemoAgentTarget()).run_many(seed_patterns())


def _norm(text: str) -> str:
    return text.replace("\r\n", "\n")


def test_protected_handles_all_seed_patterns_with_no_findings() -> None:
    traces = _protected_traces()
    assert {t.pattern_id for t in traces} == SEED_IDS
    assert all(t.findings == [] for t in traces)
    for trace in traces:
        assert [step.action for step in trace.steps] == trace.graph_path


def test_protected_scorecard_all_passed() -> None:
    card = build_scorecard(_protected_traces())
    assert card.target_name == "protected-demo-agent"
    assert len(card.passed_patterns) == 3
    assert card.failed_patterns == []
    assert card.findings_by_severity == {}


def test_baseline_still_fails() -> None:
    card = build_scorecard(_baseline_traces())
    assert len(card.failed_patterns) == 3
    assert card.passed_patterns == []
    assert card.findings_by_severity == {"high": 2, "medium": 1}


def test_compare_creates_full_structure(tmp_path: Path) -> None:
    out = tmp_path / "comparison"
    argv = [
        "compare",
        "--baseline", "demo-agent",
        "--protected", "protected-demo-agent",
        "--out", str(out),
    ]
    assert cli.main(argv) == 0
    assert (out / "comparison.md").exists()
    for side in ("baseline", "protected"):
        for name in ("traces.json", "scorecard.json", "summary.md"):
            assert (out / side / name).exists()


def test_comparison_report_deterministic() -> None:
    base = build_scorecard(_baseline_traces())
    prot = build_scorecard(_protected_traces())
    assert build_comparison_md(base, prot) == build_comparison_md(base, prot)


def test_protected_example_matches_code() -> None:
    traces = _protected_traces()
    scorecard = build_scorecard(traces)
    assert _norm((PROTECTED_EXAMPLE / "traces.json").read_text(encoding="utf-8")) == _norm(
        traces_to_json(traces)
    )
    assert _norm((PROTECTED_EXAMPLE / "scorecard.json").read_text(encoding="utf-8")) == _norm(
        scorecard_to_json(scorecard)
    )


def test_comparison_example_matches_code() -> None:
    base = build_scorecard(_baseline_traces())
    prot = build_scorecard(_protected_traces())
    assert _norm((COMPARISON_EXAMPLE / "comparison.md").read_text(encoding="utf-8")) == _norm(
        build_comparison_md(base, prot)
    )


def test_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def _boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("network call attempted")

    monkeypatch.setattr(socket, "socket", _boom)
    assert len(_protected_traces()) == 3


def test_no_real_secret_markers() -> None:
    blob = traces_to_json(_protected_traces()) + traces_to_json(_baseline_traces())
    for marker in ("sk-", "AKIA", "BEGIN PRIVATE KEY"):
        assert marker not in blob
