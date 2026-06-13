import json
from pathlib import Path

from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import (
    build_executive_md,
    build_summary_md,
    scorecard_to_json,
    traces_to_json,
    write_reports,
)
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "demo-report"


def _build() -> tuple[list[ExploitTrace], ScorecardSummary]:
    traces = HarnessRunner(MockTarget()).run_many(seed_patterns())
    return traces, build_scorecard(traces)


def _norm(text: str) -> str:
    return text.replace("\r\n", "\n")


def test_reports_are_deterministic() -> None:
    t1, s1 = _build()
    t2, s2 = _build()
    assert traces_to_json(t1) == traces_to_json(t2)
    assert scorecard_to_json(s1) == scorecard_to_json(s2)
    assert build_summary_md(s1, t1) == build_summary_md(s2, t2)
    assert build_executive_md(s1, t1) == build_executive_md(s2, t2)


def test_write_reports_creates_report_files(tmp_path: Path) -> None:
    traces, scorecard = _build()
    paths = write_reports(traces, scorecard, tmp_path / "demo")
    # Baseline demo-agent has findings, so remediation artifacts are included
    assert set(paths) == {
        "traces", "scorecard", "summary", "executive",
        "remediation_json", "remediation_md",
    }
    for path in paths.values():
        assert path.exists() and path.read_text(encoding="utf-8").strip()
    data = json.loads(paths["traces"].read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == len(traces)


def test_committed_example_matches_code() -> None:
    traces, scorecard = _build()
    assert _norm((EXAMPLE_DIR / "traces.json").read_text(encoding="utf-8")) == _norm(
        traces_to_json(traces)
    )
    assert _norm((EXAMPLE_DIR / "scorecard.json").read_text(encoding="utf-8")) == _norm(
        scorecard_to_json(scorecard)
    )
    assert _norm((EXAMPLE_DIR / "summary.md").read_text(encoding="utf-8")) == _norm(
        build_summary_md(scorecard, traces)
    )
    assert _norm((EXAMPLE_DIR / "executive.md").read_text(encoding="utf-8")) == _norm(
        build_executive_md(scorecard, traces)
    )


def test_no_real_secrets_in_reports() -> None:
    traces, scorecard = _build()
    blob = (
        traces_to_json(traces)
        + scorecard_to_json(scorecard)
        + build_summary_md(scorecard, traces)
        + build_executive_md(scorecard, traces)
    )
    for marker in ("sk-", "AKIA", "BEGIN PRIVATE KEY"):
        assert marker not in blob
