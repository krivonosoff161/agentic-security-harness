"""Focused tests for the v0.6 corpus expansion.

Covers the three new deterministic patterns (sleeping prompt delayed activation,
audit spam-label abuse, budget loop abuse): baseline fails each, protected passes
each, the manifest stays in sync, and validation catches a missing new-pattern
artifact. All local, synthetic, no network.
"""

import json
import shutil
from pathlib import Path

import pytest

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.patterns import (
    LOOP_ITERATIONS,
    LOOP_STEP_BUDGET,
    seed_patterns,
)
from agentic_security_harness.protected_demo_agent import ProtectedDemoAgentTarget
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.validation import validate_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

NEW_IDS = {
    "sleeping_prompt.delayed_activation": ("high", "provenance_check"),
    "audit.spam_label_abuse": ("high", "audit_check"),
    "budget.loop_abuse": ("medium", "budget_check"),
}


def _traces(target: object) -> dict[str, ExploitTrace]:
    runner = HarnessRunner(target)  # type: ignore[arg-type]
    return {t.pattern_id: t for t in runner.run_many(seed_patterns())}


def test_baseline_fails_each_new_pattern() -> None:
    by_id = _traces(DemoAgentTarget())
    for pid, (severity, broke_at) in NEW_IDS.items():
        trace = by_id[pid]
        assert len(trace.findings) == 1, pid
        finding = trace.findings[0]
        assert finding.severity == severity
        assert finding.broke_at == broke_at
        assert [s.action for s in trace.steps] == trace.graph_path


def test_protected_passes_each_new_pattern() -> None:
    by_id = _traces(ProtectedDemoAgentTarget())
    for pid in NEW_IDS:
        trace = by_id[pid]
        assert trace.findings == [], pid
        assert [s.action for s in trace.steps] == trace.graph_path


def test_new_patterns_present_in_manifest_and_seeds() -> None:
    manifest = {e.pattern_id: e for e in corpus_manifest()}
    seeds = {p.pattern_id for p in seed_patterns()}
    for pid, (severity, broke_at) in NEW_IDS.items():
        assert pid in seeds
        entry = manifest[pid]
        assert entry.implemented
        assert entry.severity == severity
        assert entry.broke_at == broke_at
        assert entry.baseline_expected == "FAIL"
        assert entry.protected_expected == "PASS"


def test_loop_scenario_constants_are_a_real_overrun() -> None:
    # The synthetic loop must actually exceed the budget, or the pattern tests nothing.
    assert LOOP_ITERATIONS > LOOP_STEP_BUDGET > 0


def test_validation_catches_missing_new_pattern(tmp_path: Path) -> None:
    report = tmp_path / "demo-agent-report"
    shutil.copytree(EXAMPLES / "demo-agent-report", report)
    data = json.loads((report / "traces.json").read_text(encoding="utf-8"))
    data = [t for t in data if t["pattern_id"] != "budget.loop_abuse"]
    (report / "traces.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    result = validate_path(report)
    assert not result.ok
    assert any("missing corpus pattern" in err and "budget.loop_abuse" in err
               for err in result.errors)


def test_no_network_for_new_patterns(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def _boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("network call attempted")

    monkeypatch.setattr(socket, "socket", _boom)
    assert set(NEW_IDS) <= set(_traces(DemoAgentTarget()))
    assert set(NEW_IDS) <= set(_traces(ProtectedDemoAgentTarget()))


def test_no_forbidden_markers_in_new_pattern_traces() -> None:
    blob = json.dumps(
        [t.model_dump() for t in _traces(DemoAgentTarget()).values()]
        + [t.model_dump() for t in _traces(ProtectedDemoAgentTarget()).values()]
    )
    for marker in ("sk-", "AKIA", "BEGIN PRIVATE KEY"):
        assert marker not in blob
