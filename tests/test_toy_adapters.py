"""Tests for the local toy adapters and the neutral validation tier."""

import json
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.adapters import make_target, target_ids
from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.validation import validate_path


def test_toy_adapters_registered() -> None:
    ids = target_ids()
    assert "toy-rag" in ids
    assert "toy-tools" in ids


def test_toy_rag_partial_coverage() -> None:
    traces = HarnessRunner(make_target("toy-rag")).run_many(seed_patterns())
    failed = [t for t in traces if t.findings]
    passed = [t for t in traces if not t.findings]
    # RAG surface: data/memory/injection categories produce findings; rest PASS.
    assert len(failed) == 10
    assert len(passed) == 12


def test_toy_tools_partial_coverage() -> None:
    traces = HarnessRunner(make_target("toy-tools")).run_many(seed_patterns())
    assert len([t for t in traces if t.findings]) == 5


def test_toy_findings_are_corpus_consistent() -> None:
    corpus = {e.pattern_id: e for e in corpus_manifest()}
    patterns = {p.pattern_id: p for p in seed_patterns()}
    traces = HarnessRunner(make_target("toy-rag")).run_many(seed_patterns())
    for trace in traces:
        for finding in trace.findings:
            entry = corpus[trace.pattern_id]
            assert finding.code == patterns[trace.pattern_id].category
            assert finding.severity == entry.severity
            assert finding.broke_at == entry.broke_at


def test_toy_findings_no_real_payload() -> None:
    traces = HarnessRunner(make_target("toy-rag")).run_many(seed_patterns())
    blob = json.dumps([t.model_dump(mode="json") for t in traces])
    assert "sk-" not in blob and "AKIA" not in blob
    assert "SYNTHETIC-UNTRUSTED-MARKER" in blob  # marker present, clearly synthetic


def test_cli_run_toy_rag_validates(tmp_path: Path) -> None:
    out = tmp_path / "toyrag"
    rc = cli.main(["run", "--target", "toy-rag", "--out", str(out)])
    assert rc == 0
    result = validate_path(out)
    assert result.ok, result.errors


def test_neutral_pass_only_target_validates(tmp_path: Path) -> None:
    # toy-local-function passes every pattern; the neutral tier must accept that.
    out = tmp_path / "toyfn"
    cli.main(["run", "--target", "toy-local-function", "--out", str(out)])
    result = validate_path(out)
    assert result.ok, result.errors


def test_neutral_finding_must_stay_corpus_consistent(tmp_path: Path) -> None:
    # Tamper a toy finding's severity; validation must still reject it.
    out = tmp_path / "toyrag"
    cli.main(["run", "--target", "toy-rag", "--out", str(out)])
    traces = json.loads((out / "traces.json").read_text(encoding="utf-8"))
    for trace in traces:
        if trace["findings"]:
            trace["findings"][0]["severity"] = "info"
            break
    (out / "traces.json").write_text(
        json.dumps(traces, indent=2) + "\n", encoding="utf-8"
    )
    result = validate_path(out)
    assert not result.ok
    assert any("severity" in e for e in result.errors)
