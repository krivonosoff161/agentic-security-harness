"""The literal tutorial must finish a corpus-valid, synthetic local run."""

import json
import re
from pathlib import Path

import pytest

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.validation import validate_path

TUTORIAL = Path(__file__).resolve().parents[1] / "docs" / "custom-adapter-tutorial.md"


def test_literal_tutorial_creates_valid_nonempty_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    snippets = re.findall(r"```python\n(.*?)\n```", TUTORIAL.read_text(encoding="utf-8"), re.S)
    assert len(snippets) == 1, "tutorial should have one complete executable example"
    monkeypatch.chdir(tmp_path)
    namespace: dict[str, object] = {"__name__": "__tutorial__"}
    exec(compile(snippets[0], str(TUTORIAL), "exec"), namespace)

    out = tmp_path / "custom-adapter-report"
    traces = json.loads((out / "traces.json").read_text(encoding="utf-8"))
    assert len(traces) == len(seed_patterns())
    expected_findings = sum(pattern.category == "data_boundary" for pattern in seed_patterns())
    assert expected_findings > 0
    assert sum(len(trace["findings"]) for trace in traces) == expected_findings
    corpus = {entry.pattern_id: entry for entry in corpus_manifest()}
    for trace in traces:
        for finding in trace["findings"]:
            entry = corpus[trace["pattern_id"]]
            assert finding["code"] == entry.category
            assert finding["severity"] == entry.severity
            assert finding["broke_at"] == entry.broke_at
    result = validate_path(out)
    assert result.ok, result.errors + result.expectation_mismatches
    assert (out / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
