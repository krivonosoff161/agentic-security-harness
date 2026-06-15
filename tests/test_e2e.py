"""End-to-end CLI pipeline tests.

These tests exercise full command paths with real temporary output directories. They are
not replacements for unit tests; they prove the CLI, artifact writers, validators, and
HTML renderer still work together.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agentic_security_harness import cli


def test_e2e_run_validate_report_pipeline(tmp_path: Path) -> None:
    out = tmp_path / "run"

    assert cli.main(["run", "--target", "mock", "--out", str(out)]) == 0
    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    assert (out / "traces.json").exists()
    assert (out / "scorecard.json").exists()
    assert (out / "report.html").exists()


def test_e2e_compare_validate_report_pipeline(tmp_path: Path) -> None:
    out = tmp_path / "comparison"

    assert cli.main([
        "compare",
        "--baseline",
        "demo-agent",
        "--protected",
        "protected-demo-agent",
        "--out",
        str(out),
    ]) == 0
    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    assert (out / "comparison.md").exists()
    assert (out / "report.html").exists()


def test_e2e_matrix_validate_report_pipeline(tmp_path: Path) -> None:
    out = tmp_path / "matrix"

    assert cli.main([
        "run-matrix",
        "--target",
        "mock",
        "--scenario",
        "data-boundary",
        "--out",
        str(out),
    ]) == 0
    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    matrix = json.loads((out / "matrix.json").read_text(encoding="utf-8"))
    assert matrix["corpus_version"]
    assert (out / "report.html").exists()


def test_e2e_external_validate_report_pipeline(tmp_path: Path) -> None:
    out = tmp_path / "external"
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content":
            '{"decision": "block", "reason": "boundary preserved", '
            '"would_preserve_boundary": true}'
        }}]
    }).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response):
        assert cli.main([
            "run-external",
            "--base-url",
            "http://localhost:8000/v1",
            "--model",
            "fake-model",
            "--scenario",
            "data-boundary",
            "--out",
            str(out),
        ]) == 0

    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    summary = json.loads((out / "external_summary.json").read_text(encoding="utf-8"))
    assert config["corpus_version"] == summary["corpus_version"]
    assert (out / "report.html").exists()
