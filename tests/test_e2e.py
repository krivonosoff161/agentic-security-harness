"""End-to-end CLI pipeline tests.

These tests exercise full command paths with real temporary output directories. They are
not replacements for unit tests; they prove the CLI, artifact writers, validators, and
HTML renderer still work together.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agentic_security_harness import cli
from agentic_security_harness.remediation import _FAMILY_MAP


def _pattern_id_from_request(req: object) -> str:
    body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
    for message in body.get("messages", []):
        for line in str(message.get("content", "")).splitlines():
            if line.startswith("Pattern: "):
                return line.split("Pattern: ", 1)[1].strip()
    return "unknown"


def _mock_external_open(req: object, *args: object, **kwargs: object) -> MagicMock:
    pattern_id = _pattern_id_from_request(req)
    resp = MagicMock()
    content = json.dumps(
        {
            "pattern_id": pattern_id,
            "decision": "block",
            "boundary_assertion": "preserve_boundary",
            "reason": "boundary preserved",
            "control_family": _FAMILY_MAP.get(pattern_id, "data_boundary"),
            "would_preserve_boundary": True,
        }
    )
    resp.read.return_value = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


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

    assert (
        cli.main(
            [
                "compare",
                "--baseline",
                "demo-agent",
                "--protected",
                "protected-demo-agent",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    assert (out / "comparison.md").exists()
    assert (out / "report.html").exists()


def test_e2e_matrix_validate_report_pipeline(tmp_path: Path) -> None:
    out = tmp_path / "matrix"

    assert (
        cli.main(
            [
                "run-matrix",
                "--target",
                "mock",
                "--scenario",
                "data-boundary",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    matrix = json.loads((out / "matrix.json").read_text(encoding="utf-8"))
    assert matrix["corpus_version"]
    assert (out / "report.html").exists()


def test_e2e_external_validate_report_pipeline(tmp_path: Path) -> None:
    out = tmp_path / "external"

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_external_open,
    ):
        assert (
            cli.main(
                [
                    "run-external",
                    "--base-url",
                    "http://localhost:8000/v1",
                    "--model",
                    "fake-model",
                    "--scenario",
                    "data-boundary",
                    "--execute",
                    "--out",
                    str(out),
                ]
            )
            == 0
        )

    assert cli.main(["validate", str(out)]) == 0
    assert cli.main(["report", "--root", str(out)]) == 0

    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    summary = json.loads((out / "external_summary.json").read_text(encoding="utf-8"))
    assert config["corpus_version"] == summary["corpus_version"]
    results = json.loads((out / "external_results.json").read_text(encoding="utf-8"))
    assert (out / results[0]["raw_response_path"]).exists()
    assert (out / "report.html").exists()
