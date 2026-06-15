"""Golden snapshot tests for deterministic public artifacts.

These tests intentionally compare selected generated artifacts byte-for-byte. If report
shape, trace content, or scorecard semantics change, update the implementation first,
then regenerate these fixtures in the same review.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agentic_security_harness import cli
from agentic_security_harness.external_runner import run_external
from agentic_security_harness.remediation import _FAMILY_MAP

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden"


def _assert_same_file(actual: Path, expected: Path) -> None:
    assert actual.read_text(encoding="utf-8") == expected.read_text(encoding="utf-8")


def _pattern_id_from_request(req: object) -> str:
    body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
    for message in body.get("messages", []):
        for line in str(message.get("content", "")).splitlines():
            if line.startswith("Pattern: "):
                return line.split("Pattern: ", 1)[1].strip()
    return "unknown"


def _external_snapshot_open(req: object, *args: object, **kwargs: object) -> MagicMock:
    pattern_id = _pattern_id_from_request(req)
    payload = {
        "pattern_id": pattern_id,
        "decision": "block",
        "boundary_assertion": "preserve_boundary",
        "reason": "snapshot boundary preserved",
        "control_family": _FAMILY_MAP.get(pattern_id, "perception_boundary"),
        "would_preserve_boundary": True,
    }
    content = json.dumps(payload)
    resp = MagicMock()
    resp.read.return_value = json.dumps(
        {"choices": [{"message": {"content": content}}]}
    ).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_golden_demo_run_snapshot(tmp_path: Path) -> None:
    out = tmp_path / "demo"
    assert cli.main(["run", "--target", "mock", "--out", str(out)]) == 0

    for name in (
        "traces.json",
        "scorecard.json",
        "summary.md",
        "executive.md",
        "remediation.json",
        "remediation.md",
    ):
        _assert_same_file(out / name, GOLDEN / "demo-run" / name)


def test_golden_comparison_snapshot(tmp_path: Path) -> None:
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

    _assert_same_file(
        out / "comparison.md", GOLDEN / "comparison" / "comparison.md"
    )
    _assert_same_file(
        out / "baseline" / "scorecard.json",
        GOLDEN / "comparison" / "baseline" / "scorecard.json",
    )
    _assert_same_file(
        out / "protected" / "scorecard.json",
        GOLDEN / "comparison" / "protected" / "scorecard.json",
    )


def test_golden_external_snapshot(tmp_path: Path) -> None:
    out = tmp_path / "external-pass"
    with patch("urllib.request.urlopen", side_effect=_external_snapshot_open):
        run_external(
            base_url="http://localhost:8000/v1",
            model="snapshot-model",
            scenario_id="perception-boundary",
            out_dir=out,
            repeats=1,
            max_variants=1,
        )

    for name in (
        "run_config.json",
        "external_results.json",
        "external_summary.json",
        "external_report.md",
    ):
        _assert_same_file(out / name, GOLDEN / "external-pass" / name)

    results = json.loads((out / "external_results.json").read_text(encoding="utf-8"))
    raw_path = out / results[0]["raw_response_path"]
    assert raw_path.read_text(encoding="utf-8") == results[0]["raw_response"]
