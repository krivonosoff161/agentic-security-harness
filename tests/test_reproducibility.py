"""Tests for deterministic example reproducibility pack."""

from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.reproducibility import (
    EXAMPLE_IDS,
    rebuild_and_compare_examples,
)


def test_reproducibility_pack_regenerates_committed_examples(tmp_path: Path) -> None:
    out = tmp_path / "repro"
    report = rebuild_and_compare_examples(out_dir=out, examples_root=Path("examples"))

    assert report.examples == len(EXAMPLE_IDS)
    assert report.validation_failures == 0
    assert report.metric_mismatches == 0
    assert report.ok
    assert (out / "reproducibility_report.json").exists()
    assert (out / "reproducibility_report.md").exists()


def test_cli_reproduce_examples_returns_success(tmp_path: Path) -> None:
    out = tmp_path / "cli-repro"
    rc = cli.main(["reproduce-examples", "--out", str(out)])

    assert rc == 0
    assert (out / "generated" / "comparison-report" / "comparison.md").exists()
    assert (out / "reproducibility_report.md").exists()
