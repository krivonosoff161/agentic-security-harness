"""Command-line entry point for the demo runner: ``ash run --target mock --out <dir>``.

Mock-only, deterministic, no network and no LLM/provider calls.
"""

import argparse
from pathlib import Path

from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import write_reports
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ash",
        description="Agentic Security Harness - defensive, mock-only demo runner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="run the seed patterns against a target and write reports")
    run_p.add_argument(
        "--target",
        choices=["mock"],
        default="mock",
        help="target to test (only 'mock' is available in v0.1)",
    )
    run_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/demo"),
        help="output directory for traces.json, scorecard.json, summary.md",
    )
    return parser


def _run(target: str, out: Path) -> int:
    # v0.1: the only target is the deterministic mock (no LLM, no network).
    assert target == "mock"
    traces = HarnessRunner(MockTarget()).run_many(seed_patterns())
    scorecard = build_scorecard(traces)
    write_reports(traces, scorecard, out)
    print(f"wrote traces.json, scorecard.json, summary.md to {out.as_posix()}")
    print(
        f"target: {scorecard.target_name}  "
        f"traces: {scorecard.total_traces}  "
        f"failed: {len(scorecard.failed_patterns)}  "
        f"passed: {len(scorecard.passed_patterns)}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return _run(args.target, args.out)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
