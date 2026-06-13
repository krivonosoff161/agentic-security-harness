"""Command-line entry point.

Commands:
  ash run     --target {mock,demo-agent,protected-demo-agent} --out <dir>
  ash compare --baseline <target> --protected <target> --out <dir>

All targets are local, deterministic, and make no network or LLM/provider calls.
"""

import argparse
from pathlib import Path

from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.models import Target
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.protected_demo_agent import ProtectedDemoAgentTarget
from agentic_security_harness.reporting import write_comparison, write_reports
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard
from agentic_security_harness.validation import validate_path

_TARGETS = ["mock", "demo-agent", "protected-demo-agent"]


def _make_target(target: str) -> Target:
    # All targets are local, deterministic, and make no network or LLM calls.
    if target == "mock":
        return MockTarget()
    if target == "demo-agent":
        return DemoAgentTarget()
    return ProtectedDemoAgentTarget()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ash",
        description="Agentic Security Harness - defensive, mock-only demo runner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run the seed patterns against a target and write reports")
    run_p.add_argument(
        "--target",
        choices=_TARGETS,
        default="mock",
        help="target to test (all local, synthetic, no network)",
    )
    run_p.add_argument(
        "--out", type=Path, default=Path("reports/demo"), help="output directory"
    )

    cmp_p = sub.add_parser(
        "compare", help="run baseline vs protected and write a risk-reduction comparison"
    )
    cmp_p.add_argument(
        "--baseline", choices=_TARGETS, default="demo-agent", help="baseline (vulnerable) target"
    )
    cmp_p.add_argument(
        "--protected",
        choices=_TARGETS,
        default="protected-demo-agent",
        help="protected target",
    )
    cmp_p.add_argument(
        "--out", type=Path, default=Path("reports/comparison"), help="output directory"
    )

    val_p = sub.add_parser(
        "validate", help="validate committed benchmark artifacts against the corpus"
    )
    val_p.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path("examples"),
        help="report dir, comparison dir, or a directory of such dirs (default: examples)",
    )
    return parser


def _run(target: str, out: Path) -> int:
    traces = HarnessRunner(_make_target(target)).run_many(seed_patterns())
    scorecard = build_scorecard(traces)
    write_reports(traces, scorecard, out)
    print(f"wrote traces.json, scorecard.json, summary.md, executive.md to {out.as_posix()}")
    print(
        f"target: {scorecard.target_name}  "
        f"traces: {scorecard.total_traces}  "
        f"failed: {len(scorecard.failed_patterns)}  "
        f"passed: {len(scorecard.passed_patterns)}"
    )
    return 0


def _compare(baseline: str, protected: str, out: Path) -> int:
    patterns = seed_patterns()
    base_traces = HarnessRunner(_make_target(baseline)).run_many(patterns)
    base_card = build_scorecard(base_traces)
    prot_traces = HarnessRunner(_make_target(protected)).run_many(patterns)
    prot_card = build_scorecard(prot_traces)
    write_comparison(out, base_traces, base_card, prot_traces, prot_card)
    print(f"wrote baseline/, protected/, comparison.md to {out.as_posix()}")
    print(
        f"baseline: {base_card.target_name} failed={len(base_card.failed_patterns)}  "
        f"protected: {prot_card.target_name} failed={len(prot_card.failed_patterns)}"
    )
    return 0


def _validate(path: Path) -> int:
    result = validate_path(path)
    print(
        f"validated {len(result.report_dirs)} report dir(s), "
        f"{len(result.comparison_dirs)} comparison dir(s)"
    )
    print(f"errors: {len(result.errors)}  warnings: {len(result.warnings)}")
    for warning in result.warnings:
        print(f"  warning: {warning}")
    for error in result.errors:
        print(f"  error: {error}")
    if result.ok:
        print("OK: artifacts conform to the corpus manifest and contain no forbidden markers")
    else:
        print("FAILED: see errors above")
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return _run(args.target, args.out)
    if args.command == "compare":
        return _compare(args.baseline, args.protected, args.out)
    if args.command == "validate":
        return _validate(args.path)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
