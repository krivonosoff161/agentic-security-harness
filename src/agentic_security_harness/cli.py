"""Command-line entry point.

Commands:
  ash run         --target {mock,...} --out <dir>
  ash compare     --baseline <target> --protected <target> --out <dir>
  ash validate    <path>
  ash targets
  ash scenarios
  ash run-matrix  --target <target> --scenario <scenario> --out <dir>

All targets are local, deterministic, and make no network or LLM/provider calls.
"""

import argparse
from pathlib import Path

from agentic_security_harness.adapters import list_targets, make_target, target_ids
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import write_comparison, write_reports
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scenarios import list_scenarios, scenario_ids
from agentic_security_harness.scorecard import build_scorecard
from agentic_security_harness.validation import validate_path

_TARGETS = target_ids()


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

    sub.add_parser("targets", help="list registered built-in targets")

    sub.add_parser("scenarios", help="list scenario templates and included pattern counts")

    matrix_p = sub.add_parser(
        "run-matrix", help="run a scenario matrix against a target and write reports"
    )
    matrix_p.add_argument(
        "--target",
        choices=_TARGETS,
        default="mock",
        help="target to test (all local, synthetic, no network)",
    )
    matrix_p.add_argument(
        "--scenario",
        choices=scenario_ids(),
        default="all",
        help="scenario id to run (default: all)",
    )
    matrix_p.add_argument(
        "--out", type=Path, default=Path("reports/matrix"), help="output directory"
    )

    return parser


def _run(target: str, out: Path) -> int:
    traces = HarnessRunner(make_target(target)).run_many(seed_patterns())
    scorecard = build_scorecard(traces)
    write_reports(traces, scorecard, out)
    from agentic_security_harness.remediation import build_recommendations

    remediation = build_recommendations(traces, scorecard)
    rem_files = []
    if remediation.recommendations:
        rem_files = ["remediation.json", "remediation.md"]
    all_files = ["traces.json", "scorecard.json", "summary.md", "executive.md"] + rem_files
    print(f"wrote {', '.join(all_files)} to {out.as_posix()}")
    print(
        f"target: {scorecard.target_name}  "
        f"traces: {scorecard.total_traces}  "
        f"failed: {len(scorecard.failed_patterns)}  "
        f"passed: {len(scorecard.passed_patterns)}"
    )
    if remediation.recommendations:
        families = ", ".join(remediation.control_families[:5])
        print(f"control families: {families}")
    return 0


def _compare(baseline: str, protected: str, out: Path) -> int:
    patterns = seed_patterns()
    base_traces = HarnessRunner(make_target(baseline)).run_many(patterns)
    base_card = build_scorecard(base_traces)
    prot_traces = HarnessRunner(make_target(protected)).run_many(patterns)
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


def _targets() -> int:
    for info in list_targets():
        det = "deterministic" if info.deterministic else "stochastic"
        print(f"{info.target_id:30s} {info.name:30s} {info.type:20s} {det:12s} {info.description}")
    return 0


def _scenarios() -> int:
    for scenario in list_scenarios():
        n = len(scenario.pattern_ids)
        print(f"{scenario.scenario_id:25s} {n:3d} patterns  {scenario.title}")
    return 0


def _run_matrix(target_id: str, scenario_id: str, out: Path) -> int:
    from agentic_security_harness.matrix import run_matrix

    target = make_target(target_id)
    report = run_matrix(target, scenario_id, out, target_id=target_id)
    print(f"wrote matrix artifacts to {out.as_posix()}")
    print(
        f"target: {report.target_name}  "
        f"scenario: {report.scenario_id}  "
        f"traces: {report.total_traces}  "
        f"failed: {report.total_failed}  "
        f"passed: {report.total_passed}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return _run(args.target, args.out)
    if args.command == "compare":
        return _compare(args.baseline, args.protected, args.out)
    if args.command == "validate":
        return _validate(args.path)
    if args.command == "targets":
        return _targets()
    if args.command == "scenarios":
        return _scenarios()
    if args.command == "run-matrix":
        return _run_matrix(args.target, args.scenario, args.out)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
