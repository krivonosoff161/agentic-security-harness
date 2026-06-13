"""Command-line entry point.

Commands:
  ash run         --target {mock,...} --out <dir>
  ash compare     --baseline <target> --protected <target> --out <dir>
  ash validate    <path>
  ash targets
  ash scenarios [--verbose]
  ash run-matrix  --target <target> --scenario <scenario> --out <dir>
                  [--max-variants N] [--variant VARIANT_ID]
  ash run-external --adapter openai-compatible --base-url URL --model MODEL
                   --scenario <scenario> --out <dir> [--repeats N] [--dry-run]

All built-in targets are local, deterministic, and make no network or LLM calls.
External runs require explicit user action and make network calls only when invoked.
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

    run_p = sub.add_parser(
        "run", help="run the seed patterns against a target and write reports"
    )
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
        "compare",
        help="run baseline vs protected and write a risk-reduction comparison",
    )
    cmp_p.add_argument(
        "--baseline",
        choices=_TARGETS,
        default="demo-agent",
        help="baseline (vulnerable) target",
    )
    cmp_p.add_argument(
        "--protected",
        choices=_TARGETS,
        default="protected-demo-agent",
        help="protected target",
    )
    cmp_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/comparison"),
        help="output directory",
    )

    val_p = sub.add_parser(
        "validate",
        help="validate committed benchmark artifacts against the corpus",
    )
    val_p.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path("examples"),
        help="report dir, comparison dir, or a directory of such dirs",
    )

    sub.add_parser("targets", help="list registered built-in targets")

    scen_p = sub.add_parser(
        "scenarios", help="list scenario templates and included pattern counts"
    )
    scen_p.add_argument(
        "--verbose",
        action="store_true",
        help="show variant details for each scenario",
    )

    matrix_p = sub.add_parser(
        "run-matrix",
        help="run a scenario matrix against a target and write reports",
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
        "--out",
        type=Path,
        default=Path("reports/matrix"),
        help="output directory",
    )
    matrix_p.add_argument(
        "--max-variants",
        type=int,
        default=4,
        help="maximum number of variants to run (default: 4, hard cap: 12)",
    )
    matrix_p.add_argument(
        "--variant",
        default=None,
        help="run exactly one variant by id (overrides --max-variants)",
    )
    matrix_p.add_argument(
        "--list-variants",
        action="store_true",
        help="list available variants for the scenario and exit",
    )

    ext_p = sub.add_parser(
        "run-external",
        help="run an experimental external model evaluation",
    )
    ext_p.add_argument(
        "--adapter",
        default="openai-compatible",
        help="adapter type (default: openai-compatible)",
    )
    ext_p.add_argument(
        "--base-url",
        required=True,
        help="OpenAI-compatible API base URL (e.g. http://localhost:8000/v1)",
    )
    ext_p.add_argument(
        "--model",
        required=True,
        help="model name to use (e.g. deepseek-chat)",
    )
    ext_p.add_argument(
        "--scenario",
        choices=scenario_ids(),
        default="data-boundary",
        help="scenario id to evaluate (default: data-boundary)",
    )
    ext_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/external"),
        help="output directory",
    )
    ext_p.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="number of repeats per pattern-variant (default: 1, max: 10)",
    )
    ext_p.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="model temperature (default: 0.0)",
    )
    ext_p.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="request timeout in seconds (default: 30)",
    )
    ext_p.add_argument(
        "--api-key-env",
        default="",
        help="environment variable name containing the API key",
    )
    ext_p.add_argument(
        "--max-variants",
        type=int,
        default=1,
        help="maximum number of variants to evaluate (default: 1)",
    )
    ext_p.add_argument(
        "--variant",
        default=None,
        help="evaluate exactly one variant by id",
    )
    ext_p.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be run without making network calls",
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
    all_files = (
        ["traces.json", "scorecard.json", "summary.md", "executive.md"] + rem_files
    )
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
        f"baseline: {base_card.target_name} "
        f"failed={len(base_card.failed_patterns)}  "
        f"protected: {prot_card.target_name} "
        f"failed={len(prot_card.failed_patterns)}"
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
        print(
            "OK: artifacts conform to the corpus manifest "
            "and contain no forbidden markers"
        )
    else:
        print("FAILED: see errors above")
    return 0 if result.ok else 1


def _targets() -> int:
    for info in list_targets():
        det = "deterministic" if info.deterministic else "stochastic"
        print(
            f"{info.target_id:30s} {info.name:30s} "
            f"{info.type:20s} {det:12s} {info.description}"
        )
    return 0


def _scenarios(verbose: bool = False) -> int:
    for scenario in list_scenarios():
        n = len(scenario.pattern_ids)
        nv = len(scenario.variants)
        print(
            f"{scenario.scenario_id:25s} {n:3d} patterns  "
            f"{nv:2d} variants  {scenario.title}"
        )
        if verbose:
            for v in scenario.variants:
                knobs = ", ".join(f"{k}={val}" for k, val in v.knobs.items())
                print(f"  - {v.variant_id:30s} {knobs}")
    return 0


def _run_matrix(
    target_id: str,
    scenario_id: str,
    out: Path,
    max_variants: int,
    variant_id: str | None,
    list_variants: bool,
) -> int:
    from agentic_security_harness.matrix import run_matrix
    from agentic_security_harness.scenarios import get_scenario

    if list_variants:
        scenario = get_scenario(scenario_id)
        print(f"Scenario: {scenario.scenario_id} - {scenario.title}")
        print(f"Available variants ({len(scenario.variants)}):")
        for v in scenario.variants:
            knobs = ", ".join(
                f"{k}={val}" for k, val in v.knobs.items()
            )
            print(f"  {v.variant_id:30s} {v.title}")
            if knobs:
                print(f"  {'':30s} knobs: {knobs}")
        return 0

    try:
        target = make_target(target_id)
    except KeyError as exc:
        print(f"Error: {exc}")
        return 1

    try:
        report = run_matrix(
            target,
            scenario_id,
            out,
            target_id=target_id,
            max_variants=max_variants,
            only_variant_id=variant_id,
        )
    except KeyError as exc:
        print(f"Error: {exc}")
        return 1

    s = report.summary
    print(f"wrote matrix artifacts to {out.as_posix()}")
    print(
        f"target: {report.target_name}  "
        f"scenario: {report.scenario_id}  "
        f"variants: {s.total_variants}  "
        f"traces: {s.total_traces}  "
        f"failed variants: {s.failed_variants}  "
        f"passed variants: {s.passed_variants}"
    )
    return 0


def _run_external(
    base_url: str,
    model: str,
    scenario_id: str,
    out: Path,
    repeats: int,
    temperature: float,
    timeout: int,
    api_key_env: str,
    max_variants: int,
    variant_id: str | None,
    dry_run: bool,
    adapter: str,
) -> int:
    from agentic_security_harness.external_runner import run_external
    from agentic_security_harness.run_config import _MAX_REPEATS

    if repeats < 1 or repeats > _MAX_REPEATS:
        print(f"Error: repeats must be between 1 and {_MAX_REPEATS}")
        return 1

    if adapter != "openai-compatible":
        print(f"Error: unsupported adapter '{adapter}'. Only 'openai-compatible' is supported.")
        return 1

    try:
        summary = run_external(
            base_url=base_url,
            model=model,
            scenario_id=scenario_id,
            out_dir=out,
            repeats=repeats,
            temperature=temperature,
            timeout_seconds=timeout,
            api_key_env=api_key_env,
            max_variants=max_variants,
            only_variant_id=variant_id,
            dry_run=dry_run,
        )
    except KeyError as exc:
        print(f"Error: {exc}")
        return 1

    if dry_run:
        return 0

    print(f"wrote external report artifacts to {out.as_posix()}")
    print(
        f"model: {summary.model}  "
        f"scenario: {summary.scenario_id}  "
        f"checks: {summary.total_checks}  "
        f"repeats: {summary.total_repeats}  "
        f"findings: {len(summary.patterns_with_findings)}  "
        f"flaky: {len(summary.flaky_patterns)}"
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
        return _scenarios(verbose=getattr(args, "verbose", False))
    if args.command == "run-matrix":
        return _run_matrix(
            args.target,
            args.scenario,
            args.out,
            args.max_variants,
            args.variant,
            args.list_variants,
        )
    if args.command == "run-external":
        return _run_external(
            args.base_url,
            args.model,
            args.scenario,
            args.out,
            args.repeats,
            args.temperature,
            args.timeout,
            args.api_key_env,
            args.max_variants,
            args.variant,
            args.dry_run,
            args.adapter,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
