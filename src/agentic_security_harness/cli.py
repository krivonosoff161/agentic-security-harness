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
from datetime import UTC, datetime
from pathlib import Path

from agentic_security_harness import __version__
from agentic_security_harness.adapters import list_targets, make_target, target_ids
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import write_comparison, write_reports
from agentic_security_harness.run_config import (
    _MAX_REPEATS,
    _MAX_TOTAL_REQUESTS,
    _redact_url,
)
from agentic_security_harness.run_manifest import (
    build_manifest,
    load_run_manifests,
    write_run_manifest,
)
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scenarios import list_scenarios, scenario_ids
from agentic_security_harness.scorecard import build_scorecard
from agentic_security_harness.validation import validate_path

_TARGETS = target_ids()


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifact_names(out: Path) -> list[str]:
    """Relative file paths under ``out`` (excluding the manifest itself)."""
    names: list[str] = []
    for p in sorted(out.rglob("*")):
        if p.is_file() and p.name != "run_index.json":
            names.append(p.relative_to(out).as_posix())
    return names


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
        "--max-requests",
        type=int,
        default=_MAX_TOTAL_REQUESTS,
        help=(
            "safety cap on total requests "
            f"(patterns x variants x repeats; default: {_MAX_TOTAL_REQUESTS})"
        ),
    )
    ext_p.add_argument(
        "--dry-run",
        action="store_true",
        help="preview request count and config; makes no network call, writes no files",
    )

    check_p = sub.add_parser(
        "external-check",
        help="check external adapter configuration without running a benchmark",
    )
    check_p.add_argument(
        "--adapter",
        default="openai-compatible",
        help="adapter type (default: openai-compatible)",
    )
    check_p.add_argument(
        "--base-url",
        required=True,
        help="OpenAI-compatible API base URL",
    )
    check_p.add_argument(
        "--model",
        required=True,
        help="model name",
    )
    check_p.add_argument(
        "--scenario",
        choices=scenario_ids(),
        default="data-boundary",
        help="scenario id (default: data-boundary)",
    )
    check_p.add_argument(
        "--api-key-env",
        default="",
        help="environment variable name containing the API key",
    )
    check_p.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="number of repeats (default: 1)",
    )
    check_p.add_argument(
        "--max-variants",
        type=int,
        default=1,
        help="maximum number of variants (default: 1)",
    )
    check_p.add_argument(
        "--max-requests",
        type=int,
        default=_MAX_TOTAL_REQUESTS,
        help=f"safety cap on total requests (default: {_MAX_TOTAL_REQUESTS})",
    )
    check_p.add_argument(
        "--live",
        action="store_true",
        help="make one test request to verify connectivity (requires network)",
    )

    runs_p = sub.add_parser(
        "list-runs",
        help="list run directories (run_index.json) found under a root path",
    )
    runs_p.add_argument(
        "--root",
        type=Path,
        default=Path("reports"),
        help="directory to scan for run manifests (default: reports)",
    )

    doctor_p = sub.add_parser(
        "doctor",
        help="run onboarding diagnostics (no network unless --live-local)",
    )
    doctor_p.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    doctor_p.add_argument(
        "--live-local",
        action="store_true",
        help="make one request to a LOCAL endpoint to verify connectivity",
    )
    doctor_p.add_argument(
        "--base-url",
        default="http://127.0.0.1:8766/v1",
        help="local endpoint for --live-local (default: fake server)",
    )
    doctor_p.add_argument(
        "--api-key-env",
        default="ASH_EXTERNAL_API_KEY",
        help="env var name to check for presence (value never read/printed)",
    )

    report_p = sub.add_parser(
        "report",
        help="render a static HTML report for a run directory (no network)",
    )
    report_p.add_argument(
        "--root",
        type=Path,
        required=True,
        help="run directory (run, compare, matrix, or external) to render",
    )
    report_p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output HTML file (default: <root>/report.html)",
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
    manifest = build_manifest(
        "run",
        out,
        target=scorecard.target_name,
        scenario="seed-corpus",
        outcomes={
            "failed": len(scorecard.failed_patterns),
            "passed": len(scorecard.passed_patterns),
        },
        artifacts=_artifact_names(out),
        tool_version=__version__,
        created_at=_now_utc(),
    )
    write_run_manifest(out, manifest)
    print(f"wrote {', '.join(all_files)}, run_index.json to {out.as_posix()}")
    print(
        f"target: {scorecard.target_name}  "
        f"traces: {scorecard.total_traces}  "
        f"failed: {len(scorecard.failed_patterns)}  "
        f"passed: {len(scorecard.passed_patterns)}"
    )
    if remediation.recommendations:
        families = ", ".join(remediation.control_families[:5])
        print(f"control families: {families}")
    print(f"Start here: {(out / 'executive.md').as_posix()}  (run id {manifest.run_id})")
    return 0


def _compare(baseline: str, protected: str, out: Path) -> int:
    patterns = seed_patterns()
    base_traces = HarnessRunner(make_target(baseline)).run_many(patterns)
    base_card = build_scorecard(base_traces)
    prot_traces = HarnessRunner(make_target(protected)).run_many(patterns)
    prot_card = build_scorecard(prot_traces)
    write_comparison(out, base_traces, base_card, prot_traces, prot_card)
    manifest = build_manifest(
        "compare",
        out,
        target=f"{base_card.target_name} vs {prot_card.target_name}",
        scenario="seed-corpus",
        outcomes={
            "baseline_failed": len(base_card.failed_patterns),
            "protected_failed": len(prot_card.failed_patterns),
        },
        artifacts=_artifact_names(out),
        tool_version=__version__,
        created_at=_now_utc(),
    )
    write_run_manifest(out, manifest)
    print(f"wrote baseline/, protected/, comparison.md, run_index.json to {out.as_posix()}")
    print(
        f"baseline: {base_card.target_name} "
        f"failed={len(base_card.failed_patterns)}  "
        f"protected: {prot_card.target_name} "
        f"failed={len(prot_card.failed_patterns)}"
    )
    print(f"Start here: {(out / 'comparison.md').as_posix()}  (run id {manifest.run_id})")
    return 0


def _validate(path: Path) -> int:
    result = validate_path(path)
    print(
        f"validated {len(result.report_dirs)} report dir(s), "
        f"{len(result.comparison_dirs)} comparison dir(s), "
        f"{len(result.external_dirs)} external dir(s)"
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
        print("(artifact integrity only - not a safety or security guarantee)")
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
    manifest = build_manifest(
        "matrix",
        out,
        target=report.target_name,
        scenario=report.scenario_id,
        variants=[v.variant_id for v in report.variants],
        outcomes={
            "failed_variants": s.failed_variants,
            "passed_variants": s.passed_variants,
            "total_traces": s.total_traces,
        },
        artifacts=_artifact_names(out),
        tool_version=__version__,
        created_at=_now_utc(),
    )
    write_run_manifest(out, manifest)
    print(f"wrote matrix artifacts, run_index.json to {out.as_posix()}")
    print(
        f"target: {report.target_name}  "
        f"scenario: {report.scenario_id}  "
        f"variants: {s.total_variants}  "
        f"traces: {s.total_traces}  "
        f"failed variants: {s.failed_variants}  "
        f"passed variants: {s.passed_variants}"
    )
    print(f"Start here: {(out / 'matrix.md').as_posix()}  (run id {manifest.run_id})")
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
    max_requests: int,
) -> int:
    from agentic_security_harness.external_runner import run_external
    from agentic_security_harness.scenarios import get_scenario, get_variants

    if repeats < 1 or repeats > _MAX_REPEATS:
        print(f"Error: repeats must be between 1 and {_MAX_REPEATS}")
        return 1

    if adapter != "openai-compatible":
        print(
            f"Error: unsupported adapter '{adapter}'. "
            "Only 'openai-compatible' is supported."
        )
        return 1

    # Estimate request count and enforce the cost safety cap before any call.
    try:
        scenario = get_scenario(scenario_id)
        variants = get_variants(scenario_id, max_variants, variant_id)
    except KeyError as exc:
        print(f"Error: {exc}")
        return 1
    estimate = len(scenario.pattern_ids) * len(variants) * repeats
    if estimate > max_requests:
        print(
            f"Error: estimated {estimate} requests "
            f"({len(scenario.pattern_ids)} patterns x {len(variants)} variants "
            f"x {repeats} repeats) exceeds the safety cap of {max_requests}."
        )
        print(f"  Raise it with --max-requests {estimate}, or reduce scope.")
        print("  Use --dry-run first to preview without spending anything.")
        return 1

    if dry_run:
        run_external(
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
            dry_run=True,
        )
        print("No network call. No files written. (dry run)")
        if api_key_env:
            print(f"  Set the key first: $env:{api_key_env}='...' (PowerShell)")
        print("Next: re-run without --dry-run to execute.")
        return 0

    print(f"Estimated requests: {estimate}  (cap: {max_requests})")
    print(f"Artifacts will be written to {out.as_posix()}")
    print("API key value is never stored; only the env var name is recorded.")

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
            dry_run=False,
        )
    except KeyError as exc:
        print(f"Error: {exc}")
        return 1

    manifest = build_manifest(
        "external",
        out,
        model=summary.model,
        scenario=summary.scenario_id,
        repeats=repeats,
        outcomes={
            "checks": summary.total_checks,
            "requests": summary.total_repeats,
            "findings": len(summary.patterns_with_findings),
            "flaky": len(summary.flaky_patterns),
            "inconclusive": len(summary.inconclusive_patterns),
            "errors": len(summary.error_patterns),
        },
        metadata={
            "adapter_type": "openai-compatible",
            "model": summary.model,
            "base_url_label": _redact_url(base_url),
            "scenario": summary.scenario_id,
            "max_variants": max_variants,
            "repeats": repeats,
            "temperature": temperature,
            "timeout_seconds": timeout,
            "request_count": summary.total_repeats,
            "network_mode": "explicit-external",
            "api_key_env": api_key_env,
        },
        artifacts=_artifact_names(out),
        tool_version=__version__,
        created_at=_now_utc(),
    )
    write_run_manifest(out, manifest)
    print(f"wrote external report artifacts, run_index.json to {out.as_posix()}")
    print(
        f"model: {summary.model}  "
        f"scenario: {summary.scenario_id}  "
        f"checks: {summary.total_checks}  "
        f"requests: {summary.total_repeats}  "
        f"findings: {len(summary.patterns_with_findings)}  "
        f"flaky: {len(summary.flaky_patterns)}"
    )
    if summary.error_patterns:
        print(
            f"  {len(summary.error_patterns)} pattern(s) errored "
            "(see external_results.json for structured errors)."
        )
    print(f"Start here: {(out / 'external_report.md').as_posix()}  (run id {manifest.run_id})")
    print("Next: ash validate " + out.as_posix())
    return 0


def _doctor(
    as_json: bool, live_local: bool, base_url: str, api_key_env: str
) -> int:
    import json as _json

    from agentic_security_harness.doctor import run_doctor

    report = run_doctor(
        live_local=live_local, base_url=base_url, api_key_env=api_key_env
    )
    if as_json:
        print(_json.dumps(report.model_dump(mode="json"), indent=2))
        return 0 if report.ok else 1

    print("ash doctor - environment diagnostics")
    print("=" * 40)
    mark = {True: "OK", False: "!!", None: "--"}
    for check in report.checks:
        print(f"  [{mark[check.ok]:2s}] {check.name:20s} {check.detail}")
    print("")
    print("Result: ready" if report.ok else "Result: issues found (see [!!] above)")
    print("Next:")
    for cmd in report.next_commands:
        print(f"  {cmd}")
    return 0 if report.ok else 1


def _report(root: Path, out: Path | None) -> int:
    from agentic_security_harness.html_report import write_html_report

    if not root.exists() or not root.is_dir():
        print(f"Error: run directory not found: {root.as_posix()}")
        print("Tip: pass --root <a run/compare/matrix/external output dir>.")
        return 1
    target = out if out is not None else root / "report.html"
    try:
        path = write_html_report(root, target)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    print(f"wrote HTML report to {path.as_posix()}")
    print("Static, self-contained HTML: no network, no external resources.")
    print(f"Open it in a browser: {path.as_posix()}")
    return 0


def _list_runs(root: Path) -> int:
    manifests = load_run_manifests(root)
    if not manifests:
        print(f"No runs found under {root.as_posix()}.")
        print("Run a benchmark first, e.g. ash run --out reports/demo")
        return 0
    print(f"Found {len(manifests)} run(s) under {root.as_posix()}:")
    print(f"{'run_id':14s} {'kind':9s} {'scenario':16s} {'target/model':28s} outcomes")
    for path, m in manifests:
        target = (m.target or m.model or "-")[:28]
        outcomes = "  ".join(f"{k}={v}" for k, v in m.outcomes.items())
        when = f"  [{m.created_at}]" if m.created_at else ""
        print(
            f"{m.run_id:14s} {m.run_kind:9s} {m.scenario[:16]:16s} "
            f"{target:28s} {outcomes}{when}"
        )
        print(f"  -> {path.parent.as_posix()}")
    return 0


def _external_check(
    base_url: str,
    model: str,
    scenario_id: str,
    adapter: str,
    api_key_env: str,
    repeats: int,
    max_variants: int,
    live: bool,
    max_requests: int,
) -> int:
    from agentic_security_harness.run_config import _redact_url
    from agentic_security_harness.scenarios import get_scenario, get_variants

    print("External adapter configuration check")
    print("=" * 40)

    # Check adapter
    if adapter != "openai-compatible":
        print(f"  Adapter: {adapter} -- UNSUPPORTED (only openai-compatible)")
        return 1
    print(f"  Adapter: {adapter} -- OK")

    # Check base URL
    redacted = _redact_url(base_url)
    print(f"  Base URL: {redacted}")

    # Check model
    if not model:
        print("  Model: MISSING -- provide --model")
        return 1
    print(f"  Model: {model} -- OK")

    # Check scenario
    try:
        scenario = get_scenario(scenario_id)
    except KeyError as exc:
        print(f"  Scenario: {exc}")
        return 1
    print(f"  Scenario: {scenario_id} -- OK ({len(scenario.pattern_ids)} patterns)")

    # Check variants
    try:
        variants = get_variants(scenario_id, max_variants)
    except KeyError as exc:
        print(f"  Variants: {exc}")
        return 1
    print(f"  Variants: {len(variants)} selected")

    # Estimate requests
    total = len(scenario.pattern_ids) * len(variants) * repeats
    print(f"  Estimated requests: {total} ({len(scenario.pattern_ids)} patterns x "
          f"{len(variants)} variants x {repeats} repeats)")
    if total > max_requests:
        print(
            f"  Cost cap: {total} exceeds the safety cap of {max_requests} -- "
            f"run-external will refuse. Raise with --max-requests {total} or "
            "reduce scope."
        )
    else:
        print(f"  Cost cap: {max_requests} (within budget)")

    # Check API key env
    if api_key_env:
        import os

        val = os.environ.get(api_key_env)
        if val:
            print(f"  API key env ({api_key_env}): SET (value hidden)")
        else:
            print(f"  API key env ({api_key_env}): NOT SET")
        print(f"    Linux/macOS: export {api_key_env}=your_key")
        print(f"    PowerShell:  $env:{api_key_env}='your_key'")
    else:
        print("  API key env: not specified (local server may not need one)")

    # Check repeats
    from agentic_security_harness.run_config import _MAX_REPEATS

    if repeats < 1 or repeats > _MAX_REPEATS:
        print(f"  Repeats: {repeats} -- OUT OF RANGE (max {_MAX_REPEATS})")
        return 1
    print(f"  Repeats: {repeats} -- OK")

    # Live mode
    if live:
        print("\nLive mode: making one test request...")
        try:
            from agentic_security_harness.external_openai_compatible import (
                chat_completion,
            )

            resp = chat_completion(
                base_url=base_url,
                model=model,
                messages=[{"role": "user", "content": "ping"}],
                timeout_seconds=10,
                api_key_env=api_key_env,
            )
            print("  Live request: SUCCESS")
            print(f"  Response model: {resp.get('model', 'unknown')}")
        except Exception as exc:
            print(f"  Live request: FAILED -- {exc}")
            return 1
    else:
        print(
            "\n  Tip: add --live to make exactly one test request "
            "(verifies connectivity; counts as 1 request)."
        )

    print("\nConfiguration looks valid.")
    print(
        "Note: external-check and --dry-run make no benchmark network calls; "
        "only --live and a real run-external do."
    )
    # Concrete copy-pasteable next step (dry-run first, then the live run).
    key_flag = f" --api-key-env {api_key_env}" if api_key_env else ""
    next_cmd = (
        f"ash run-external --base-url {redacted} --model {model} "
        f"--scenario {scenario_id} --repeats {repeats} "
        f"--max-variants {max_variants}{key_flag}"
    )
    print("Next steps:")
    print(f"  1) dry-run (no network, no files): {next_cmd} --dry-run")
    print(f"  2) live run:                       {next_cmd} --out reports/external-run")
    print("  3) validate:                       ash validate reports/external-run")
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
            args.max_requests,
        )
    if args.command == "external-check":
        return _external_check(
            args.base_url,
            args.model,
            args.scenario,
            args.adapter,
            args.api_key_env,
            args.repeats,
            args.max_variants,
            getattr(args, "live", False),
            args.max_requests,
        )
    if args.command == "list-runs":
        return _list_runs(args.root)
    if args.command == "report":
        return _report(args.root, args.out)
    if args.command == "doctor":
        return _doctor(args.json, args.live_local, args.base_url, args.api_key_env)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
