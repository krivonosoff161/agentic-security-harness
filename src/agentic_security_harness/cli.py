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
import json
from datetime import UTC, datetime
from pathlib import Path

from agentic_security_harness import __version__
from agentic_security_harness.adapters import list_targets, make_target, target_ids
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.presets import (
    apply_preset,
    infer_runtime_profile,
    list_presets,
    preset_names,
)
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
from agentic_security_harness.safe_io import redact_artifact_text
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
        description="Agentic Security Harness - trace-first defensive benchmark harness.",
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
    val_p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
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
        "--preset",
        default=None,
        choices=preset_names(),
        help="connection preset that fills a default base URL (see `ash external-presets`)",
    )
    ext_p.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible API base URL (required unless --preset is given)",
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
        "--retries",
        type=int,
        default=1,
        help="retry count for transient external API failures (default: 1, max: 3)",
    )
    ext_p.add_argument(
        "--raw-response-limit",
        type=int,
        default=0,
        help="chars kept in external_results.raw_response (0 = full; full text is always saved)",
    )
    ext_p.add_argument(
        "--credential-env",
        "--api-key-env",
        dest="credential_env_var",
        default="",
        help="environment variable name containing an optional API credential",
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
        "--preset",
        default=None,
        choices=preset_names(),
        help="connection preset that fills a default base URL",
    )
    check_p.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible API base URL (required unless --preset is given)",
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
        "--credential-env",
        "--api-key-env",
        dest="credential_env_var",
        default="",
        help="environment variable name containing an optional API credential",
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
    runs_p.add_argument(
        "--db",
        type=Path,
        default=None,
        help="read from a SQLite run index instead of scanning (see `ash index-runs`)",
    )

    index_p = sub.add_parser(
        "index-runs",
        help="index run manifests under a root into a local SQLite file (metadata only)",
    )
    index_p.add_argument(
        "--root", type=Path, default=Path("reports"),
        help="directory to scan for run manifests (default: reports)",
    )
    index_p.add_argument(
        "--db", type=Path, default=Path("reports/runs.db"),
        help="SQLite index path (default: reports/runs.db)",
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
        "--credential-env",
        "--api-key-env",
        dest="credential_env_var",
        default="ASH_EXTERNAL_API_KEY",
        help="credential env var name to check for presence (value never printed)",
    )
    doctor_p.add_argument(
        "--reports-root",
        type=Path,
        default=None,
        help="reports directory to check is writable (default: ./reports)",
    )

    sub.add_parser(
        "external-presets",
        help="list connection presets for the external OpenAI-compatible path",
    )

    diff_p = sub.add_parser(
        "diff-runs",
        help="compare two run directories of the same kind (run/matrix/external)",
    )
    diff_p.add_argument("--left", type=Path, required=True, help="left run directory")
    diff_p.add_argument("--right", type=Path, required=True, help="right run directory")
    diff_p.add_argument(
        "--out",
        type=Path,
        required=True,
        help="output directory for run_diff.json / run_diff.md",
    )

    model_cmp_p = sub.add_parser(
        "compare-models",
        help="compare two external model run directories",
    )
    model_cmp_p.add_argument("--left", type=Path, required=True, help="left external run")
    model_cmp_p.add_argument("--right", type=Path, required=True, help="right external run")
    model_cmp_p.add_argument(
        "--out",
        type=Path,
        required=True,
        help="output directory for model comparison diff artifacts",
    )
    model_cmp_p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )

    stats_p = sub.add_parser(
        "stats",
        help="summarize run history from run_index.json manifests",
    )
    stats_p.add_argument(
        "--root",
        type=Path,
        default=Path("reports"),
        help="directory to scan for run manifests (default: reports)",
    )
    stats_p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="optional output directory for run_stats.json / run_stats.md",
    )
    stats_p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )

    retention_p = sub.add_parser(
        "retention",
        help="plan or apply retention for old run directories",
    )
    retention_p.add_argument(
        "--root",
        type=Path,
        default=Path("reports"),
        help="directory to scan for run manifests (default: reports)",
    )
    retention_p.add_argument(
        "--keep-last",
        type=int,
        default=20,
        help="runs to keep per kind (default: 20)",
    )
    retention_p.add_argument(
        "--kind",
        action="append",
        default=[],
        help="limit to one run kind; may be repeated",
    )
    retention_p.add_argument(
        "--apply",
        action="store_true",
        help="remove selected run directories (default is dry-run plan only)",
    )
    retention_p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
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


def _validate(path: Path, output_format: str = "text") -> int:
    result = validate_path(path)
    redacted_errors = [redact_artifact_text(msg) for msg in result.errors]
    redacted_warnings = [redact_artifact_text(msg) for msg in result.warnings]
    if output_format == "json":
        safe_result = result.model_copy(
            update={"errors": redacted_errors, "warnings": redacted_warnings}
        )
        # Validation messages are redacted before printing.
        # codeql[py/clear-text-logging-sensitive-data]
        print(json.dumps(safe_result.model_dump(mode="json"), indent=2))
        return 0 if result.ok else 1
    print(
        f"validated {len(result.report_dirs)} report dir(s), "
        f"{len(result.comparison_dirs)} comparison dir(s), "
        f"{len(result.external_dirs)} external dir(s), "
        f"{len(result.run_diff_dirs)} run-diff dir(s)"
    )
    print(f"errors: {len(result.errors)}  warnings: {len(result.warnings)}")
    if redacted_errors or redacted_warnings:
        print(
            "Validation message details are hidden in text output to avoid "
            "printing artifact contents."
        )
        print("Use `ash validate --format json` for redacted machine-readable details.")
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
    retries: int,
    raw_response_limit: int,
    credential_env_var: str,
    max_variants: int,
    variant_id: str | None,
    dry_run: bool,
    adapter: str,
    max_requests: int,
    preset_name: str | None,
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
    if retries < 0 or retries > 3:
        print("Error: retries must be between 0 and 3")
        return 1
    if raw_response_limit < 0:
        print("Error: raw-response-limit must be >= 0")
        return 1
    runtime_profile = infer_runtime_profile(preset_name, base_url)

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
            max_retries=retries,
            raw_response_limit=raw_response_limit,
            credential_env_var=credential_env_var,
            max_variants=max_variants,
            only_variant_id=variant_id,
            dry_run=True,
            preset_name=preset_name,
        )
        print("No network call. No files written. (dry run)")
        if credential_env_var:
            print(
                f"  Credential env var required: {credential_env_var} "
                "(set its value in your shell before the live run)."
            )
        print("Next: re-run without --dry-run to execute.")
        return 0

    print(f"Estimated requests: {estimate}  (cap: {max_requests})")
    print(f"Artifacts will be written to {out.as_posix()}")
    print(
        f"Runtime: {runtime_profile.runtime_name}  "
        f"network_mode: {runtime_profile.network_mode}  "
        f"prompt_only: true"
    )
    print("Credential values are never stored; only the env var name is recorded.")

    try:
        summary = run_external(
            base_url=base_url,
            model=model,
            scenario_id=scenario_id,
            out_dir=out,
            repeats=repeats,
            temperature=temperature,
            timeout_seconds=timeout,
            max_retries=retries,
            raw_response_limit=raw_response_limit,
            credential_env_var=credential_env_var,
            max_variants=max_variants,
            only_variant_id=variant_id,
            dry_run=False,
            preset_name=preset_name,
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
            "max_retries": retries,
            "raw_response_limit": raw_response_limit,
            "request_count": summary.total_repeats,
            "runtime_name": runtime_profile.runtime_name,
            "runtime_family": runtime_profile.runtime_family,
            "network_mode": runtime_profile.network_mode,
            "authorization_mode": runtime_profile.authorization_mode,
            "local_only": runtime_profile.local_only,
            "prompt_only": True,
            "tool_execution": False,
            "credential_env_var": credential_env_var,
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
    as_json: bool,
    live_local: bool,
    base_url: str,
    credential_env_var: str,
    reports_root: Path | None,
) -> int:
    import json as _json

    from agentic_security_harness.doctor import run_doctor

    report = run_doctor(
        reports_root=reports_root,
        live_local=live_local,
        base_url=base_url,
        credential_env_var=credential_env_var,
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


def _external_presets() -> int:
    print("Connection presets for the external OpenAI-compatible path:")
    print(
        "(presets only fill a default base URL + credential env-var NAME; "
        "network is still opt-in)"
    )
    print(f"{'preset':26s} {'key':4s} base_url")
    for p in list_presets():
        key = "yes" if p.needs_key else "no"
        print(f"{p.name:26s} {key:4s} {p.base_url}")
        print(f"{'':31s} {p.notes}")
    print("\nUse: ash external-check --preset <name> --model <model>")
    print("Vendor URLs are starting points; confirm the current value in provider docs.")
    return 0


def _diff_runs(left: Path, right: Path, out: Path) -> int:
    from agentic_security_harness.run_diff import diff_runs, write_run_diff

    for label, p in (("--left", left), ("--right", right)):
        if not p.exists() or not p.is_dir():
            print(f"Error: {label} run directory not found: {p.as_posix()}")
            return 1
    try:
        diff = diff_runs(left, right)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    write_run_diff(diff, out)
    print(f"wrote run_diff.json, run_diff.md to {out.as_posix()}")
    print(
        f"kind: {diff.kind}  fixed: {diff.fixed}  new: {diff.new}  "
        f"changed: {diff.changed}  unchanged: {diff.unchanged}"
    )
    print("Diff is an artifact comparison, not a re-run or a certification.")
    print("Next: ash report --root " + out.as_posix() + "  (or open run_diff.md)")
    return 0


def _compare_models(left: Path, right: Path, out: Path, output_format: str = "text") -> int:
    from agentic_security_harness.html_report import detect_kind
    from agentic_security_harness.run_diff import diff_runs, write_run_diff

    for label, p in (("--left", left), ("--right", right)):
        if not p.exists() or not p.is_dir():
            print(f"Error: {label} external run directory not found: {p.as_posix()}")
            return 1
        if detect_kind(p) != "external":
            print(f"Error: {label} is not an external run directory: {p.as_posix()}")
            return 1
    diff = diff_runs(left, right)
    write_run_diff(diff, out)
    if output_format == "json":
        print(json.dumps(diff.model_dump(mode="json"), indent=2))
        return 0
    print(f"wrote model comparison artifacts to {out.as_posix()}")
    print(
        f"fixed: {diff.fixed}  new: {diff.new}  changed: {diff.changed}  "
        f"unchanged: {diff.unchanged}"
    )
    print("Comparison is based on recorded external artifacts; it does not call models.")
    return 0


def _stats(root: Path, out: Path | None, output_format: str = "text") -> int:
    from agentic_security_harness.stats import build_run_stats, write_run_stats

    stats = build_run_stats(root)
    if out is not None:
        write_run_stats(stats, out)
    if output_format == "json":
        print(json.dumps(stats.model_dump(mode="json"), indent=2))
        return 0
    print(f"Run stats for {root.as_posix()}")
    print(f"  total runs: {stats.total_runs}")
    for kind, count in stats.by_kind.items():
        print(f"  {kind}: {count}")
    if out is not None:
        print(f"wrote run_stats.json, run_stats.md to {out.as_posix()}")
    return 0


def _retention(
    root: Path,
    keep_last: int,
    kinds: list[str],
    apply: bool,
    output_format: str = "text",
) -> int:
    from agentic_security_harness.run_manifest import _RUN_KINDS
    from agentic_security_harness.stats import apply_retention_plan, build_retention_plan

    bad = sorted(set(kinds) - set(_RUN_KINDS))
    if bad:
        print(f"Error: unknown run kind(s): {', '.join(bad)}")
        return 1
    try:
        plan = build_retention_plan(root, keep_last=keep_last, kinds=kinds)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    if output_format == "json" and not apply:
        print(json.dumps(plan.model_dump(mode="json"), indent=2))
        return 0
    print(
        f"Retention plan for {root.as_posix()}: "
        f"{len(plan.candidates)} candidate(s), keep_last={keep_last}"
    )
    for c in plan.candidates:
        print(f"  {c.run_kind:9s} {c.run_id:14s} {c.run_dir}  ({c.reason})")
    if not apply:
        print("Dry run only. Re-run with --apply to remove these run directories.")
        return 0
    try:
        applied = apply_retention_plan(plan)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    if output_format == "json":
        print(json.dumps(applied.model_dump(mode="json"), indent=2))
        return 0
    print(f"Removed {applied.removed} run dir(s).")
    return 0


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


def _list_runs(root: Path, db: Path | None) -> int:
    if db is not None:
        from agentic_security_harness.rundb import list_db_runs

        rows = list_db_runs(db)
        if not rows:
            print(f"No runs in index {db.as_posix()}. Build it with ash index-runs.")
            return 0
        print(f"Found {len(rows)} run(s) in {db.as_posix()}:")
        for r in rows:
            oc = r.get("outcomes") or {}
            oc_dict = oc if isinstance(oc, dict) else {}
            outcomes = "  ".join(f"{k}={v}" for k, v in oc_dict.items())
            print(f"{str(r['run_id']):14s} {str(r['run_kind']):9s} "
                  f"{str(r.get('scenario', '') or '')[:16]:16s} "
                  f"{str(r.get('target') or r.get('model') or '-')[:28]:28s} {outcomes}")
            print(f"  -> {r.get('manifest_path', '')}")
        return 0
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


def _index_runs(root: Path, db: Path) -> int:
    from agentic_security_harness.rundb import index_runs

    if not root.exists() or not root.is_dir():
        print(f"Error: root not found: {root.as_posix()}")
        return 1
    count = index_runs(root, db)
    print(f"indexed {count} run(s) from {root.as_posix()} into {db.as_posix()}")
    print("Metadata only (run id/kind/target/model/scenario/outcomes); no trace bodies.")
    print("Read it with: ash list-runs --db " + db.as_posix())
    return 0


def _external_check(
    base_url: str,
    model: str,
    scenario_id: str,
    adapter: str,
    credential_env_var: str,
    repeats: int,
    max_variants: int,
    live: bool,
    max_requests: int,
    preset_name: str | None,
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
    runtime_profile = infer_runtime_profile(preset_name, base_url)
    print(f"  Runtime: {runtime_profile.runtime_name} ({runtime_profile.runtime_family})")
    print(f"  Network mode: {runtime_profile.network_mode}")
    print(f"  Authorization mode: {runtime_profile.authorization_mode}")
    print("  Prompt-only: yes; tool execution: no")
    print(f"  Model/license note: {runtime_profile.model_license_note}")

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

    # Check credential env var
    if credential_env_var:
        import os

        val = os.environ.get(credential_env_var)
        if val:
            print(f"  Credential env var ({credential_env_var}): SET (value hidden)")
        else:
            print(f"  Credential env var ({credential_env_var}): NOT SET")
        print("    Set this environment variable in your shell before a live run.")
        print("    The value is only read for the request header; it is not printed.")
    else:
        print("  Credential env var: not specified (local server may not need one)")

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
                credential_env_var=credential_env_var,
            )
            print("  Live request: SUCCESS")
            print(f"  Response model: {resp.get('model', 'unknown')}")
        except Exception as exc:
            print(f"  Live request: FAILED -- {exc}")
            print("  Recovery:")
            for hint in runtime_profile.recovery_guidance:
                print(f"    - {hint}")
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
    credential_flag = (
        f" --credential-env {credential_env_var}" if credential_env_var else ""
    )
    next_cmd = (
        f"ash run-external --base-url {redacted} --model {model} "
        f"--scenario {scenario_id} --repeats {repeats} "
        f"--max-variants {max_variants}{credential_flag}"
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
        return _validate(args.path, args.format)
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
    if args.command == "external-presets":
        return _external_presets()
    if args.command in ("run-external", "external-check"):
        try:
            base_url, credential_env_var, err = apply_preset(
                args.preset, args.base_url, args.credential_env_var
            )
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if args.preset:
            print(f"Using preset '{args.preset}': base_url {_redact_url(base_url)}")
        if args.command == "run-external":
            return _run_external(
                base_url,
                args.model,
                args.scenario,
                args.out,
                args.repeats,
                args.temperature,
                args.timeout,
                args.retries,
                args.raw_response_limit,
                credential_env_var,
                args.max_variants,
                args.variant,
                args.dry_run,
                args.adapter,
                args.max_requests,
                args.preset,
            )
        return _external_check(
            base_url,
            args.model,
            args.scenario,
            args.adapter,
            credential_env_var,
            args.repeats,
            args.max_variants,
            getattr(args, "live", False),
            args.max_requests,
            args.preset,
        )
    if args.command == "list-runs":
        return _list_runs(args.root, args.db)
    if args.command == "index-runs":
        return _index_runs(args.root, args.db)
    if args.command == "diff-runs":
        return _diff_runs(args.left, args.right, args.out)
    if args.command == "compare-models":
        return _compare_models(args.left, args.right, args.out, args.format)
    if args.command == "stats":
        return _stats(args.root, args.out, args.format)
    if args.command == "retention":
        return _retention(args.root, args.keep_last, args.kind, args.apply, args.format)
    if args.command == "report":
        return _report(args.root, args.out)
    if args.command == "doctor":
        return _doctor(
            args.json, args.live_local, args.base_url, args.credential_env_var,
            args.reports_root,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
