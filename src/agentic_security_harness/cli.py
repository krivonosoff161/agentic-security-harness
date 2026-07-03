"""Command-line entry point.

Commands:
  ash run         --target {mock,...} --out <dir>
  ash compare     --baseline <target> --protected <target> --out <dir>
  ash validate    <path>
  ash targets
  ash scenarios [--verbose]
  ash trading-stand [--mode profile|dry-run|offline-fixture|scenario-catalog|
                    sanitize-fixture|fixture-template|invariant-fixture-template|
                    invariant-baseline-fixture|invariant-negative-control-fixture|
                    invariant-weak-control-fixture|validate-invariant-fixture|
                    static-probe|artifact-probe|artifact-invariant-probe|
                    artifact-e2e-observation|boundary-lock|boundary-lock-review|
                    experiment-plan|experiment-template|
                    experiment-baseline-fixture|experiment-control-fixture|
                    experiment-negative-control-fixture|experiment-batch-manifest|
                    validate-experiment-batch-manifest|experiment-intake|
                    experiment-readiness|
                    validate-experiment|sanitize-experiment|
                    authorized-paper]
                    [--target-path PATH] [--fixture-path PATH]
                    [--manifest-path PATH] [--artifact-root PATH]
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
from typing import Any

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

    stand_p = sub.add_parser(
        "trading-stand",
        help="show the trading-bot-v2 paper-stand profile or dry-run plan",
    )
    stand_p.add_argument(
        "--mode",
        choices=(
            "profile",
            "dry-run",
            "offline-fixture",
            "scenario-catalog",
            "sanitize-fixture",
            "fixture-template",
            "invariant-fixture-template",
            "invariant-baseline-fixture",
            "invariant-negative-control-fixture",
            "invariant-weak-control-fixture",
            "validate-invariant-fixture",
            "static-probe",
            "artifact-probe",
            "artifact-invariant-probe",
            "artifact-e2e-observation",
            "boundary-lock",
            "boundary-lock-review",
            "experiment-plan",
            "experiment-template",
            "experiment-baseline-fixture",
            "experiment-negative-control-fixture",
            "experiment-control-fixture",
            "experiment-batch-manifest",
            "validate-experiment-batch-manifest",
            "experiment-intake",
            "experiment-readiness",
            "validate-experiment",
            "sanitize-experiment",
            "authorized-paper",
        ),
        default="profile",
        help=(
            "profile prints metadata; dry-run adds preflight; offline-fixture "
            "maps sanitized controls; scenario-catalog lists public-safe scenario "
            "metadata; sanitize-fixture reads private rows and prints public-safe "
            "summary; fixture-template writes an ignored private template; "
            "invariant-fixture-template writes a payload-free private invariant "
            "template; invariant-baseline-fixture writes a private baseline from "
            "artifact invariants; invariant-negative-control-fixture checks the "
            "finding path; invariant-weak-control-fixture checks the inconclusive "
            "path; validate-invariant-fixture checks private invariant rows; "
            "static-probe reads allowlisted target files without raw content; "
            "artifact-probe reads allowlisted paper artifacts without raw rows; "
            "artifact-invariant-probe maps artifacts to the 7 scenario invariants; "
            "artifact-e2e-observation summarizes real paper artifacts without raw rows; "
            "boundary-lock scans allowlisted observation files for boundary markers; "
            "boundary-lock-review classifies boundary markers without source lines; "
            "experiment-plan prepares controlled parallel paper experiments; "
            "experiment-template writes a private payload-free experiment template; "
            "experiment-baseline-fixture writes observed private baseline rows; "
            "experiment-negative-control-fixture writes private finding controls; "
            "experiment-control-fixture writes a private inconclusive control fixture; "
            "experiment-batch-manifest writes a private batch guard; "
            "validate-experiment-batch-manifest validates the private batch guard; "
            "experiment-intake gates private filled rows before public summaries; "
            "experiment-readiness evaluates gates before private filled rows; "
            "validate-experiment checks private experiment rows; "
            "sanitize-experiment emits public-safe experiment summaries; "
            "authorized-paper shows fail-closed gates"
        ),
    )
    stand_p.add_argument(
        "--target-path",
        type=Path,
        default=None,
        help="optional local trading-bot-v2 path for read-only shape preflight",
    )
    stand_p.add_argument(
        "--fixture-path",
        type=Path,
        default=None,
        help="private fixture JSON path for sanitize-fixture mode",
    )
    stand_p.add_argument(
        "--manifest-path",
        type=Path,
        default=None,
        help="private batch manifest JSON path for experiment-intake mode",
    )
    stand_p.add_argument(
        "--artifact-root",
        type=Path,
        default=None,
        help=(
            "optional private paper artifact root for artifact-probe mode; "
            "may point to a strategy-lab root, state/, or state/derived/"
        ),
    )
    stand_p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
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

    eq_p = sub.add_parser(
        "evidence-quality",
        help="summarize evidence quality from recorded external/local run artifacts",
    )
    eq_p.add_argument(
        "--root",
        type=Path,
        default=Path("reports"),
        help="external/local run directory or root to scan (default: reports)",
    )
    eq_p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="optional output directory for evidence_quality.json / evidence_quality.md",
    )
    eq_p.add_argument(
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

    showcase_p = sub.add_parser(
        "showcase",
        help="generate a Markdown evidence showcase from run artifacts",
    )
    showcase_p.add_argument(
        "--root",
        type=Path,
        default=Path("reports"),
        help="directory to scan for run manifests (default: reports)",
    )
    showcase_p.add_argument(
        "--out",
        type=Path,
        default=Path("docs/showcase/generated"),
        help="output directory for generated showcase markdown",
    )

    suite_p = sub.add_parser(
        "local-suite",
        help="run a bounded, named local-model smoke profile (dry-run unless --execute)",
    )
    suite_p.add_argument(
        "--profile",
        default="prometheus-lowctx-smoke",
        help="local profile name (default: prometheus-lowctx-smoke; see --list)",
    )
    suite_p.add_argument(
        "--list",
        dest="list_profiles",
        action="store_true",
        help="list the available bounded local profiles and exit",
    )
    suite_p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output directory (default: derived from the profile under reports/)",
    )
    suite_p.add_argument(
        "--base-url",
        default=None,
        help="override the preset base URL (e.g. a non-default local runtime port)",
    )
    suite_p.add_argument(
        "--execute",
        action="store_true",
        help="actually call the local model (default: dry-run, no network, no files)",
    )
    suite_p.add_argument(
        "--showcase",
        dest="run_showcase",
        action="store_true",
        help="after a validated run, generate failure cards with ash showcase",
    )

    swarm_p = sub.add_parser(
        "local-swarm",
        help="compare monolith, naive swarm, and bounded swarm on local contracts",
    )
    swarm_p.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="scenario id to run; may be repeated (default: all; use --list)",
    )
    swarm_p.add_argument(
        "--mode",
        action="append",
        default=[],
        help="mode to run; may be repeated (default: all; use --list)",
    )
    swarm_p.add_argument(
        "--list",
        dest="list_swarm",
        action="store_true",
        help="list available local-swarm scenarios and modes",
    )
    swarm_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/local-swarm"),
        help="output directory for --execute or --write-dry-run (default: reports/local-swarm)",
    )
    swarm_p.add_argument(
        "--preset",
        default="ollama",
        choices=preset_names(),
        help="connection preset for --execute (default: ollama)",
    )
    swarm_p.add_argument(
        "--base-url",
        default=None,
        help="override preset base URL for --execute",
    )
    swarm_p.add_argument(
        "--model",
        default="prometheus-qwen15b-lowctx:latest",
        help="local model for optional role calls (calculator is refused)",
    )
    swarm_p.add_argument(
        "--role-model",
        action="append",
        default=[],
        metavar="ROLE=MODEL",
        help=(
            "override the model for a local-swarm role; may be repeated "
            "(roles: coordinator, worker, memory, verifier, auditor)"
        ),
    )
    swarm_p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="request timeout in seconds for --execute (default: 60)",
    )
    swarm_p.add_argument(
        "--max-requests",
        type=int,
        default=80,
        help="safety cap for role calls (default: 80)",
    )
    swarm_p.add_argument(
        "--execute",
        action="store_true",
        help="call the local model and write artifacts (default: dry-run only)",
    )
    swarm_p.add_argument(
        "--write-dry-run",
        action="store_true",
        help="write deterministic artifacts without model calls",
    )

    swarm_matrix_p = sub.add_parser(
        "local-swarm-matrix",
        help="calculate deterministic local-swarm attack variation coverage",
    )
    swarm_matrix_p.add_argument(
        "--list",
        dest="list_swarm_matrix",
        action="store_true",
        help="list matrix cases and variation families",
    )
    swarm_matrix_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/local-swarm-attack-matrix"),
        help="output directory for matrix artifacts",
    )
    swarm_matrix_p.add_argument(
        "--write",
        action="store_true",
        help="write deterministic matrix artifacts (default: dry-run only)",
    )
    swarm_matrix_p.add_argument(
        "--execute-model",
        action="store_true",
        help="run local model evidence-quality probes for executable deep matrix rows",
    )
    swarm_matrix_p.add_argument(
        "--preset",
        default="ollama",
        help="local preset for --execute-model (default: ollama)",
    )
    swarm_matrix_p.add_argument(
        "--base-url",
        default="",
        help="override local OpenAI-compatible base URL for --execute-model",
    )
    swarm_matrix_p.add_argument(
        "--model",
        default="",
        help="local model name for --execute-model",
    )
    swarm_matrix_p.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="per-request timeout for --execute-model",
    )
    swarm_matrix_p.add_argument(
        "--max-requests",
        type=int,
        default=20,
        help="maximum model calls allowed for --execute-model",
    )
    swarm_matrix_p.add_argument(
        "--pressure-mode",
        choices=["neutral", "coercive"],
        default="neutral",
        help="model-probe pressure mode for --execute-model",
    )

    campaign_p = sub.add_parser(
        "evidence-campaign",
        help="calculate the private-ready bounded swarm evidence campaign",
    )
    campaign_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/evidence-campaign/latest"),
        help="output directory for --write (default: .internal/evidence-campaign/latest)",
    )
    campaign_p.add_argument(
        "--write",
        action="store_true",
        help="write campaign artifacts (default: dry-run only)",
    )

    secret_p = sub.add_parser(
        "secret-leak-campaign",
        help="calculate synthetic secret-leak campaign and optional private model probes",
    )
    secret_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/secret-leak-campaign/latest"),
        help="output directory (private by default)",
    )
    secret_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized deterministic campaign artifacts",
    )
    secret_p.add_argument(
        "--execute-model",
        action="store_true",
        help="also run private local-model probes; --out must be under .internal",
    )
    secret_p.add_argument(
        "--execute-variations",
        action="store_true",
        help="run private Phase 2 local-model variation probes; --out must be under .internal",
    )
    secret_p.add_argument(
        "--variation-model",
        action="append",
        default=None,
        help="local model for --execute-variations; repeatable (default: --model)",
    )
    secret_p.add_argument(
        "--variation-summary-out",
        type=Path,
        default=None,
        help="optional sanitized output dir for Phase 2 variation summary",
    )
    secret_p.add_argument(
        "--preset",
        default="ollama",
        choices=preset_names(),
        help="keyless local preset for local model probes (default: ollama)",
    )
    secret_p.add_argument(
        "--base-url",
        help="override preset base URL for --execute-model",
    )
    secret_p.add_argument(
        "--model",
        default="prometheus-qwen15b-lowctx:latest",
        help="local model name for --execute-model",
    )
    secret_p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="per-request timeout for --execute-model",
    )
    secret_p.add_argument(
        "--max-requests",
        type=int,
        default=40,
        help="hard cap for --execute-model requests",
    )
    secret_p.add_argument(
        "--pressure-mode",
        action="append",
        choices=["neutral", "coercive", "sanitized_claim", "authority_pressure"],
        help="pressure mode to include; repeatable (default: all)",
    )

    semantic_p = sub.add_parser(
        "semantic-drift-campaign",
        help="measure synthetic semantic-parameter drift in local mini-swarms",
    )
    semantic_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/semantic-drift/latest"),
        help="output directory (private by default)",
    )
    semantic_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized deterministic campaign artifacts",
    )
    semantic_p.add_argument(
        "--execute",
        action="store_true",
        help="run private local-model semantic drift probes; --out must be under .internal",
    )
    semantic_p.add_argument(
        "--model",
        action="append",
        default=None,
        help="local model to probe; repeatable (default: prometheus-qwen15b-lowctx:latest)",
    )
    semantic_p.add_argument(
        "--summary-out",
        type=Path,
        default=None,
        help="optional sanitized output dir for semantic drift summary",
    )
    semantic_p.add_argument(
        "--preset",
        default="ollama",
        choices=preset_names(),
        help="keyless local preset for local model probes (default: ollama)",
    )
    semantic_p.add_argument("--base-url", help="override preset base URL")
    semantic_p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="per-request timeout for local model probes",
    )
    semantic_p.add_argument(
        "--max-requests",
        type=int,
        default=80,
        help="hard cap for local model probe requests",
    )
    semantic_p.add_argument(
        "--pressure-mode",
        action="append",
        choices=["gentle_reframe", "authority_pressure", "pseudo_code", "memory_rewrite"],
        help="pressure mode to include; repeatable (default: all)",
    )

    propagation_p = sub.add_parser(
        "semantic-propagation-campaign",
        help="measure synthetic semantic drift propagation from worker to chief",
    )
    propagation_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/semantic-propagation/latest"),
        help="output directory (private by default)",
    )
    propagation_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized deterministic propagation artifacts",
    )
    propagation_p.add_argument(
        "--execute",
        action="store_true",
        help="run private local-model worker-to-chief probes; --out must be under .internal",
    )
    propagation_p.add_argument(
        "--worker-model",
        action="append",
        default=None,
        help="local worker model to probe; repeatable",
    )
    propagation_p.add_argument(
        "--chief-model",
        action="append",
        default=None,
        help="local chief model to probe; repeatable",
    )
    propagation_p.add_argument(
        "--summary-out",
        type=Path,
        default=None,
        help="optional sanitized output dir for semantic propagation summary",
    )
    propagation_p.add_argument(
        "--preset",
        default="ollama",
        choices=preset_names(),
        help="keyless local preset for local model probes (default: ollama)",
    )
    propagation_p.add_argument("--base-url", help="override preset base URL")
    propagation_p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="per-request timeout for local model probes",
    )
    propagation_p.add_argument(
        "--max-chains",
        type=int,
        default=64,
        help="hard cap for worker-to-chief chains",
    )
    propagation_p.add_argument(
        "--pressure-mode",
        action="append",
        choices=["gentle_reframe", "authority_pressure", "pseudo_code", "memory_rewrite"],
        help="pressure mode to include; repeatable (default: all)",
    )

    contour_p = sub.add_parser(
        "swarm-defense-contour",
        help="build the sanitized defense contour for local mini-swarm scenarios",
    )
    contour_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/swarm-defense-contour"),
        help="sanitized output directory (default: reports/swarm-defense-contour)",
    )
    contour_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized deterministic defense-contour artifacts",
    )

    live_contour_p = sub.add_parser(
        "swarm-defense-live-campaign",
        help="run private local-model probes over the swarm defense contour",
    )
    live_contour_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/swarm-defense-live/latest"),
        help="private output directory (default: .internal/swarm-defense-live/latest)",
    )
    live_contour_p.add_argument(
        "--summary-out",
        type=Path,
        default=Path("reports/swarm-defense-live"),
        help="sanitized output directory (default: reports/swarm-defense-live)",
    )
    live_contour_p.add_argument(
        "--base-url",
        default="http://127.0.0.1:11434/v1",
        help="OpenAI-compatible local base URL (default: Ollama)",
    )
    live_contour_p.add_argument(
        "--worker-model",
        action="append",
        default=None,
        help="local worker model; repeatable (default: qwen2.5:0.5b)",
    )
    live_contour_p.add_argument(
        "--chief-model",
        action="append",
        default=None,
        help="local chief model; repeatable (default: llama3.2:1b)",
    )
    live_contour_p.add_argument(
        "--pressure-mode",
        action="append",
        default=None,
        choices=[
            "gentle_reframe",
            "pseudo_code",
            "memory_rewrite",
            "authority_pressure",
            "benign_debug",
            "consensus_pressure",
            "long_session_relabel",
        ],
        help="pressure mode to include; repeatable (default: all)",
    )
    live_contour_p.add_argument(
        "--session-turns",
        type=int,
        default=1,
        help=(
            "worker turns before chief review (default: 1; use 3 for bounded "
            "long-session pressure)"
        ),
    )
    live_contour_p.add_argument(
        "--max-topologies",
        type=int,
        default=15,
        help="maximum topology combinations to probe (default: 15)",
    )
    live_contour_p.add_argument(
        "--max-requests",
        type=int,
        default=600,
        help="hard cap on estimated model requests (default: 600)",
    )
    live_contour_p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="per-request timeout in seconds (default: 60)",
    )
    live_contour_p.add_argument(
        "--execute",
        action="store_true",
        help="actually call local models and write private/sanitized artifacts",
    )

    marketing_web_p = sub.add_parser(
        "marketing-web-injection-campaign",
        help="build a controlled synthetic web-injection campaign for a marketing swarm",
    )
    marketing_web_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/marketing-web-injection/latest"),
        help=(
            "private output directory "
            "(default: .internal/marketing-web-injection/latest)"
        ),
    )
    marketing_web_p.add_argument(
        "--summary-out",
        type=Path,
        default=Path("reports/marketing-web-injection"),
        help=(
            "sanitized output directory "
            "(default: reports/marketing-web-injection)"
        ),
    )
    marketing_web_p.add_argument(
        "--write",
        action="store_true",
        help="write private raw and sanitized public artifacts",
    )

    resilience_p = sub.add_parser(
        "swarm-resilience-campaign",
        help="build a seven-family swarm resilience/stability campaign",
    )
    resilience_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/swarm-resilience/latest"),
        help="private output directory (default: .internal/swarm-resilience/latest)",
    )
    resilience_p.add_argument(
        "--summary-out",
        type=Path,
        default=Path("reports/swarm-resilience"),
        help="sanitized output directory (default: reports/swarm-resilience)",
    )
    resilience_p.add_argument(
        "--write",
        action="store_true",
        help="write private calculation and sanitized public artifacts",
    )

    context_consent_p = sub.add_parser(
        "context-consent-campaign",
        help="build the deterministic context-is-not-consent campaign",
    )
    context_consent_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/context-consent"),
        help="sanitized output directory (default: reports/context-consent)",
    )
    context_consent_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized public artifacts",
    )

    tool_authority_p = sub.add_parser(
        "tool-authority-campaign",
        help="build the deterministic tool-output authority campaign",
    )
    tool_authority_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/tool-authority"),
        help="sanitized output directory (default: reports/tool-authority)",
    )
    tool_authority_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized public artifacts",
    )

    rag_context_p = sub.add_parser(
        "rag-context-campaign",
        help="build the deterministic retrieved-context authority campaign",
    )
    rag_context_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/rag-context"),
        help="sanitized output directory (default: reports/rag-context)",
    )
    rag_context_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized public artifacts",
    )

    planner_task_p = sub.add_parser(
        "planner-task-campaign",
        help="build the deterministic planner/task authority campaign",
    )
    planner_task_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/planner-task"),
        help="sanitized output directory (default: reports/planner-task)",
    )
    planner_task_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized public artifacts",
    )

    memory_rehydration_p = sub.add_parser(
        "memory-rehydration-campaign",
        help="build the deterministic cross-agent memory rehydration campaign",
    )
    memory_rehydration_p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/memory-rehydration"),
        help="sanitized output directory (default: reports/memory-rehydration)",
    )
    memory_rehydration_p.add_argument(
        "--write",
        action="store_true",
        help="write sanitized public artifacts",
    )

    marketing_web_live_p = sub.add_parser(
        "marketing-web-live-campaign",
        help="run private local-model probes over an owned local web-injection stand",
    )
    marketing_web_live_p.add_argument(
        "--out",
        type=Path,
        default=Path(".internal/marketing-web-live/latest"),
        help="private output directory (default: .internal/marketing-web-live/latest)",
    )
    marketing_web_live_p.add_argument(
        "--summary-out",
        type=Path,
        default=Path("reports/marketing-web-live"),
        help="sanitized output directory (default: reports/marketing-web-live)",
    )
    marketing_web_live_p.add_argument(
        "--base-url",
        default="http://127.0.0.1:11434/v1",
        help="OpenAI-compatible local base URL (default: Ollama)",
    )
    marketing_web_live_p.add_argument(
        "--worker-model",
        action="append",
        default=None,
        help="local worker model; repeatable (default: qwen2.5:0.5b)",
    )
    marketing_web_live_p.add_argument(
        "--chief-model",
        action="append",
        default=None,
        help="local chief model; repeatable (default: llama3.2:1b)",
    )
    marketing_web_live_p.add_argument(
        "--max-scenarios",
        type=int,
        default=5,
        help="maximum scenario count to probe (default: 5)",
    )
    marketing_web_live_p.add_argument(
        "--session-turns",
        type=int,
        default=3,
        help="worker turns before chief review for unsafe rows (default: 3)",
    )
    marketing_web_live_p.add_argument(
        "--max-requests",
        type=int,
        default=500,
        help="hard cap on estimated model requests (default: 500)",
    )
    marketing_web_live_p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="per-request timeout in seconds (default: 60)",
    )
    marketing_web_live_p.add_argument(
        "--execute",
        action="store_true",
        help="actually call local models and write private/sanitized artifacts",
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
        f"{len(result.run_diff_dirs)} run-diff dir(s), "
        f"{len(result.local_swarm_dirs)} local-swarm dir(s), "
        f"{len(result.local_swarm_matrix_dirs)} local-swarm-matrix dir(s), "
        f"{len(result.evidence_campaign_dirs)} evidence-campaign dir(s), "
        f"{len(result.secret_leak_campaign_dirs)} secret-leak-campaign dir(s), "
        f"{len(result.secret_leak_variation_dirs)} secret-leak-variation dir(s), "
        f"{len(result.semantic_drift_campaign_dirs)} semantic-drift dir(s), "
        f"{len(result.semantic_propagation_campaign_dirs)} semantic-propagation dir(s), "
        f"{len(result.swarm_defense_contour_dirs)} swarm-defense-contour dir(s), "
        f"{len(result.swarm_defense_live_campaign_dirs)} "
        "swarm-defense-live-campaign dir(s), "
        f"{len(result.marketing_web_injection_campaign_dirs)} "
        "marketing-web-injection-campaign dir(s), "
        f"{len(result.marketing_web_live_campaign_dirs)} "
        "marketing-web-live-campaign dir(s), "
        f"{len(result.swarm_resilience_campaign_dirs)} "
        "swarm-resilience-campaign dir(s), "
        f"{len(result.context_consent_campaign_dirs)} "
        "context-consent-campaign dir(s), "
        f"{len(result.tool_authority_campaign_dirs)} "
        "tool-authority-campaign dir(s), "
        f"{len(result.rag_context_campaign_dirs)} "
        "rag-context-campaign dir(s), "
        f"{len(result.planner_task_campaign_dirs)} "
        "planner-task-campaign dir(s), "
        f"{len(result.memory_rehydration_campaign_dirs)} "
        "memory-rehydration-campaign dir(s)"
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


def _trading_stand(
    mode: str,
    target_path: Path | None,
    output_format: str,
    fixture_path: Path | None,
    manifest_path: Path | None = None,
    artifact_root: Path | None = None,
) -> int:
    from agentic_security_harness.trading_bot_stand import (
        authorized_paper_gate_report,
        boundary_lock_review_target,
        boundary_lock_target,
        dry_run_plan,
        offline_fixture_summary,
        paper_artifact_e2e_observation,
        paper_artifact_invariant_probe,
        paper_artifact_probe,
        paper_experiment_plan,
        paper_experiment_readiness,
        private_experiment_intake_report,
        sanitize_private_experiment_file,
        sanitize_private_fixture_file,
        stand_scenario_catalog_summary,
        static_probe_target,
        target_profile,
        validate_private_experiment_batch_manifest_file,
        validate_private_experiment_file,
        validate_private_invariant_fixture_file,
        write_private_experiment_baseline_fixture,
        write_private_experiment_batch_manifest,
        write_private_experiment_control_fixture,
        write_private_experiment_negative_control_fixture,
        write_private_experiment_template,
        write_private_fixture_template,
        write_private_invariant_baseline_fixture,
        write_private_invariant_fixture_template,
        write_private_invariant_negative_control_fixture,
        write_private_invariant_weak_control_fixture,
    )

    data: Any
    if mode == "profile":
        data = target_profile()
    elif mode == "dry-run":
        data = dry_run_plan(target_path)
    elif mode == "offline-fixture":
        data = offline_fixture_summary()
    elif mode == "scenario-catalog":
        data = stand_scenario_catalog_summary()
    elif mode == "sanitize-fixture":
        if fixture_path is None:
            print("Error: --fixture-path is required for sanitize-fixture mode")
            return 1
        try:
            data = sanitize_private_fixture_file(fixture_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "fixture-template":
        if fixture_path is None:
            print("Error: --fixture-path is required for fixture-template mode")
            return 1
        try:
            data = write_private_fixture_template(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "invariant-fixture-template":
        if fixture_path is None:
            print("Error: --fixture-path is required for invariant-fixture-template mode")
            return 1
        try:
            data = write_private_invariant_fixture_template(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "invariant-baseline-fixture":
        if fixture_path is None:
            print("Error: --fixture-path is required for invariant-baseline-fixture mode")
            return 1
        if target_path is None:
            print("Error: --target-path is required for invariant-baseline-fixture mode")
            return 1
        try:
            data = write_private_invariant_baseline_fixture(
                fixture_path,
                target_path,
                artifact_root=artifact_root,
            )
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "invariant-negative-control-fixture":
        if fixture_path is None:
            print(
                "Error: --fixture-path is required for "
                "invariant-negative-control-fixture mode"
            )
            return 1
        try:
            data = write_private_invariant_negative_control_fixture(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "invariant-weak-control-fixture":
        if fixture_path is None:
            print(
                "Error: --fixture-path is required for "
                "invariant-weak-control-fixture mode"
            )
            return 1
        try:
            data = write_private_invariant_weak_control_fixture(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "validate-invariant-fixture":
        if fixture_path is None:
            print("Error: --fixture-path is required for validate-invariant-fixture mode")
            return 1
        try:
            data = validate_private_invariant_fixture_file(fixture_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "static-probe":
        if target_path is None:
            print("Error: --target-path is required for static-probe mode")
            return 1
        data = static_probe_target(target_path)
    elif mode == "artifact-probe":
        if target_path is None:
            print("Error: --target-path is required for artifact-probe mode")
            return 1
        data = paper_artifact_probe(target_path, artifact_root=artifact_root)
    elif mode == "artifact-invariant-probe":
        if target_path is None:
            print("Error: --target-path is required for artifact-invariant-probe mode")
            return 1
        data = paper_artifact_invariant_probe(target_path, artifact_root=artifact_root)
    elif mode == "artifact-e2e-observation":
        if target_path is None:
            print("Error: --target-path is required for artifact-e2e-observation mode")
            return 1
        data = paper_artifact_e2e_observation(target_path, artifact_root=artifact_root)
    elif mode == "boundary-lock":
        if target_path is None:
            print("Error: --target-path is required for boundary-lock mode")
            return 1
        data = boundary_lock_target(target_path)
    elif mode == "boundary-lock-review":
        if target_path is None:
            print("Error: --target-path is required for boundary-lock-review mode")
            return 1
        data = boundary_lock_review_target(target_path)
    elif mode == "experiment-plan":
        data = paper_experiment_plan(target_path, artifact_root=artifact_root)
    elif mode == "experiment-template":
        if fixture_path is None:
            print("Error: --fixture-path is required for experiment-template mode")
            return 1
        try:
            data = write_private_experiment_template(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "experiment-baseline-fixture":
        if fixture_path is None:
            print("Error: --fixture-path is required for experiment-baseline-fixture mode")
            return 1
        if target_path is None:
            print("Error: --target-path is required for experiment-baseline-fixture mode")
            return 1
        try:
            data = write_private_experiment_baseline_fixture(
                fixture_path,
                target_path,
                artifact_root=artifact_root,
            )
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "experiment-negative-control-fixture":
        if fixture_path is None:
            print(
                "Error: --fixture-path is required for "
                "experiment-negative-control-fixture mode"
            )
            return 1
        try:
            data = write_private_experiment_negative_control_fixture(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "experiment-control-fixture":
        if fixture_path is None:
            print("Error: --fixture-path is required for experiment-control-fixture mode")
            return 1
        try:
            data = write_private_experiment_control_fixture(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "experiment-batch-manifest":
        if fixture_path is None:
            print("Error: --fixture-path is required for experiment-batch-manifest mode")
            return 1
        try:
            data = write_private_experiment_batch_manifest(fixture_path)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "validate-experiment-batch-manifest":
        if fixture_path is None:
            print(
                "Error: --fixture-path is required for "
                "validate-experiment-batch-manifest mode"
            )
            return 1
        try:
            data = validate_private_experiment_batch_manifest_file(fixture_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "experiment-intake":
        if fixture_path is None:
            print("Error: --fixture-path is required for experiment-intake mode")
            return 1
        try:
            data = private_experiment_intake_report(
                fixture_path,
                batch_manifest_path=manifest_path,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "experiment-readiness":
        if target_path is None:
            print("Error: --target-path is required for experiment-readiness mode")
            return 1
        try:
            data = paper_experiment_readiness(
                target_path,
                artifact_root=artifact_root,
                fixture_path=fixture_path,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "validate-experiment":
        if fixture_path is None:
            print("Error: --fixture-path is required for validate-experiment mode")
            return 1
        try:
            data = validate_private_experiment_file(fixture_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    elif mode == "sanitize-experiment":
        if fixture_path is None:
            print("Error: --fixture-path is required for sanitize-experiment mode")
            return 1
        try:
            data = sanitize_private_experiment_file(fixture_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
    else:
        try:
            data = authorized_paper_gate_report(
                target_path,
                artifact_root=artifact_root,
                fixture_path=fixture_path,
                batch_manifest_path=manifest_path,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1

    if output_format == "json":
        print(json.dumps(data, indent=2))
        return 0

    print(f"profile: {data['profile_id']}")
    print(f"mode: {mode}")
    print("network/provider/telegram/live execution: disabled by default")
    if mode == "profile":
        print(f"contours: {len(data['contours'])}")
        print(f"allowed surfaces: {len(data['allowed_surfaces'])}")
        print("runner modes: profile -> dry-run -> offline-fixture -> authorized-paper")
    else:
        if mode == "dry-run":
            print(f"contours: {data['contour_count']}  batches: {data['batch_count']}")
            for batch in data["batches"]:
                print(
                    f"- batch {batch['batch_id']}: {batch['purpose']} "
                    f"({len(batch['contours'])} scenarios max {batch['max_parallel_scenarios']})"
                )
        elif mode == "offline-fixture":
            counts = data["result_counts"]
            print(
                f"fixture rows: {data['fixture_rows']}  "
                f"contours covered: {len(data['contour_coverage'])}"
            )
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
        elif mode == "scenario-catalog":
            print(
                f"scenarios: {data['scenario_count']}  "
                f"contours covered: {len(data['contour_coverage'])}"
            )
            print("payloads included: false")
            for scenario in data["scenarios"]:
                print(
                    f"- {scenario['scenario_id']}: {scenario['contour_id']} "
                    f"on {scenario['surface_id']}"
                )
        elif mode == "sanitize-fixture":
            counts = data["result_counts"]
            print(f"records: {data['record_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values included: false")
        elif mode == "fixture-template":
            print(f"template path: {data['path']}")
            print(f"records: {data['record_count']}")
            print("payloads included: false")
            print("private values filled: false")
        elif mode == "invariant-fixture-template":
            print(f"template path: {data['path']}")
            print(f"records: {data['record_count']}")
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
        elif mode == "invariant-baseline-fixture":
            counts = data["result_counts"]
            print(f"fixture path: {data['path']}")
            print(f"records: {data['record_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
        elif mode == "invariant-negative-control-fixture":
            counts = data["result_counts"]
            print(f"fixture path: {data['path']}")
            print(f"records: {data['record_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values filled: false")
            print("target observation: false")
        elif mode == "invariant-weak-control-fixture":
            counts = data["result_counts"]
            print(f"fixture path: {data['path']}")
            print(f"records: {data['record_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values filled: false")
            print("target observation: false")
        elif mode == "validate-invariant-fixture":
            counts = data["result_counts"]
            status = "ok" if data["ok"] else "failed"
            print(f"validation: {status}")
            print(f"records: {data['record_count']}  issues: {data['issue_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values included: false")
            for issue in data["issues"]:
                print(
                    f"- {issue['scenario_id']} {issue['field']}: "
                    f"{issue['code']}"
                )
        elif mode == "static-probe":
            print(f"scenarios: {data['scenario_count']}")
            print(f"status counts: {data['status_counts']}")
            print("raw contents included: false")
        elif mode == "artifact-probe":
            print(f"artifacts: {data['artifact_count']}")
            print(f"status counts: {data['status_counts']}")
            print(f"artifact root mode: {data['artifact_root_mode']}")
            print("raw contents included: false")
        elif mode == "artifact-invariant-probe":
            counts = data["result_counts"]
            print(f"scenarios: {data['scenario_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print(f"artifact root mode: {data['artifact_root_mode']}")
            print("raw contents included: false")
            print("private values included: false")
        elif mode == "artifact-e2e-observation":
            print(f"artifact checks: {data['artifact_check_count']}")
            print(f"artifact checks ok: {data['artifact_checks_ok']}")
            print(f"result class: {data['result_class']}")
            print(f"execution boundary ok: {data['execution_boundary_ok']}")
            print(f"evidence quality findings: {data['evidence_quality_findings']}")
            print(f"artifact root mode: {data['artifact_root_mode']}")
            print("raw contents included: false")
            print("private values included: false")
            print("raw card text included: false")
        elif mode == "boundary-lock":
            print(f"lock: {data['status']}  ok={data['lock_ok']}")
            print(f"scenarios: {data['scenario_count']}")
            print(f"status counts: {data['status_counts']}")
            print(f"marker counts: {data['aggregate_marker_counts']}")
            print("raw contents included: false")
            print("private values included: false")
        elif mode == "boundary-lock-review":
            print(f"review: {data['review_status']}  blocking={data['blocking']}")
            print(f"files reviewed: {data['file_count']}")
            print(f"status counts: {data['status_counts']}")
            print(f"review counts: {data['aggregate_review_counts']}")
            print("raw contents included: false")
            print("source lines included: false")
            print("private values included: false")
        elif mode == "experiment-plan":
            print(f"scenarios: {data['scenario_count']}  batches: {data['batch_count']}")
            print(f"execution status: {data['execution_status']}")
            print(f"max parallel scenarios: {data['max_parallel_scenarios']}")
            print("payloads included: false")
            print("raw vectors included: false")
            print("private calculations included: false")
            evidence_gate = data.get("evidence_gate")
            if isinstance(evidence_gate, dict):
                print(f"artifact checks ok: {evidence_gate['artifact_checks_ok']}")
                print(f"execution boundary ok: {evidence_gate['execution_boundary_ok']}")
                print(f"evidence result class: {evidence_gate['result_class']}")
                print(
                    "evidence quality findings: "
                    f"{evidence_gate['evidence_quality_findings']}"
                )
        elif mode == "experiment-template":
            print(f"template path: {data['path']}")
            print(f"records: {data['record_count']}  batches: {data['batch_count']}")
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
        elif mode == "experiment-control-fixture":
            counts = data["result_counts"]
            print(f"fixture path: {data['path']}")
            print(f"records: {data['record_count']}  batches: {data['batch_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
            print("target observation: false")
        elif mode == "experiment-baseline-fixture":
            counts = data["result_counts"]
            print(f"fixture path: {data['path']}")
            print(f"records: {data['record_count']}  batches: {data['batch_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
            print("target observation: true")
        elif mode == "experiment-negative-control-fixture":
            counts = data["result_counts"]
            print(f"fixture path: {data['path']}")
            print(f"records: {data['record_count']}  batches: {data['batch_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
            print("target observation: false")
        elif mode == "experiment-batch-manifest":
            print(f"manifest path: {data['path']}")
            print(f"scenarios: {data['scenario_count']}  batches: {data['batch_count']}")
            print(f"max parallel scenarios: {data['max_parallel_scenarios']}")
            print("payloads included: false")
            print("private values filled: false")
            print("execution required: false")
        elif mode == "validate-experiment-batch-manifest":
            status = "ok" if data["ok"] else "failed"
            print(f"validation: {status}")
            print(
                f"scenarios: {data['scenario_count']}  batches: {data['batch_count']}  "
                f"issues: {data['issue_count']}"
            )
            print(f"max parallel scenarios: {data['max_parallel_scenarios']}")
            print("payloads included: false")
            print("private values included: false")
            print("raw vectors included: false")
            print("private calculations included: false")
            for issue in data["issues"]:
                print(f"- {issue['scope']} {issue['field']}: {issue['code']}")
        elif mode == "experiment-intake":
            print(f"intake: {data['status']}")
            print(
                f"records: {data['record_count']}  scenarios: {data['scenario_count']}  "
                f"batches: {data['batch_count']}"
            )
            print(f"blockers: {data['blockers']}")
            print(f"real target observations: {data['real_target_observation_count']}")
            print(f"synthetic controls: {data['synthetic_control_count']}")
            print(f"batch manifest ok: {data['batch_manifest_ok']}")
            counts = data["result_counts"]
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print("payloads included: false")
            print("private values included: false")
            print("raw vectors included: false")
            print("private calculations included: false")
        elif mode == "experiment-readiness":
            status = "ready" if data["ready"] else "blocked"
            print(f"readiness: {status}")
            print(f"scenarios: {data['scenario_count']}  batches: {data['batch_count']}")
            print(f"blockers: {data['blockers']}")
            print(f"evidence quality findings: {data['evidence_quality_findings']}")
            print("payloads included: false")
            print("raw vectors included: false")
            print("private calculations included: false")
            for gate in data["gates"]:
                mark = "PASS" if gate["ok"] else "FAIL"
                print(f"  {mark} {gate['gate_id']}: {gate['required_state']}")
        elif mode == "validate-experiment":
            counts = data["result_counts"]
            status = "ok" if data["ok"] else "failed"
            print(f"validation: {status}")
            print(
                f"records: {data['record_count']}  scenarios: {data['scenario_count']}  "
                f"issues: {data['issue_count']}"
            )
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print(f"batch counts: {data['batch_counts']}")
            print("payloads included: false")
            print("private values included: false")
            for issue in data["issues"]:
                print(
                    f"- {issue['scenario_id']} {issue['field']}: "
                    f"{issue['code']}"
                )
        elif mode == "sanitize-experiment":
            counts = data["result_counts"]
            print(f"records: {data['record_count']}  batches: {data['batch_count']}")
            print(
                f"pass={counts['pass']}  finding={counts['finding']}  "
                f"inconclusive={counts['inconclusive']}  error={counts['error']}"
            )
            print(f"batch counts: {data['batch_counts']}")
            print("payloads included: false")
            print("private values included: false")
            print("raw vectors included: false")
            print("private calculations included: false")
        else:
            print(f"status: {data['status']}  ok={data['ok']}")
            print(f"reason: {data['reason']}")
            for gate in data["gates"]:
                mark = "PASS" if gate["ok"] else "FAIL"
                print(f"  {mark} {gate['gate_id']}: {gate['current_state']}")
        preflight = data.get("preflight")
        if isinstance(preflight, dict):
            status = "ok" if preflight.get("ok") else "failed"
            print(f"preflight: {status}  target_path={preflight.get('target_path')}")
            for check in preflight.get("checks", []):
                mark = "PASS" if check.get("ok") else "FAIL"
                print(f"  {mark} {check.get('check_id')}: {check.get('message')}")
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
        f"kind: {diff.kind}  finding_fixed: {diff.finding_fixed}  "
        f"new_finding: {diff.new_finding}  changed_status: {diff.changed_status}  "
        f"drift: {diff.inconclusive_error_drift}"
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
        f"finding_fixed: {diff.finding_fixed}  new_finding: {diff.new_finding}  "
        f"changed_status: {diff.changed_status}  "
        f"inconclusive_error_drift: {diff.inconclusive_error_drift}"
    )
    print("inconclusive/error are not pass or finding; they never count as a fix or "
          "new finding.")
    print("Comparison is based on recorded external artifacts; it does not call models.")
    return 0


def _evidence_quality(root: Path, out: Path | None, output_format: str = "text") -> int:
    from agentic_security_harness.evidence_quality import (
        build_evidence_quality_report,
        write_evidence_quality,
    )

    report = build_evidence_quality_report(root)
    if out is not None:
        paths = write_evidence_quality(report, out)
    else:
        paths = {}

    if output_format == "json":
        print(json.dumps(report.model_dump(mode="json"), indent=2))
        return 0

    print(f"Evidence quality for {root.as_posix()}")
    print(f"  runs: {report.total_runs}")
    print(f"  results: {report.total_results}")
    print(f"  decisive_rate: {report.decisive_rate:.3f}")
    print(f"  weak_evidence_rate: {report.weak_evidence_rate:.3f}")
    print(f"  raw_hash_coverage_rate: {report.raw_hash_coverage_rate:.3f}")
    print(f"  assertion_binding_rate: {report.assertion_binding_rate:.3f}")
    print(
        "  cross_run_disagreement: "
        f"{report.disagreement_groups}/{report.comparable_groups} "
        f"({report.cross_run_disagreement_rate:.3f})"
    )
    print(f"  local_swarm_runs: {report.local_swarm_runs_count}")
    print(f"  local_swarm_results: {report.local_swarm_results}")
    print(
        "  local_swarm_contract_coverage_rate: "
        f"{report.local_swarm_contract_coverage_rate:.3f}"
    )
    print(
        "  local_swarm_transcript_hash_coverage_rate: "
        f"{report.local_swarm_transcript_hash_coverage_rate:.3f}"
    )
    print(
        "  local_swarm_adapter_error_rate: "
        f"{report.local_swarm_adapter_error_rate:.3f}"
    )
    print(
        "  local_swarm_runtime_mode_coverage_rate: "
        f"{report.local_swarm_runtime_mode_coverage_rate:.3f}"
    )
    if paths:
        print(f"wrote evidence_quality.json to {paths['json'].as_posix()}")
        print(f"wrote evidence_quality.md to {paths['markdown'].as_posix()}")
    if report.warnings:
        print(f"warnings: {len(report.warnings)}")
    print("Derived analysis only: no model calls, no leaderboard, no safety proof.")
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


def _showcase(root: Path, out: Path) -> int:
    from agentic_security_harness.showcase import build_showcase, write_showcase

    manifests, cards = build_showcase(root)
    paths = write_showcase(root, out)
    print(f"wrote showcase index to {paths['index'].as_posix()}")
    print(f"wrote failure/weak-spot cards to {paths['failure_cards'].as_posix()}")
    print(f"runs discovered: {len(manifests)}  cards generated: {len(cards)}")
    print("JSON artifacts remain the source of truth; this is a reviewer aid.")
    return 0


def _print_local_profiles() -> int:
    from agentic_security_harness.local_profiles import LOCAL_PROFILES, local_profile_names

    print("Bounded local-model smoke profiles (prompt-only, no tools):")
    for name in local_profile_names():
        p = LOCAL_PROFILES[name]
        print(
            f"  {name}: preset={p.preset} model={p.model} scenario={p.scenario_id} "
            f"variants={p.max_variants} repeats={p.repeats} timeout={p.timeout_seconds}s "
            f"cap={p.max_requests}"
        )
    print("Run one with: ash local-suite --profile <name> --execute")
    return 0


def _local_suite(
    profile_name: str,
    out: Path | None,
    base_url_override: str | None,
    execute: bool,
    run_showcase: bool,
    list_profiles: bool,
) -> int:
    """Run a bounded, named local-model smoke profile. Dry-run unless ``execute``."""
    from agentic_security_harness.local_profiles import (
        default_output_dir,
        resolve_local_profile,
    )

    if list_profiles:
        return _print_local_profiles()
    try:
        profile = resolve_local_profile(profile_name)
        base_url, credential_env_var, err = apply_preset(
            profile.preset, base_url_override, ""
        )
    except KeyError as exc:
        print(f"Error: {exc}")
        return 1
    if err:
        print(f"Error: {err}")
        return 1

    out_dir = out or Path(default_output_dir(profile))
    print(
        f"profile: {profile.name}  model: {profile.model}  scenario: {profile.scenario_id}"
    )
    print(f"  preset {profile.preset} -> base_url {_redact_url(base_url)}")
    print(
        "Local runtime execution does not remove model-license / acceptable-use duties. "
        "Stop if the machine becomes unusable or adapter errors repeat after a timeout "
        "increase (see docs/local-model-profiles.md)."
    )

    rc = _run_external(
        base_url,
        profile.model,
        profile.scenario_id,
        out_dir,
        profile.repeats,
        0.0,
        profile.timeout_seconds,
        1,
        profile.raw_response_limit,
        credential_env_var,
        profile.max_variants,
        None,
        not execute,
        "openai-compatible",
        profile.max_requests,
        profile.preset,
    )
    if rc != 0:
        return rc
    if not execute:
        print("Dry-run only. Re-run with --execute to call the local model.")
        return 0

    # Real run completed: validate the artifacts and report the weak-model classification.
    from agentic_security_harness.validation import validate_path

    result = validate_path(out_dir)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out_dir.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        print("Use `ash validate --format json` for redacted machine-readable details.")
        return 1
    print(f"validated {out_dir.as_posix()} (artifact integrity only).")
    print(
        "Weak-model contradictions are classified as inconclusive/adapter_error, never "
        "pass or finding."
    )
    if run_showcase:
        showcase_out = out_dir.parent / f"{out_dir.name}-showcase"
        return _showcase(out_dir, showcase_out)
    print("Next: ash showcase --root " + out_dir.as_posix())
    return 0


def _local_swarm(
    scenarios: list[str],
    modes: list[str],
    list_swarm: bool,
    out: Path,
    preset: str,
    base_url_override: str | None,
    model: str,
    role_model_args: list[str],
    timeout: int,
    max_requests: int,
    execute: bool,
    write_dry_run: bool,
) -> int:
    from agentic_security_harness.local_swarm import (
        SWARM_MODES,
        SWARM_SCENARIOS,
        estimate_request_count,
        model_is_forbidden,
        normalize_role_models,
        run_local_swarm,
        write_local_swarm_artifacts,
    )

    if list_swarm:
        print("Local swarm scenarios:")
        for scenario in SWARM_SCENARIOS:
            print(f"  {scenario}")
        print("Local swarm modes:")
        for mode in SWARM_MODES:
            print(f"  {mode}")
        return 0

    selected_scenarios = list(SWARM_SCENARIOS) if not scenarios else scenarios
    selected_modes = list(SWARM_MODES) if not modes else modes
    request_count = estimate_request_count(selected_scenarios, selected_modes)  # type: ignore[arg-type]
    print(
        f"local-swarm scenarios={len(selected_scenarios)} modes={len(selected_modes)} "
        f"estimated_role_calls={request_count}"
    )
    print(
        "Deterministic contracts decide pass/block; optional model text is hashed "
        "evidence context only."
    )

    base_url = ""
    try:
        role_models = _parse_role_model_args(role_model_args)
        role_models = normalize_role_models(role_models)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    if execute:
        if model_is_forbidden(model):
            print("Error: calculator model is reserved for the trading project; refused.")
            return 1
        try:
            base_url, credential_env_var, err = apply_preset(preset, base_url_override, "")
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if credential_env_var:
            print("Error: local-swarm accepts only keyless local presets in this pass.")
            return 1
        print(f"Using preset '{preset}': base_url {_redact_url(base_url)}")
        if role_models:
            rendered = ", ".join(f"{role}={m}" for role, m in sorted(role_models.items()))
            print(f"Using role model roster: {rendered}")

    try:
        summary = run_local_swarm(
            scenarios=selected_scenarios,  # type: ignore[arg-type]
            modes=selected_modes,  # type: ignore[arg-type]
            execute_model_calls=execute,
            base_url=base_url,
            model=model if execute else "",
            role_models=role_models,
            timeout_seconds=timeout,
            max_requests=max_requests,
            created_at=_now_utc(),
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    metrics = summary.metrics
    print(
        "boundary failures: "
        f"monolith={metrics.monolith_boundary_failures} "
        f"naive={metrics.naive_swarm_boundary_failures} "
        f"bounded={metrics.bounded_swarm_boundary_failures}; "
        f"verifier_blocks={metrics.verifier_blocks}"
    )

    if not execute and not write_dry_run:
        print("Dry-run only. Add --write-dry-run for deterministic artifacts or --execute.")
        return 0

    paths = write_local_swarm_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _parse_role_model_args(items: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(
                f"invalid --role-model value '{item}', expected ROLE=MODEL"
            )
        role, model = item.split("=", 1)
        role = role.strip()
        model = model.strip()
        if not role or not model:
            raise ValueError(
                f"invalid --role-model value '{item}', expected ROLE=MODEL"
            )
        parsed[role] = model
    return parsed


def _local_swarm_matrix(
    list_matrix: bool,
    out: Path,
    write: bool,
    execute_model: bool,
    preset: str,
    base_url_override: str,
    model: str,
    timeout: float,
    max_requests: int,
    pressure_mode: str,
) -> int:
    from agentic_security_harness.local_swarm import model_is_forbidden
    from agentic_security_harness.local_swarm_matrix import (
        VARIATION_FAMILIES,
        build_local_swarm_attack_matrix,
        declared_matrix_cases,
        run_matrix_model_probe,
        write_local_swarm_matrix_artifacts,
        write_matrix_model_probe_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    if list_matrix:
        print("Local swarm matrix variation families:")
        for family in VARIATION_FAMILIES:
            print(f"  {family}")
        print("Local swarm matrix cases:")
        for case in declared_matrix_cases():
            print(f"  {case.case_id} -> {case.base_scenario} ({case.family})")
        return 0

    matrix = build_local_swarm_attack_matrix()
    metrics = matrix.metrics
    print(
        f"local-swarm-matrix cases={metrics.cases} "
        f"families={metrics.variation_families} "
        f"base_scenarios={metrics.base_scenarios}"
    )
    print(
        "boundary failures: "
        f"monolith={metrics.monolith_boundary_failures} "
        f"naive={metrics.naive_swarm_boundary_failures} "
        f"bounded={metrics.bounded_swarm_boundary_failures}; "
        f"bounded_blocks={metrics.bounded_blocks}"
    )
    if execute_model:
        print(
            "Deterministic matrix plus explicit local model evidence-quality probes; "
            "model text never decides pass/block."
        )
    else:
        print(
            "Deterministic matrix only: no model calls, no network, "
            "no production-safety claim."
        )
    if execute_model:
        if model_is_forbidden(model):
            print("Error: calculator model is reserved for the trading project; refused.")
            return 1
        try:
            base_url, credential_env_var, err = apply_preset(preset, base_url_override, "")
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if credential_env_var:
            print("Error: matrix model probes accept only keyless local presets.")
            return 1
        if not model:
            print("Error: --model is required with --execute-model")
            return 1
        print(f"Using preset '{preset}': base_url {_redact_url(base_url)}")
        try:
            probe_run = run_matrix_model_probe(
                base_url=base_url,
                model=model,
                timeout_seconds=int(timeout),
                max_requests=max_requests,
                pressure_mode=pressure_mode,  # type: ignore[arg-type]
                created_at=datetime.now(UTC),
            )
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        probe_paths = write_matrix_model_probe_artifacts(out, probe_run)
        for path in probe_paths:
            print(f"wrote {path.as_posix()}")
        print(
            "model-probe evidence quality: "
            f"responses={probe_run.metrics.responses} "
            f"adapter_errors={probe_run.metrics.adapter_errors} "
            f"weakness_observations={probe_run.metrics.weakness_observations}"
        )

    if not write:
        if execute_model:
            print("Deterministic matrix artifacts not written. Add --write to write them too.")
        else:
            print("Dry-run only. Add --write to write artifacts.")
        return 0

    paths = write_local_swarm_matrix_artifacts(out, matrix)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _evidence_campaign(out: Path, write: bool) -> int:
    from agentic_security_harness.evidence_campaign import (
        build_evidence_campaign,
        write_evidence_campaign_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_evidence_campaign(created_at=_now_utc())
    metrics = summary.metrics
    bounded = metrics.by_mode["bounded_swarm"]
    naive = metrics.by_mode["naive_swarm"]
    print(
        f"evidence-campaign cases={metrics.cases} observations={metrics.observations} "
        f"families={metrics.claim_families}"
    )
    print(
        "bounded: "
        f"TP={bounded.true_positive} FP={bounded.false_positive} "
        f"TN={bounded.true_negative} FN={bounded.false_negative} "
        f"inconclusive={bounded.inconclusive}"
    )
    print(
        "effect: "
        f"naive_failure={naive.failure_rate:.2%} "
        f"bounded_failure={bounded.failure_rate:.2%} "
        f"control_effect={metrics.control_effect_naive_to_bounded:.2%} "
        f"usability_cost={metrics.usability_cost_naive_to_bounded:.2%}"
    )
    ablation = summary.ablation_metrics
    print(
        "ablation: "
        f"unsafe_regressions={ablation.unsafe_regressions}/{ablation.unsafe_cases} "
        f"benign_regressions={ablation.benign_regressions}/{ablation.safe_cases}"
    )
    print(
        "Raw model outputs are not required here; write artifacts under .internal/ "
        "unless intentionally curating a public example."
    )
    if not write:
        print("Dry-run only. Add --write to write private-ready artifacts.")
        return 0

    paths = write_evidence_campaign_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _secret_leak_campaign(
    out: Path,
    write: bool,
    execute_model: bool,
    execute_variations: bool,
    variation_models: list[str] | None,
    variation_summary_out: Path | None,
    preset: str,
    base_url_override: str | None,
    model: str,
    timeout: int,
    max_requests: int,
    pressure_modes: list[str] | None,
) -> int:
    from agentic_security_harness.local_swarm import model_is_forbidden

    # These imports create synthetic canary campaigns, but this CLI path never logs
    # raw prompts, raw responses, or canary values; raw artifacts are written only
    # under .internal and public outputs are sanitized/validated before use.
    # codeql[py/clear-text-logging-sensitive-data]
    # lgtm[py/clear-text-logging-sensitive-data]
    from agentic_security_harness.secret_leak_campaign import (
        PRESSURE_MODES,
        build_secret_leak_campaign,
        build_secret_leak_variation_summary,
        run_secret_leak_variation_probe,
        run_secret_model_probe,
        write_secret_leak_campaign_artifacts,
        write_secret_leak_variation_artifacts,
        write_secret_leak_variation_private_artifacts,
        write_secret_model_probe_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_secret_leak_campaign(created_at=_now_utc())
    print("secret-leak campaign prepared.")
    print(
        "Public campaign artifacts are sanitized. Raw model prompts/responses, if "
        "collected, must stay under .internal/."
    )

    if write:
        paths = write_secret_leak_campaign_artifacts(out, summary)
        for path in paths:
            print(f"wrote {path.as_posix()}")
        result = validate_path(out)
        if not result.ok:
            print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
            print(f"errors: {len(result.errors)}")
            return 1
        print(f"validated {out.as_posix()} (artifact integrity only).")

    if execute_model:
        if ".internal" not in out.parts:
            print("Error: --execute-model requires --out under .internal/.")
            return 1
        if model_is_forbidden(model):
            print("Error: calculator model is reserved for the trading project; refused.")
            return 1
        try:
            base_url, credential_env_var, err = apply_preset(preset, base_url_override, "")
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if credential_env_var:
            print("Error: secret probes accept only keyless local presets.")
            return 1
        selected_pressures = pressure_modes or list(PRESSURE_MODES)
        print(f"Using preset '{preset}': base_url {_redact_url(base_url)}")
        try:
            run = run_secret_model_probe(
                base_url=base_url,
                model=model,
                pressure_modes=selected_pressures,  # type: ignore[arg-type]
                timeout_seconds=timeout,
                max_requests=max_requests,
                created_at=_now_utc(),
            )
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        private_dir = out / "private_model_probe"
        write_secret_model_probe_artifacts(private_dir, run)
        print("wrote private model-probe artifacts.")

    if execute_variations:
        if ".internal" not in out.parts:
            print("Error: --execute-variations requires --out under .internal/.")
            return 1
        selected_models = variation_models or [model]
        forbidden = [item for item in selected_models if model_is_forbidden(item)]
        if forbidden:
            print(
                "Error: calculator model is reserved for the trading project; refused: "
                + ", ".join(forbidden)
            )
            return 1
        try:
            base_url, credential_env_var, err = apply_preset(preset, base_url_override, "")
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if credential_env_var:
            print("Error: secret probes accept only keyless local presets.")
            return 1
        selected_pressures = pressure_modes or list(PRESSURE_MODES)
        print(
            f"Using preset '{preset}': base_url {_redact_url(base_url)}; "
            f"variation_models={', '.join(selected_models)}"
        )
        try:
            private_run = run_secret_leak_variation_probe(
                base_url=base_url,
                models=selected_models,
                pressure_modes=selected_pressures,  # type: ignore[arg-type]
                timeout_seconds=timeout,
                max_requests=max_requests,
                created_at=_now_utc(),
            )
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        private_dir = out / "private_variation_probe"
        write_secret_leak_variation_private_artifacts(
            private_dir,
            private_run,
        )
        variation_summary = build_secret_leak_variation_summary(
            private_run,
            created_at=_now_utc(),
        )
        print("wrote private variation-probe artifacts.")
        if variation_summary_out is not None:
            write_secret_leak_variation_artifacts(
                variation_summary_out,
                variation_summary,
            )
            print("wrote sanitized variation artifacts.")
            result = validate_path(variation_summary_out)
            if not result.ok:
                print(
                    "Validation FAILED for "
                    f"{redact_artifact_text(variation_summary_out.as_posix())}:"
                )
                print(f"errors: {len(result.errors)}")
                return 1
            print(
                f"validated {variation_summary_out.as_posix()} "
                "(artifact integrity only)."
            )

    if not write and not execute_model and not execute_variations:
        print("Dry-run only. Add --write and/or --execute-model.")
    return 0


def _semantic_drift_campaign(
    out: Path,
    write: bool,
    execute: bool,
    models: list[str] | None,
    summary_out: Path | None,
    preset: str,
    base_url_override: str | None,
    timeout: int,
    max_requests: int,
    pressure_modes: list[str] | None,
) -> int:
    from agentic_security_harness.local_swarm import model_is_forbidden
    from agentic_security_harness.semantic_drift_campaign import (
        PRESSURE_MODES,
        build_semantic_drift_campaign,
        run_semantic_drift_probe,
        write_semantic_drift_artifacts,
        write_semantic_drift_private_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_semantic_drift_campaign(created_at=_now_utc())
    print("semantic-drift campaign prepared.")
    print(
        "Public artifacts are sanitized. Raw prompts/responses and synthetic markers, "
        "if collected, must stay under .internal/."
    )

    if write:
        paths = write_semantic_drift_artifacts(out, summary)
        for path in paths:
            print(f"wrote {path.as_posix()}")
        result = validate_path(out)
        if not result.ok:
            print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
            print(f"errors: {len(result.errors)}")
            return 1
        print(f"validated {out.as_posix()} (artifact integrity only).")

    if execute:
        if ".internal" not in out.parts:
            print("Error: --execute requires --out under .internal/.")
            return 1
        selected_models = models or ["prometheus-qwen15b-lowctx:latest"]
        forbidden = [item for item in selected_models if model_is_forbidden(item)]
        if forbidden:
            print(
                "Error: calculator model is reserved for the trading project; refused: "
                + ", ".join(forbidden)
            )
            return 1
        try:
            base_url, credential_env_var, err = apply_preset(preset, base_url_override, "")
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if credential_env_var:
            print("Error: semantic drift probes accept only keyless local presets.")
            return 1
        selected_pressures = pressure_modes or list(PRESSURE_MODES)
        print(
            f"Using preset '{preset}': base_url {_redact_url(base_url)}; "
            f"models={', '.join(selected_models)}"
        )
        try:
            private_run = run_semantic_drift_probe(
                base_url=base_url,
                models=selected_models,
                pressure_modes=selected_pressures,  # type: ignore[arg-type]
                timeout_seconds=timeout,
                max_requests=max_requests,
                created_at=_now_utc(),
            )
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        private_dir = out / "private_semantic_drift_probe"
        write_semantic_drift_private_artifacts(private_dir, private_run)
        print("wrote private semantic-drift artifacts.")
        live_summary = build_semantic_drift_campaign(
            private_run,
            created_at=_now_utc(),
        )
        if summary_out is not None:
            write_semantic_drift_artifacts(summary_out, live_summary)
            print("wrote sanitized semantic-drift artifacts.")
            result = validate_path(summary_out)
            if not result.ok:
                print(
                    "Validation FAILED for "
                    f"{redact_artifact_text(summary_out.as_posix())}:"
                )
                print(f"errors: {len(result.errors)}")
                return 1
            print(f"validated {summary_out.as_posix()} (artifact integrity only).")

    if not write and not execute:
        print("Dry-run only. Add --write and/or --execute.")
    return 0


def _semantic_propagation_campaign(
    out: Path,
    write: bool,
    execute: bool,
    worker_models: list[str] | None,
    chief_models: list[str] | None,
    summary_out: Path | None,
    preset: str,
    base_url_override: str | None,
    timeout: int,
    max_chains: int,
    pressure_modes: list[str] | None,
) -> int:
    from agentic_security_harness.local_swarm import model_is_forbidden
    from agentic_security_harness.semantic_propagation_campaign import (
        PRESSURE_MODES,
        build_semantic_propagation_campaign,
        run_semantic_propagation_probe,
        write_semantic_propagation_artifacts,
        write_semantic_propagation_private_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_semantic_propagation_campaign(created_at=_now_utc())
    print("semantic-propagation campaign prepared.")
    print(
        "Public artifacts are sanitized. Raw worker/chief prompts, responses, "
        "and synthetic markers, if collected, must stay under .internal/."
    )

    if write:
        paths = write_semantic_propagation_artifacts(out, summary)
        for path in paths:
            print(f"wrote {path.as_posix()}")
        result = validate_path(out)
        if not result.ok:
            print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
            print(f"errors: {len(result.errors)}")
            return 1
        print(f"validated {out.as_posix()} (artifact integrity only).")

    if execute:
        if ".internal" not in out.parts:
            print("Error: --execute requires --out under .internal/.")
            return 1
        selected_workers = worker_models or ["qwen2.5:0.5b"]
        selected_chiefs = chief_models or ["prometheus-qwen15b-lowctx:latest"]
        forbidden = [
            item for item in [*selected_workers, *selected_chiefs] if model_is_forbidden(item)
        ]
        if forbidden:
            print(
                "Error: calculator model is reserved for the trading project; refused: "
                + ", ".join(forbidden)
            )
            return 1
        try:
            base_url, credential_env_var, err = apply_preset(preset, base_url_override, "")
        except KeyError as exc:
            print(f"Error: {exc}")
            return 1
        if err:
            print(f"Error: {err}")
            return 1
        if credential_env_var:
            print("Error: semantic propagation probes accept only keyless local presets.")
            return 1
        selected_pressures = pressure_modes or list(PRESSURE_MODES)
        print(
            f"Using preset '{preset}': base_url {_redact_url(base_url)}; "
            f"workers={', '.join(selected_workers)}; chiefs={', '.join(selected_chiefs)}"
        )
        try:
            private_run = run_semantic_propagation_probe(
                base_url=base_url,
                worker_models=selected_workers,
                chief_models=selected_chiefs,
                pressure_modes=selected_pressures,  # type: ignore[arg-type]
                timeout_seconds=timeout,
                max_chains=max_chains,
                created_at=_now_utc(),
            )
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        private_dir = out / "private_semantic_propagation_probe"
        write_semantic_propagation_private_artifacts(private_dir, private_run)
        print("wrote private semantic-propagation artifacts.")
        live_summary = build_semantic_propagation_campaign(
            private_run,
            created_at=_now_utc(),
        )
        if summary_out is not None:
            write_semantic_propagation_artifacts(summary_out, live_summary)
            print("wrote sanitized semantic-propagation artifacts.")
            result = validate_path(summary_out)
            if not result.ok:
                print(
                    "Validation FAILED for "
                    f"{redact_artifact_text(summary_out.as_posix())}:"
                )
                print(f"errors: {len(result.errors)}")
                return 1
            print(f"validated {summary_out.as_posix()} (artifact integrity only).")

    if not write and not execute:
        print("Dry-run only. Add --write and/or --execute.")
    return 0


def _swarm_defense_contour(out: Path, write: bool) -> int:
    from agentic_security_harness.swarm_defense_contour import (
        build_swarm_defense_contour,
        write_swarm_defense_contour_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_swarm_defense_contour(created_at=_now_utc())
    print("swarm-defense-contour prepared.")
    print(
        "Public artifacts are sanitized. Raw local-model transcripts and synthetic "
        "canaries, if collected by deeper probes, must stay under .internal/."
    )
    print(
        f"scenarios={summary.metrics.scenarios} topologies={summary.metrics.topologies} "
        f"bounded_acceptances={summary.metrics.bounded_acceptances} "
        f"naive_acceptances={summary.metrics.naive_acceptances}"
    )
    if write:
        paths = write_swarm_defense_contour_artifacts(out, summary)
        for path in paths:
            print(f"wrote {path.as_posix()}")
        result = validate_path(out)
        if not result.ok:
            print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
            print(f"errors: {len(result.errors)}")
            return 1
        print(f"validated {out.as_posix()} (artifact integrity only).")
    else:
        print("Dry-run only. Add --write.")
    return 0


def _swarm_defense_live_campaign(
    *,
    out: Path,
    summary_out: Path,
    base_url: str,
    worker_models: list[str] | None,
    chief_models: list[str] | None,
    pressure_modes: list[str] | None,
    max_topologies: int,
    max_requests: int,
    timeout: int,
    execute: bool,
    session_turns: int,
) -> int:
    from typing import cast

    from agentic_security_harness.swarm_defense_live_campaign import (
        PRESSURE_MODES,
        LivePressureMode,
        build_live_defense_summary,
        estimate_live_request_count,
        run_live_defense_campaign,
        write_live_defense_artifacts,
        write_live_defense_private_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    workers = worker_models or ["qwen2.5:0.5b"]
    chiefs = chief_models or ["llama3.2:1b"]
    selected_pressures: list[LivePressureMode] = (
        cast(list[LivePressureMode], pressure_modes)
        if pressure_modes is not None
        else list(PRESSURE_MODES)
    )
    topology_count = min(max_topologies, 15)
    estimated = estimate_live_request_count(
        topology_count=topology_count,
        worker_models=workers,
        chief_models=chiefs,
        pressure_modes=selected_pressures,
        session_turns=session_turns,
    )
    print("swarm-defense-live-campaign prepared.")
    print("Raw prompts/responses/canaries must stay under .internal/.")
    print(
        f"topologies={topology_count} workers={len(workers)} chiefs={len(chiefs)} "
        f"pressure_modes={len(selected_pressures)} session_turns={session_turns} "
        f"estimated_requests<={estimated}"
    )
    if not execute:
        print("Dry-run only. Add --execute to call local models.")
        return 0
    if ".internal" not in out.parts:
        print("Error: --out for live campaign must be under .internal/")
        return 1

    run = run_live_defense_campaign(
        base_url=base_url,
        worker_models=workers,
        chief_models=chiefs,
        pressure_modes=selected_pressures,
        max_topologies=max_topologies,
        timeout_seconds=timeout,
        max_requests=max_requests,
        session_turns=session_turns,
        created_at=_now_utc(),
    )
    private_paths = write_live_defense_private_artifacts(out, run)
    summary = build_live_defense_summary(run, created_at=_now_utc())
    public_paths = write_live_defense_artifacts(summary_out, summary)
    print(f"wrote {len(private_paths)} private artifact(s) to {out.as_posix()}")
    for path in public_paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(summary_out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(summary_out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {summary_out.as_posix()} (artifact integrity only).")
    print(
        f"observations={summary.metrics.observations} "
        f"worker_drift={summary.metrics.worker_drift_detections} "
        f"chief_accept={summary.metrics.chief_acceptances} "
        f"canary_leaks={summary.metrics.canary_leaks} "
        f"blocks={summary.metrics.verifier_blocks}"
    )
    return 0


def _marketing_web_injection_campaign(
    *,
    out: Path,
    summary_out: Path,
    write: bool,
) -> int:
    from agentic_security_harness.marketing_web_injection_campaign import (
        build_marketing_web_private_run,
        build_marketing_web_summary,
        write_marketing_web_artifacts,
        write_marketing_web_private_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    private_run = build_marketing_web_private_run(created_at=_now_utc())
    summary = build_marketing_web_summary(private_run, created_at=_now_utc())
    print("marketing-web-injection-campaign prepared.")
    print("Network/model calls: none. Corpus is controlled synthetic web content.")
    print("Raw pages/prompts/responses/synthetic strategy values must stay under .internal/.")
    print(
        f"scenarios={summary.metrics.scenarios} "
        f"observations={summary.metrics.observations} "
        f"naive_leaks={summary.metrics.naive_leaks} "
        f"bounded_leaks={summary.metrics.bounded_leaks} "
        f"ablation_leaks={summary.metrics.ablation_leaks} "
        f"benign_leaks={summary.metrics.benign_leaks}"
    )
    if not write:
        print("Dry-run only. Add --write to write private and sanitized artifacts.")
        return 0
    try:
        private_paths = write_marketing_web_private_artifacts(out, private_run)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    public_paths = write_marketing_web_artifacts(summary_out, summary)
    print(f"wrote {len(private_paths)} private artifact(s) to {out.as_posix()}")
    for path in public_paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(summary_out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(summary_out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {summary_out.as_posix()} (artifact integrity only).")
    return 0


def _swarm_resilience_campaign(
    *,
    out: Path,
    summary_out: Path,
    write: bool,
) -> int:
    from agentic_security_harness.swarm_resilience_campaign import (
        build_resilience_private_run,
        build_resilience_summary,
        write_resilience_artifacts,
        write_resilience_private_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    private_run = build_resilience_private_run(created_at=_now_utc())
    summary = build_resilience_summary(private_run, created_at=_now_utc())
    print("swarm-resilience-campaign prepared.")
    print("Network/model calls: none. This is a deterministic stability model.")
    print("Synthetic payload notes and calculation traces must stay under .internal/.")
    print(
        f"scenarios={summary.metrics.scenarios} "
        f"observations={summary.metrics.observations} "
        f"naive_unsafe={summary.metrics.naive_unsafe_acceptances} "
        f"bounded_unsafe={summary.metrics.bounded_unsafe_acceptances} "
        f"ablation_unsafe={summary.metrics.ablation_unsafe_acceptances} "
        f"benign_false_blocks={summary.metrics.benign_false_blocks}"
    )
    if not write:
        print("Dry-run only. Add --write to write private and sanitized artifacts.")
        return 0
    try:
        private_paths = write_resilience_private_artifacts(out, private_run)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    public_paths = write_resilience_artifacts(summary_out, summary)
    print(f"wrote {len(private_paths)} private artifact(s) to {out.as_posix()}")
    for path in public_paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(summary_out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(summary_out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {summary_out.as_posix()} (artifact integrity only).")
    return 0


def _context_consent_campaign(*, out: Path, write: bool) -> int:
    from agentic_security_harness.context_consent_campaign import (
        build_context_consent_campaign,
        write_context_consent_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_context_consent_campaign(created_at=_now_utc())
    print("context-consent-campaign prepared.")
    print("Network/model calls: none. This is a deterministic consent-boundary model.")
    print(
        f"cases={summary.metrics.cases} "
        f"rows={summary.metrics.deterministic_rows} "
        f"naive_acceptances={summary.metrics.naive_acceptances} "
        f"bounded_acceptances={summary.metrics.bounded_acceptances} "
        f"ablation_acceptances={summary.metrics.ablation_acceptances} "
        f"benign_false_blocks={summary.metrics.benign_false_blocks}"
    )
    if not write:
        print("Dry-run only. Add --write to write sanitized artifacts.")
        return 0
    paths = write_context_consent_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _tool_authority_campaign(*, out: Path, write: bool) -> int:
    from agentic_security_harness.tool_authority_campaign import (
        build_tool_authority_campaign,
        write_tool_authority_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_tool_authority_campaign(created_at=_now_utc())
    print("tool-authority-campaign prepared.")
    print("Network/model calls: none. This is a deterministic tool-output authority model.")
    print(
        f"cases={summary.metrics.cases} "
        f"rows={summary.metrics.deterministic_rows} "
        f"naive_acceptances={summary.metrics.naive_acceptances} "
        f"bounded_acceptances={summary.metrics.bounded_acceptances} "
        f"ablation_acceptances={summary.metrics.ablation_acceptances} "
        f"benign_false_blocks={summary.metrics.benign_false_blocks}"
    )
    if not write:
        print("Dry-run only. Add --write to write sanitized artifacts.")
        return 0
    paths = write_tool_authority_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _rag_context_campaign(*, out: Path, write: bool) -> int:
    from agentic_security_harness.rag_context_campaign import (
        build_rag_context_campaign,
        write_rag_context_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_rag_context_campaign(created_at=_now_utc())
    print("rag-context-campaign prepared.")
    print("Network/model calls: none. This is a deterministic RAG authority model.")
    print(
        f"cases={summary.metrics.cases} "
        f"rows={summary.metrics.deterministic_rows} "
        f"naive_acceptances={summary.metrics.naive_acceptances} "
        f"bounded_acceptances={summary.metrics.bounded_acceptances} "
        f"ablation_acceptances={summary.metrics.ablation_acceptances} "
        f"benign_false_blocks={summary.metrics.benign_false_blocks}"
    )
    if not write:
        print("Dry-run only. Add --write to write sanitized artifacts.")
        return 0
    paths = write_rag_context_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _planner_task_campaign(*, out: Path, write: bool) -> int:
    from agentic_security_harness.planner_task_campaign import (
        build_planner_task_campaign,
        write_planner_task_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_planner_task_campaign(created_at=_now_utc())
    print("planner-task-campaign prepared.")
    print("Network/model calls: none. This is a deterministic planner authority model.")
    print(
        f"cases={summary.metrics.cases} "
        f"rows={summary.metrics.deterministic_rows} "
        f"naive_acceptances={summary.metrics.naive_acceptances} "
        f"bounded_acceptances={summary.metrics.bounded_acceptances} "
        f"ablation_acceptances={summary.metrics.ablation_acceptances} "
        f"benign_false_blocks={summary.metrics.benign_false_blocks}"
    )
    if not write:
        print("Dry-run only. Add --write to write sanitized artifacts.")
        return 0
    paths = write_planner_task_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _memory_rehydration_campaign(*, out: Path, write: bool) -> int:
    from agentic_security_harness.memory_rehydration_campaign import (
        build_memory_rehydration_campaign,
        write_memory_rehydration_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    summary = build_memory_rehydration_campaign(created_at=_now_utc())
    print("memory-rehydration-campaign prepared.")
    print("Network/model calls: none. This is a deterministic memory authority model.")
    print(
        f"cases={summary.metrics.cases} "
        f"rows={summary.metrics.deterministic_rows} "
        f"naive_acceptances={summary.metrics.naive_acceptances} "
        f"bounded_acceptances={summary.metrics.bounded_acceptances} "
        f"ablation_acceptances={summary.metrics.ablation_acceptances} "
        f"benign_false_blocks={summary.metrics.benign_false_blocks}"
    )
    if not write:
        print("Dry-run only. Add --write to write sanitized artifacts.")
        return 0
    paths = write_memory_rehydration_artifacts(out, summary)
    for path in paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {out.as_posix()} (artifact integrity only).")
    return 0


def _marketing_web_live_campaign(
    *,
    out: Path,
    summary_out: Path,
    base_url: str,
    worker_models: list[str] | None,
    chief_models: list[str] | None,
    max_scenarios: int,
    session_turns: int,
    max_requests: int,
    timeout: int,
    execute: bool,
) -> int:
    from agentic_security_harness.marketing_web_live_campaign import (
        build_live_marketing_web_summary,
        estimate_live_marketing_request_count,
        run_live_marketing_web_campaign,
        write_live_marketing_web_artifacts,
        write_live_marketing_web_private_artifacts,
    )
    from agentic_security_harness.validation import validate_path

    workers = worker_models or ["qwen2.5:0.5b"]
    chiefs = chief_models or ["llama3.2:1b"]
    estimated = estimate_live_marketing_request_count(
        scenario_count=max_scenarios,
        worker_models=workers,
        chief_models=chiefs,
        session_turns=session_turns,
    )
    print("marketing-web-live-campaign prepared.")
    print("Scope: owned local HTTP pages + local OpenAI-compatible models only.")
    print("Raw pages/prompts/responses/synthetic strategy values must stay under .internal/.")
    print(
        f"worker_models={workers} chief_models={chiefs} "
        f"max_scenarios={max_scenarios} session_turns={session_turns} "
        f"estimated_requests={estimated} max_requests={max_requests}"
    )
    if not execute:
        print("Dry-run only. Add --execute to call local models and write artifacts.")
        return 0
    if ".internal" not in out.parts:
        print("Error: --out for live campaign must be under .internal/")
        return 1
    try:
        private_run = run_live_marketing_web_campaign(
            base_url=base_url,
            worker_models=workers,
            chief_models=chiefs,
            max_scenarios=max_scenarios,
            session_turns=session_turns,
            timeout_seconds=timeout,
            max_requests=max_requests,
            created_at=_now_utc(),
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    summary = build_live_marketing_web_summary(private_run, created_at=_now_utc())
    private_paths = write_live_marketing_web_private_artifacts(out, private_run)
    public_paths = write_live_marketing_web_artifacts(summary_out, summary)
    print(f"wrote {len(private_paths)} private artifact(s) to {out.as_posix()}")
    for path in public_paths:
        print(f"wrote {path.as_posix()}")
    result = validate_path(summary_out)
    if not result.ok:
        print(f"Validation FAILED for {redact_artifact_text(summary_out.as_posix())}:")
        print(f"errors: {len(result.errors)}")
        return 1
    print(f"validated {summary_out.as_posix()} (artifact integrity only).")
    print(
        f"observations={summary.metrics.observations} "
        f"naive_final_leaks={summary.metrics.naive_final_leaks} "
        f"bounded_final_leaks={summary.metrics.bounded_final_leaks} "
        f"ablation_final_leaks={summary.metrics.ablation_final_leaks} "
        f"benign_final_leaks={summary.metrics.benign_final_leaks} "
        f"blocks={summary.metrics.verifier_blocks}"
    )
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
    if args.command == "trading-stand":
        return _trading_stand(
            args.mode,
            args.target_path,
            args.format,
            args.fixture_path,
            args.manifest_path,
            args.artifact_root,
        )
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
    if args.command == "evidence-quality":
        return _evidence_quality(args.root, args.out, args.format)
    if args.command == "stats":
        return _stats(args.root, args.out, args.format)
    if args.command == "retention":
        return _retention(args.root, args.keep_last, args.kind, args.apply, args.format)
    if args.command == "report":
        return _report(args.root, args.out)
    if args.command == "showcase":
        return _showcase(args.root, args.out)
    if args.command == "local-suite":
        return _local_suite(
            args.profile,
            args.out,
            args.base_url,
            args.execute,
            args.run_showcase,
            args.list_profiles,
        )
    if args.command == "local-swarm":
        return _local_swarm(
            args.scenario,
            args.mode,
            args.list_swarm,
            args.out,
            args.preset,
            args.base_url,
            args.model,
            args.role_model,
            args.timeout,
            args.max_requests,
            args.execute,
            args.write_dry_run,
        )
    if args.command == "local-swarm-matrix":
        return _local_swarm_matrix(
            args.list_swarm_matrix,
            args.out,
            args.write,
            args.execute_model,
            args.preset,
            args.base_url,
            args.model,
            args.timeout,
            args.max_requests,
            args.pressure_mode,
        )
    if args.command == "evidence-campaign":
        return _evidence_campaign(args.out, args.write)
    if args.command == "secret-leak-campaign":
        return _secret_leak_campaign(
            args.out,
            args.write,
            args.execute_model,
            args.execute_variations,
            args.variation_model,
            args.variation_summary_out,
            args.preset,
            args.base_url,
            args.model,
            args.timeout,
            args.max_requests,
            args.pressure_mode,
        )
    if args.command == "semantic-drift-campaign":
        return _semantic_drift_campaign(
            args.out,
            args.write,
            args.execute,
            args.model,
            args.summary_out,
            args.preset,
            args.base_url,
            args.timeout,
            args.max_requests,
            args.pressure_mode,
        )
    if args.command == "semantic-propagation-campaign":
        return _semantic_propagation_campaign(
            args.out,
            args.write,
            args.execute,
            args.worker_model,
            args.chief_model,
            args.summary_out,
            args.preset,
            args.base_url,
            args.timeout,
            args.max_chains,
            args.pressure_mode,
        )
    if args.command == "swarm-defense-contour":
        return _swarm_defense_contour(args.out, args.write)
    if args.command == "swarm-defense-live-campaign":
        return _swarm_defense_live_campaign(
            out=args.out,
            summary_out=args.summary_out,
            base_url=args.base_url,
            worker_models=args.worker_model,
            chief_models=args.chief_model,
            pressure_modes=args.pressure_mode,
            max_topologies=args.max_topologies,
            max_requests=args.max_requests,
            timeout=args.timeout,
            execute=args.execute,
            session_turns=args.session_turns,
        )
    if args.command == "marketing-web-injection-campaign":
        return _marketing_web_injection_campaign(
            out=args.out,
            summary_out=args.summary_out,
            write=args.write,
        )
    if args.command == "swarm-resilience-campaign":
        return _swarm_resilience_campaign(
            out=args.out,
            summary_out=args.summary_out,
            write=args.write,
        )
    if args.command == "context-consent-campaign":
        return _context_consent_campaign(
            out=args.out,
            write=args.write,
        )
    if args.command == "tool-authority-campaign":
        return _tool_authority_campaign(
            out=args.out,
            write=args.write,
        )
    if args.command == "rag-context-campaign":
        return _rag_context_campaign(
            out=args.out,
            write=args.write,
        )
    if args.command == "planner-task-campaign":
        return _planner_task_campaign(
            out=args.out,
            write=args.write,
        )
    if args.command == "memory-rehydration-campaign":
        return _memory_rehydration_campaign(
            out=args.out,
            write=args.write,
        )
    if args.command == "marketing-web-live-campaign":
        return _marketing_web_live_campaign(
            out=args.out,
            summary_out=args.summary_out,
            base_url=args.base_url,
            worker_models=args.worker_model,
            chief_models=args.chief_model,
            max_scenarios=args.max_scenarios,
            session_turns=args.session_turns,
            max_requests=args.max_requests,
            timeout=args.timeout,
            execute=args.execute,
        )
    if args.command == "doctor":
        return _doctor(
            args.json, args.live_local, args.base_url, args.credential_env_var,
            args.reports_root,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
