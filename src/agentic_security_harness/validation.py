"""Validation layer for committed benchmark artifacts and corpus consistency.

Deterministic, stdlib + Pydantic only - no network, no new dependencies. Validates report
directories (traces.json / scorecard.json / summary.md / executive.md) and comparison
directories (baseline/ + protected/ + comparison.md) against the corpus manifest, and scans for
forbidden secret-shaped markers.

Passing validation means the artifacts conform to the corpus manifest (schema v0.1) and
contain no forbidden marker patterns - NOT that any system is secure.
"""

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.models import ExploitTrace, TargetDescriptor
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import (
    _SEVERITY_RANK,
    build_comparison_md,
    build_executive_md,
    build_summary_md,
)
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard

if TYPE_CHECKING:
    from agentic_security_harness.run_config import ExternalResult, ExternalSummary

_SCHEMA_VERSION = "0.1"
_PROTECTED_TYPES = {"protected_demo_agent"}

# Conservative, format-anchored markers. The left look-behind keeps "risk-reduction" and
# similar prose from matching "sk-"; the length tails require key-shaped tokens.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sk-", re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}")),
    ("AKIA", re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}")),
    ("BEGIN PRIVATE KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY")),
]


class ValidationResult(BaseModel):
    """Structured outcome of validating one or more benchmark artifacts."""

    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    report_dirs: list[str] = Field(default_factory=list)
    comparison_dirs: list[str] = Field(default_factory=list)
    external_dirs: list[str] = Field(default_factory=list)

    def _err(self, msg: str) -> None:
        self.errors.append(msg)
        self.ok = False

    def _warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _rel(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
    return rel if rel and rel != "." else path.name


def _is_protected(target: TargetDescriptor) -> bool:
    return target.type in _PROTECTED_TYPES


def _is_comparison_dir(path: Path) -> bool:
    return (path / "comparison.md").exists() or (
        (path / "baseline").is_dir() and (path / "protected").is_dir()
    )


def _is_external_dir(path: Path) -> bool:
    return (path / "run_config.json").exists() or (
        (path / "external_results.json").exists()
        and (path / "external_summary.json").exists()
    )


def validate_path(path: Path) -> ValidationResult:
    """Validate a report dir, a comparison dir, or a directory of such dirs."""
    result = ValidationResult()
    _validate_into(path, path, result)
    return result


def _validate_into(path: Path, root: Path, result: ValidationResult) -> None:
    if not path.exists():
        result._err(f"missing path: {_rel(path, root)}")
        return
    if not path.is_dir():
        result._err(f"not a directory: {_rel(path, root)}")
        return
    if _is_comparison_dir(path):
        result.comparison_dirs.append(_rel(path, root))
        _validate_comparison_dir(path, root, result)
    elif _is_external_dir(path):
        result.external_dirs.append(_rel(path, root))
        _validate_external_dir(path, root, result)
    elif (path / "traces.json").exists():
        result.report_dirs.append(_rel(path, root))
        _validate_report_dir(path, root, result)
    else:
        children = sorted((c for c in path.iterdir() if c.is_dir()), key=lambda c: c.name)
        if not children:
            result._warn(f"no benchmark artifacts found under {_rel(path, root)}")
            return
        for child in children:
            _validate_into(child, root, result)


def _load_json(path: Path, root: Path, result: ValidationResult) -> Any:
    if not path.exists():
        result._err(f"{_rel(path, root)}: missing")
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result._err(f"{_rel(path, root)}: unreadable ({type(exc).__name__})")
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        result._err(f"{_rel(path, root)}: invalid JSON")
        return None


def _fmt_error(exc: ValidationError) -> str:
    errs = exc.errors()
    if not errs:
        return "invalid"
    first = errs[0]
    loc = ".".join(str(part) for part in first.get("loc", ()))
    msg = str(first.get("msg", "invalid"))
    return f"{loc}: {msg}" if loc else msg


def _load_traces(
    path: Path, root: Path, result: ValidationResult
) -> list[ExploitTrace] | None:
    raw = _load_json(path, root, result)
    if raw is None:
        return None
    if not isinstance(raw, list):
        result._err(f"{_rel(path, root)}: expected a JSON list at the root")
        return None
    traces: list[ExploitTrace] = []
    ok = True
    for i, item in enumerate(raw):
        try:
            traces.append(ExploitTrace.model_validate(item))
        except ValidationError as exc:
            result._err(f"{_rel(path, root)}[{i}]: schema: {_fmt_error(exc)}")
            ok = False
    return traces if ok else None


def _load_scorecard(
    path: Path, root: Path, result: ValidationResult
) -> ScorecardSummary | None:
    raw = _load_json(path, root, result)
    if raw is None:
        return None
    try:
        return ScorecardSummary.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{_rel(path, root)}: schema: {_fmt_error(exc)}")
        return None


def _validate_traces(
    traces: list[ExploitTrace],
    path: Path,
    root: Path,
    result: ValidationResult,
    expected_pattern_ids: set[str] | None = None,
    is_matrix: bool = False,
) -> None:
    corpus = {entry.pattern_id: entry for entry in corpus_manifest()}
    canonical = {pattern.pattern_id: pattern for pattern in seed_patterns()}
    rel = _rel(path, root)
    target_names = sorted({trace.target.name for trace in traces})
    if len(target_names) > 1:
        result._err(f"{rel}: traces mix multiple target names: {target_names}")
    # A report dir must describe ONE target. Enforcing a single target.type closes the
    # false-negative where one relabeled trace exempts itself from the PASS/FAIL invariant
    # (a baseline trace flipped to a protected type, or vice versa).
    target_types = sorted({trace.target.type for trace in traces})
    if len(target_types) > 1:
        result._err(f"{rel}: traces mix multiple target types: {target_types}")
    seen: dict[str, int] = {}
    pattern_counts: dict[str, int] = {}
    for i, trace in enumerate(traces):
        prefix = f"{rel}[{i}] {trace.pattern_id}"
        pattern_counts[trace.pattern_id] = pattern_counts.get(trace.pattern_id, 0) + 1
        if trace.schema_version != _SCHEMA_VERSION:
            result._err(
                f"{prefix}: schema_version '{trace.schema_version}' != '{_SCHEMA_VERSION}'"
            )
        indices = [step.index for step in trace.steps]
        if indices != list(range(len(indices))):
            result._err(f"{prefix}: step indices not sequential from 0: {indices}")
        if trace.trace_id in seen:
            result._err(
                f"{rel}: duplicate trace_id '{trace.trace_id}' "
                f"(items {seen[trace.trace_id]}, {i})"
            )
        else:
            seen[trace.trace_id] = i
        entry = corpus.get(trace.pattern_id)
        if entry is None:
            result._err(f"{prefix}: pattern_id not in corpus")
            continue
        pattern = canonical.get(trace.pattern_id)
        if pattern is None:
            result._err(f"{prefix}: pattern_id not in seed patterns")
            continue
        if trace.graph_path != pattern.graph_path:
            result._err(f"{prefix}: graph_path does not match the seed pattern")
        if trace.expected_vulnerable_behavior != pattern.expected_vulnerable_behavior:
            result._err(
                f"{prefix}: expected_vulnerable_behavior does not match the seed pattern"
            )
        if trace.data_envelope != pattern.data_envelope:
            result._err(f"{prefix}: data_envelope does not match the seed pattern")
        protected = _is_protected(trace.target)
        if trace.findings:
            if protected:
                result._err(f"{prefix}: protected target should PASS but has findings")
            top = max(trace.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, -1))
            if top.code != pattern.category:
                result._err(
                    f"{prefix}: finding code '{top.code}' != pattern category "
                    f"'{pattern.category}'"
                )
            if top.severity != entry.severity:
                result._err(
                    f"{prefix}: finding severity '{top.severity}' != corpus '{entry.severity}'"
                )
            if top.broke_at != entry.broke_at:
                result._err(
                    f"{prefix}: finding broke_at '{top.broke_at}' != corpus '{entry.broke_at}'"
                )
        elif not protected:
            result._err(f"{prefix}: no findings but baseline target expects FAIL")
    # For matrix runs, validate against the selected patterns instead of the full corpus
    expected_ids = expected_pattern_ids if expected_pattern_ids is not None else set(corpus)
    actual_ids = set(pattern_counts)
    missing = sorted(expected_ids - actual_ids)
    extra = sorted(actual_ids - expected_ids)
    # Matrix runs intentionally have duplicate pattern_ids (one per variant)
    if not is_matrix:
        duplicates = sorted(
            pid for pid, count in pattern_counts.items() if count > 1
        )
    else:
        duplicates = []
    if missing:
        result._err(f"{rel}: missing corpus pattern(s): {missing}")
    if extra:
        result._err(f"{rel}: extra non-corpus pattern(s): {extra}")
    if duplicates:
        result._err(f"{rel}: duplicate pattern_id(s): {duplicates}")


def _validate_scorecard(
    committed: ScorecardSummary,
    expected: ScorecardSummary,
    traces: list[ExploitTrace],
    path: Path,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    if committed.total_traces != len(traces):
        result._err(
            f"{rel}: total_traces {committed.total_traces} != number of traces {len(traces)}"
        )
    if committed.target_name != expected.target_name:
        result._err(f"{rel}: target_name '{committed.target_name}' != '{expected.target_name}'")
    if committed.findings_by_severity != expected.findings_by_severity:
        result._err(f"{rel}: findings_by_severity does not match the traces' findings")
    if committed.findings_by_category != expected.findings_by_category:
        result._err(f"{rel}: findings_by_category does not match the traces' findings")
    if committed.failed_patterns != expected.failed_patterns:
        result._err(f"{rel}: failed_patterns do not match the traces' findings")
    if committed.passed_patterns != expected.passed_patterns:
        result._err(f"{rel}: passed_patterns do not match the traces' findings")
    corpus_ids = {entry.pattern_id for entry in corpus_manifest()}
    for pid in committed.failed_patterns + committed.passed_patterns:
        if pid not in corpus_ids:
            result._err(f"{rel}: pattern_id '{pid}' not in corpus")


def _validate_summary(
    path: Path,
    traces: list[ExploitTrace],
    expected_card: ScorecardSummary,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    if not path.exists():
        result._err(f"{rel}: missing")
        return
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    expected = build_summary_md(expected_card, traces)
    if actual.replace("\r\n", "\n") != expected.replace("\r\n", "\n"):
        result._err(f"{rel}: does not match the summary rebuilt from scorecard + traces")


def _validate_executive(
    path: Path,
    traces: list[ExploitTrace],
    expected_card: ScorecardSummary,
    root: Path,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    if not path.exists():
        result._err(f"{rel}: missing")
        return
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    expected = build_executive_md(expected_card, traces)
    if actual.replace("\r\n", "\n") != expected.replace("\r\n", "\n"):
        result._err(f"{rel}: does not match the executive report rebuilt from scorecard + traces")


def _validate_remediation(
    path: Path,
    traces: list[ExploitTrace],
    expected_card: ScorecardSummary,
    root: Path,
    result: ValidationResult,
) -> None:
    """Validate remediation.json and remediation.md if present."""
    from agentic_security_harness.remediation import (
        build_recommendations,
        build_remediation_md,
    )

    rem_json = path / "remediation.json"
    rem_md = path / "remediation.md"
    expected = build_recommendations(traces, expected_card)

    if not expected.recommendations:
        # No findings → no remediation artifacts expected; clean up stale ones
        for p in (rem_json, rem_md):
            if p.exists():
                p.unlink()
        return

    # Validate remediation.json
    if rem_json.exists():
        try:
            raw = json.loads(rem_json.read_text(encoding="utf-8"))
            from agentic_security_harness.remediation import RemediationReport

            committed = RemediationReport.model_validate(raw)
            if committed.model_dump(mode="json") != expected.model_dump(mode="json"):
                result._err(
                    f"{_rel(rem_json, root)}: does not match remediation rebuilt "
                    "from traces + scorecard"
                )
        except (json.JSONDecodeError, ValidationError) as exc:
            result._err(f"{_rel(rem_json, root)}: invalid ({type(exc).__name__})")
    else:
        result._err(f"{_rel(rem_json, root)}: missing (expected when findings exist)")

    # Validate remediation.md
    if rem_md.exists():
        try:
            actual = rem_md.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result._err(f"{_rel(rem_md, root)}: unreadable")
        else:
            expected_md = build_remediation_md(expected)
            if actual.replace("\r\n", "\n") != expected_md.replace("\r\n", "\n"):
                result._err(
                    f"{_rel(rem_md, root)}: does not match remediation markdown "
                    "rebuilt from traces + scorecard"
                )
    else:
        result._err(f"{_rel(rem_md, root)}: missing (expected when findings exist)")


def _validate_report_dir(
    path: Path, root: Path, result: ValidationResult
) -> ScorecardSummary | None:
    # Check for matrix.json first to determine expected pattern subset
    matrix_json = path / "matrix.json"
    expected_pattern_ids: set[str] | None = None
    if matrix_json.exists():
        matrix_raw = _load_json(matrix_json, root, result)
        if matrix_raw is not None:
            try:
                from agentic_security_harness.matrix import MatrixReport

                matrix_report = MatrixReport.model_validate(matrix_raw)
                expected_pattern_ids = set(matrix_report.selected_pattern_ids)
            except ValidationError:
                pass

    traces = _load_traces(path / "traces.json", root, result)
    committed_card = _load_scorecard(path / "scorecard.json", root, result)
    expected_card: ScorecardSummary | None = None
    is_matrix = expected_pattern_ids is not None
    if traces is not None:
        _validate_traces(
            traces, path / "traces.json", root, result,
            expected_pattern_ids=expected_pattern_ids,
            is_matrix=is_matrix,
        )
        expected_card = build_scorecard(traces)
    if traces is not None and committed_card is not None and expected_card is not None:
        _validate_scorecard(
            committed_card, expected_card, traces, path / "scorecard.json", root, result
        )
        _validate_summary(path / "summary.md", traces, expected_card, root, result)
        _validate_executive(path / "executive.md", traces, expected_card, root, result)
        _validate_remediation(path, traces, expected_card, root, result)
    # Validate matrix.json if present
    if matrix_json.exists():
        _validate_matrix_json(matrix_json, traces, root, result)
    for name in ("traces.json", "scorecard.json", "summary.md", "executive.md"):
        _scan_secrets(path / name, root, result)
    # Scan remediation artifacts if present
    for name in ("remediation.json", "remediation.md"):
        if (path / name).exists():
            _scan_secrets(path / name, root, result)
    # Scan matrix artifacts if present
    for name in ("matrix.json", "matrix.md"):
        if (path / name).exists():
            _scan_secrets(path / name, root, result)
    _validate_run_manifest(path, root, result)
    return expected_card


def _validate_comparison_dir(path: Path, root: Path, result: ValidationResult) -> None:
    baseline = path / "baseline"
    protected = path / "protected"
    comparison_md = path / "comparison.md"
    for name, sub in (
        ("baseline/", baseline),
        ("protected/", protected),
        ("comparison.md", comparison_md),
    ):
        if not sub.exists():
            result._err(f"{_rel(path, root)}: missing {name}")
    base_card: ScorecardSummary | None = None
    prot_card: ScorecardSummary | None = None
    if baseline.is_dir():
        result.report_dirs.append(_rel(baseline, root))
        base_card = _validate_report_dir(baseline, root, result)
    if protected.is_dir():
        result.report_dirs.append(_rel(protected, root))
        prot_card = _validate_report_dir(protected, root, result)
    if comparison_md.exists() and base_card is not None and prot_card is not None:
        _validate_comparison_md(comparison_md, root, base_card, prot_card, result)
    elif comparison_md.exists():
            _scan_secrets(comparison_md, root, result)
    _validate_run_manifest(path, root, result)


def _validate_external_dir(path: Path, root: Path, result: ValidationResult) -> None:
    from agentic_security_harness.run_config import ExternalResult, ExternalSummary, RunConfig

    config_raw = _load_json(path / "run_config.json", root, result)
    results_raw = _load_json(path / "external_results.json", root, result)
    summary_raw = _load_json(path / "external_summary.json", root, result)
    report_md = path / "external_report.md"
    if not report_md.exists():
        result._err(f"{_rel(report_md, root)}: missing")
    else:
        _validate_external_report_md(report_md, root, result)

    config: RunConfig | None = None
    summary: ExternalSummary | None = None
    results: list[ExternalResult] | None = None

    if config_raw is not None:
        try:
            config = RunConfig.model_validate(config_raw)
        except ValidationError as exc:
            result._err(f"{_rel(path / 'run_config.json', root)}: schema: {_fmt_error(exc)}")
    if summary_raw is not None:
        try:
            summary = ExternalSummary.model_validate(summary_raw)
        except ValidationError as exc:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: schema: {_fmt_error(exc)}"
            )
    if results_raw is not None:
        if not isinstance(results_raw, list):
            result._err(f"{_rel(path / 'external_results.json', root)}: expected list")
        else:
            parsed: list[ExternalResult] = []
            ok = True
            for i, item in enumerate(results_raw):
                try:
                    parsed.append(ExternalResult.model_validate(item))
                except ValidationError as exc:
                    result._err(
                        f"{_rel(path / 'external_results.json', root)}[{i}]: "
                        f"schema: {_fmt_error(exc)}"
                    )
                    ok = False
            results = parsed if ok else None

    if config is not None:
        if config.adapter_type != "openai-compatible":
            result._err(
                f"{_rel(path / 'run_config.json', root)}: unsupported adapter_type "
                f"'{config.adapter_type}'"
            )
        if config.api_key_env and any(
            token in config.api_key_env.lower() for token in ("sk-", "key=")
        ):
            result._err(
                f"{_rel(path / 'run_config.json', root)}: api_key_env looks like a key value"
            )
        # request_count is the pre-run estimate; once results exist it must match
        # the number of normalized results actually written.
        if results is not None and config.request_count != len(results):
            result._err(
                f"{_rel(path / 'run_config.json', root)}: request_count "
                f"{config.request_count} != external_results count {len(results)}"
            )
    if results is not None:
        _validate_external_results(path, root, results, result)
    if config is not None and summary is not None:
        if summary.adapter_type != config.adapter_type:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: adapter_type "
                "does not match run_config"
            )
        if summary.model != config.model:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: model "
                "does not match run_config"
            )
        if summary.scenario_id != config.scenario_id:
            result._err(
                f"{_rel(path / 'external_summary.json', root)}: scenario_id "
                "does not match run_config"
            )
    if results is not None and summary is not None:
        _validate_external_summary(path, root, results, summary, result)

    for name in (
        "run_config.json",
        "external_results.json",
        "external_summary.json",
        "external_report.md",
    ):
        _scan_secrets(path / name, root, result)
    _validate_run_manifest(path, root, result)


def _validate_external_report_md(
    path: Path, root: Path, result: ValidationResult
) -> None:
    """Light structural check: the human report has its core sections and points
    back to the machine artifacts. Not a byte-for-byte rebuild (the report can
    carry model-dependent prose)."""
    rel = _rel(path, root)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    required = [
        "## Configuration",
        "## Results",
        "## Control recommendations",
        "## Related artifacts",
        "## How to reproduce / validate",
    ]
    for section in required:
        if section not in text:
            result._err(f"{rel}: missing section '{section}'")
    if "run_config.json" not in text or "external_summary.json" not in text:
        result._err(
            f"{rel}: does not reference run_config.json / external_summary.json"
        )


def _validate_external_results(
    path: Path, root: Path, results: list["ExternalResult"], result: ValidationResult
) -> None:
    rel = _rel(path / "external_results.json", root)
    corpus_ids = {entry.pattern_id for entry in corpus_manifest()}
    seen: set[str] = set()
    for i, item in enumerate(results):
        prefix = f"{rel}[{i}] {item.pattern_id}"
        if item.result_id in seen:
            result._err(f"{rel}: duplicate result_id '{item.result_id}'")
        seen.add(item.result_id)
        if item.pattern_id not in corpus_ids:
            result._err(f"{prefix}: pattern_id not in corpus")
        if item.error and (
            item.decision != "unclear"
            or item.reason
            or item.control_family
            or item.would_preserve_boundary is not None
        ):
            result._err(f"{prefix}: error result should not also carry a decision")


def _validate_external_summary(
    path: Path,
    root: Path,
    results: list["ExternalResult"],
    summary: "ExternalSummary",
    result: ValidationResult,
) -> None:
    from collections import defaultdict

    from agentic_security_harness.remediation import _FAMILY_MAP

    rel = _rel(path / "external_summary.json", root)
    total_checks = len({(r.pattern_id, r.variant_id) for r in results})
    if summary.total_repeats != len(results):
        result._err(
            f"{rel}: total_repeats {summary.total_repeats} != "
            f"external_results count {len(results)}"
        )
    if summary.total_checks != total_checks:
        result._err(
            f"{rel}: total_checks {summary.total_checks} != "
            f"unique pattern/variant checks {total_checks}"
        )

    # Recompute per-pattern aggregates from results to catch tampered/stale summaries.
    finding_results = [
        r for r in results if not r.error and r.would_preserve_boundary is False
    ]
    findings_by_pattern: dict[str, int] = defaultdict(int)
    for r in finding_results:
        findings_by_pattern[r.pattern_id] += 1

    patterns_with_findings = sorted(set(findings_by_pattern))
    if summary.patterns_with_findings != patterns_with_findings:
        result._err(f"{rel}: patterns_with_findings does not match external_results")

    if dict(summary.findings_by_pattern) != dict(findings_by_pattern):
        result._err(f"{rel}: findings_by_pattern does not match external_results")

    findings_by_control_family: dict[str, int] = defaultdict(int)
    for pid, count in findings_by_pattern.items():
        family = _FAMILY_MAP.get(pid, "provenance")
        findings_by_control_family[family] += count
    if dict(summary.findings_by_control_family) != dict(findings_by_control_family):
        result._err(
            f"{rel}: findings_by_control_family does not match external_results"
        )

    error_patterns = sorted({r.pattern_id for r in results if r.error})
    if summary.error_patterns != error_patterns:
        result._err(f"{rel}: error_patterns does not match external_results")

    # inconclusive_patterns: had an inconclusive result and no finding for that pattern.
    inconclusive_pids = {
        r.pattern_id
        for r in results
        if not r.error and r.would_preserve_boundary is None
    }
    expected_inconclusive = sorted(
        pid for pid in inconclusive_pids if pid not in findings_by_pattern
    )
    if summary.inconclusive_patterns != expected_inconclusive:
        result._err(f"{rel}: inconclusive_patterns does not match external_results")

    # flaky_patterns: a (pattern, variant) group with >1 non-error outcome.
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in results:
        if r.error:
            outcome = "error"
        elif r.would_preserve_boundary is True:
            outcome = "pass"
        elif r.would_preserve_boundary is False:
            outcome = "finding"
        else:
            outcome = "inconclusive"
        groups[(r.pattern_id, r.variant_id)].add(outcome)
    flaky_pids = sorted({
        pid for (pid, _vid), outs in groups.items() if len(outs - {"error"}) > 1
    })
    if summary.flaky_patterns != flaky_pids:
        result._err(f"{rel}: flaky_patterns does not match external_results")


def _validate_comparison_md(
    path: Path,
    root: Path,
    base_card: ScorecardSummary,
    prot_card: ScorecardSummary,
    result: ValidationResult,
) -> None:
    rel = _rel(path, root)
    try:
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        result._err(f"{rel}: unreadable")
        return
    expected = build_comparison_md(base_card, prot_card)
    if actual.replace("\r\n", "\n") != expected.replace("\r\n", "\n"):
        result._err(f"{rel}: does not match the comparison rebuilt from the scorecards")
    b_total = sum(base_card.findings_by_severity.values())
    p_total = sum(prot_card.findings_by_severity.values())
    # The delta is signed (negative = reduction); tolerate either sign so a worse-than-
    # baseline comparison (more findings) is validated, not rejected as malformed.
    match = re.search(r"Findings reduced:\s*(\d+)\s*->\s*(\d+)\s*\(([+-]?\d+)\)", actual)
    if match is None:
        result._err(f"{rel}: missing 'Findings reduced: X -> Y (Z)' line")
    else:
        nums = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        if nums != (b_total, p_total, p_total - b_total):
            result._err(
                f"{rel}: reduction mismatch: file says {nums[0]} -> {nums[1]} ({nums[2]:+d}); "
                f"scorecards imply {b_total} -> {p_total} ({p_total - b_total:+d})"
            )
    _scan_secrets(path, root, result)


def _validate_run_manifest(dir_path: Path, root: Path, result: ValidationResult) -> None:
    """Validate ``run_index.json`` inside a run directory, if present.

    Checks structure, run kind, and that every listed artifact exists. The
    ``created_at`` timestamp is informational and is not rebuilt or compared.
    """
    manifest_path = dir_path / "run_index.json"
    if not manifest_path.exists():
        return
    from agentic_security_harness.run_manifest import _RUN_KINDS, RunManifest

    rel = _rel(manifest_path, root)
    raw = _load_json(manifest_path, root, result)
    if raw is None:
        return
    try:
        manifest = RunManifest.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    if not manifest.run_id:
        result._err(f"{rel}: run_id is empty")
    if manifest.run_kind not in _RUN_KINDS:
        result._err(f"{rel}: unknown run_kind '{manifest.run_kind}'")
    for art in manifest.artifacts:
        if not (dir_path / art).exists():
            result._err(f"{rel}: artifact '{art}' is missing from the run directory")
    _scan_secrets(manifest_path, root, result)


def _scan_secrets(path: Path, root: Path, result: ValidationResult) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    rel = _rel(path, root)
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            result._err(
                f"{rel}: possible secret-shaped string (forbidden marker '{name}')"
            )


def _validate_matrix_json(
    matrix_path: Path,
    traces: list[ExploitTrace] | None,
    root: Path,
    result: ValidationResult,
) -> None:
    """Validate matrix.json against traces and corpus."""
    rel = _rel(matrix_path, root)
    raw = _load_json(matrix_path, root, result)
    if raw is None:
        return
    try:
        from agentic_security_harness.matrix import MatrixReport

        report = MatrixReport.model_validate(raw)
    except ValidationError as exc:
        result._err(f"{rel}: schema: {_fmt_error(exc)}")
        return
    # Validate selected pattern ids exist in corpus
    corpus = {entry.pattern_id: entry for entry in corpus_manifest()}
    for pid in report.selected_pattern_ids:
        if pid not in corpus:
            result._err(f"{rel}: selected pattern_id '{pid}' not in corpus")
    # Validate unique variant ids
    variant_ids = [v.variant_id for v in report.variants]
    if len(variant_ids) != len(set(variant_ids)):
        dupes = sorted(
            vid for vid in set(variant_ids) if variant_ids.count(vid) > 1
        )
        result._err(f"{rel}: duplicate variant_id(s): {dupes}")
    # Validate trace ids referenced by variants exist in traces.json
    if traces is not None:
        trace_id_set = {t.trace_id for t in traces}
        all_ref_ids: list[str] = []
        for v in report.variants:
            all_ref_ids.extend(v.trace_ids)
        missing_traces = sorted(set(all_ref_ids) - trace_id_set)
        if missing_traces:
            result._err(
                f"{rel}: variant references trace_id(s) not in traces.json: "
                f"{missing_traces}"
            )
        # Validate total traces match
        if report.total_traces != len(traces):
            result._err(
                f"{rel}: total_traces {report.total_traces} "
                f"!= traces in traces.json {len(traces)}"
            )
        # Validate summary counts
        if report.summary:
            if report.summary.total_variants != len(report.variants):
                result._err(
                    f"{rel}: summary.total_variants "
                    f"{report.summary.total_variants} "
                    f"!= variants count {len(report.variants)}"
                )
            if report.summary.total_traces != report.total_traces:
                result._err(
                    f"{rel}: summary.total_traces "
                    f"{report.summary.total_traces} "
                    f"!= total_traces {report.total_traces}"
                )
    # Validate matrix.md if present
    matrix_md = matrix_path.parent / "matrix.md"
    if matrix_md.exists():
        _scan_secrets(matrix_md, root, result)
