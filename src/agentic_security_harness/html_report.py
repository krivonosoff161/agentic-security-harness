"""Static HTML report renderer (view layer over the JSON/Markdown artifacts).

The JSON and Markdown artifacts remain authoritative; this module only renders an
existing run directory into a single self-contained ``report.html`` with inline CSS.
No external resources, no CDN, no JavaScript, no network, no telemetry. It reads only
the committed JSON artifacts, so it never embeds absolute filesystem paths.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

_CSS = """
:root { color-scheme: light dark; }
body { font: 15px/1.5 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0; padding: 2rem; max-width: 960px; margin: 0 auto; color: #202124; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 1.75rem 0 .5rem; border-bottom: 1px solid #dadce0;
  padding-bottom: .25rem; }
.sub { color: #5f6368; margin: 0 0 1rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; font-size: .92rem; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #ececec; }
th { background: #f8f9fa; }
code { background: #f1f3f4; padding: .05rem .3rem; border-radius: 3px; }
.cell { text-align: center; font-weight: 600; }
.pass { background: #e6f4ea; color: #137333; }
.fail, .finding { background: #fce8e6; color: #c5221f; }
.inconclusive { background: #fef7e0; color: #b06000; }
.error { background: #f1f3f4; color: #5f6368; }
.bar { display: flex; height: 18px; border-radius: 4px; overflow: hidden;
  border: 1px solid #dadce0; }
.bar span { display: block; }
.kv td:first-child { color: #5f6368; width: 14rem; }
.note { background: #f8f9fa; border-left: 4px solid #9aa0a6; padding: .6rem .9rem;
  margin: 1rem 0; border-radius: 0 4px 4px 0; }
footer { color: #5f6368; font-size: .82rem; margin-top: 2rem; border-top: 1px solid
  #dadce0; padding-top: .75rem; }
"""

_SEV_COLORS = {
    "critical": "#9a0007",
    "high": "#c5221f",
    "medium": "#e8710a",
    "low": "#f9ab00",
    "info": "#9aa0a6",
}

_DISCLAIMER = (
    "This report shows conformance to a synthetic, deterministic benchmark. It does "
    "<strong>not</strong> prove that any real system is secure, certified, or production-"
    "safe. Findings are synthetic test outcomes, not live exploits; a clean result means "
    "the modelled patterns passed, not that real-world risk is eliminated."
)


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _load(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def detect_kind(run_dir: Path) -> str:
    """Detect the report kind from the artifacts present."""
    if (run_dir / "run_diff.json").exists():
        return "diff"
    if (run_dir / "matrix.json").exists():
        return "matrix"
    if (run_dir / "comparison.md").exists() or (
        (run_dir / "baseline").is_dir() and (run_dir / "protected").is_dir()
    ):
        return "compare"
    if (run_dir / "external_summary.json").exists():
        return "external"
    if (run_dir / "traces.json").exists():
        return "run"
    raise ValueError(
        f"no recognizable run artifacts in {run_dir.as_posix()} "
        "(expected traces.json, matrix.json, comparison.md, external_summary.json, "
        "or run_diff.json)"
    )


# --------------------------------------------------------------------------- helpers


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>\n"
        f"{body}\n"
        "<footer>Agentic Security Harness - static report. No external resources, "
        "no network, no telemetry. JSON/Markdown artifacts remain authoritative."
        "</footer></body></html>\n"
    )


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _kv(pairs: list[tuple[str, str]]) -> str:
    rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in pairs if v
    )
    return f"<table class=\"kv\"><tbody>{rows}</tbody></table>"


def _severity_bar(by_sev: dict[str, int]) -> str:
    total = sum(by_sev.values())
    if total == 0:
        return "<p class=\"sub\">No findings.</p>"
    spans = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if n:
            pct = 100 * n / total
            color = _SEV_COLORS[sev]
            spans.append(
                f"<span style=\"width:{pct:.1f}%;background:{color}\" "
                f"title=\"{_esc(sev)}: {n}\"></span>"
            )
    legend = "  ".join(
        f"<code>{_esc(s)}</code> {by_sev.get(s, 0)}"
        for s in ("critical", "high", "medium", "low", "info")
        if by_sev.get(s, 0)
    )
    return f"<div class=\"bar\">{''.join(spans)}</div><p class=\"sub\">{legend}</p>"


def _disclaimer_section() -> str:
    return f"<h2>What this does not prove</h2><div class=\"note\">{_DISCLAIMER}</div>"


def _manifest_pairs(manifest: dict | None) -> list[tuple[str, str]]:
    if not manifest:
        return []
    pairs: list[tuple[str, str]] = [
        ("Run id", _esc(manifest.get("run_id", ""))),
        ("Kind", _esc(manifest.get("run_kind", ""))),
        ("Tool version", _esc(manifest.get("tool_version", ""))),
        ("Created at", _esc(manifest.get("created_at", ""))),
    ]
    meta = manifest.get("metadata") or {}
    for key in (
        "adapter_type",
        "model",
        "base_url_label",
        "scenario",
        "repeats",
        "temperature",
        "timeout_seconds",
        "network_mode",
        "api_key_env",
    ):
        if key in meta and meta[key] not in ("", None):
            pairs.append((key.replace("_", " "), _esc(meta[key])))
    return pairs


# --------------------------------------------------------------------------- run


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _trace_outcome(trace: dict) -> tuple[str, str, str]:
    findings = trace.get("findings") or []
    if not findings:
        return ("PASS", "pass", "")
    top = max(findings, key=lambda f: _SEV_RANK.get(f.get("severity", ""), -1))
    return ("FINDING", "finding", f"{top.get('severity', '')} / {top.get('code', '')}")


def _render_run(run_dir: Path, manifest: dict | None) -> str:
    traces = _load(run_dir / "traces.json") or []
    scorecard = _load(run_dir / "scorecard.json") or {}
    remediation = _load(run_dir / "remediation.json")

    target = _esc(scorecard.get("target_name", "unknown"))
    failed = scorecard.get("failed_patterns", [])
    passed = scorecard.get("passed_patterns", [])
    by_sev = scorecard.get("findings_by_severity", {})

    body = [f"<h1>Run report - {target}</h1>"]
    body.append(f"<p class=\"sub\">{len(traces)} patterns - "
                f"{len(failed)} with findings - {len(passed)} clean</p>")
    if manifest:
        body.append("<h2>Run metadata</h2>")
        body.append(_kv(_manifest_pairs(manifest)))

    body.append("<h2>Severity distribution</h2>")
    body.append(_severity_bar(by_sev))

    body.append("<h2>Pattern results</h2>")
    rows = []
    for trace in sorted(traces, key=lambda t: t.get("pattern_id", "")):
        outcome, cls, detail = _trace_outcome(trace)
        rows.append([
            f"<code>{_esc(trace.get('pattern_id', ''))}</code>",
            f"<span class=\"cell {cls}\">{outcome}</span>",
            _esc(detail),
        ])
    body.append(_table(["Pattern", "Outcome", "Top finding"], rows))

    body.append(_remediation_section(remediation))
    body.append(_pattern_detail_sections(traces, remediation))
    body.append(_disclaimer_section())
    return _page(f"Run report - {scorecard.get('target_name', 'run')}", "".join(body))


def _pattern_detail_sections(traces: list, remediation: dict | None) -> str:
    """Per-pattern detail for each finding: status, family, evidence, fixes, retest."""
    recs_by_pid: dict[str, dict] = {}
    if remediation:
        for rec in remediation.get("recommendations", []):
            recs_by_pid.setdefault(rec.get("pattern_id", ""), rec)
    finding_traces = [t for t in traces if t.get("findings")]
    if not finding_traces:
        return ""
    out = ["<h2>Findings detail (per pattern)</h2>"]
    for trace in sorted(finding_traces, key=lambda t: t.get("pattern_id", "")):
        pid = trace.get("pattern_id", "")
        findings = trace.get("findings") or []
        top = max(findings, key=lambda f: _SEV_RANK.get(f.get("severity", ""), -1))
        rec = recs_by_pid.get(pid, {})
        family = rec.get("control_family", "")
        evidence = trace.get("observed_behavior", "") or top.get("message", "")
        out.append(f"<h3>{_esc(pid)}</h3>")
        rows = [
            ("Category", _esc(top.get("code", ""))),
            ("Severity", f"<span class=\"cell finding\">{_esc(top.get('severity', ''))}</span>"),
            ("Status", "<span class=\"cell finding\">FINDING</span>"),
            ("Control family", _esc(family) if family else "-"),
            ("Evidence", _esc(evidence[:400])),
        ]
        if rec:
            rows += [
                ("Quick fix", _esc(rec.get("quick_fix", ""))),
                ("Engineering fix", _esc(rec.get("engineering_fix", ""))),
                ("Architecture fix", _esc(rec.get("architecture_fix", ""))),
                ("Verification", _esc(rec.get("verification", ""))),
                ("Residual risk", _esc(rec.get("residual_risk", ""))),
            ]
        rows.append((
            "Retest",
            "re-run after the fix, then <code>ash diff-runs</code> the two run dirs",
        ))
        out.append(_kv(rows))
    return "".join(out)


def _remediation_section(remediation: dict | None) -> str:
    if not remediation or not remediation.get("recommendations"):
        return ""
    families = remediation.get("control_families", [])
    out = ["<h2>Control families needing attention</h2>"]
    out.append("<p class=\"sub\">" + ", ".join(
        f"<code>{_esc(f)}</code>" for f in families
    ) + "</p>")
    out.append("<p class=\"sub\">See <code>remediation.md</code> for quick / engineering "
               "/ architecture fixes, verification, and residual risk.</p>")
    return "".join(out)


# --------------------------------------------------------------------------- compare


def _render_compare(run_dir: Path, manifest: dict | None) -> str:
    base = _load(run_dir / "baseline" / "scorecard.json") or {}
    prot = _load(run_dir / "protected" / "scorecard.json") or {}
    b_findings = sum((base.get("findings_by_severity") or {}).values())
    p_findings = sum((prot.get("findings_by_severity") or {}).values())

    body = ["<h1>Risk-reduction comparison</h1>"]
    body.append(f"<p class=\"sub\">{_esc(base.get('target_name', 'baseline'))} -> "
                f"{_esc(prot.get('target_name', 'protected'))}</p>")
    if manifest:
        body.append("<h2>Run metadata</h2>")
        body.append(_kv(_manifest_pairs(manifest)))

    body.append("<h2>Before / after</h2>")
    rows = [
        ["Patterns with findings",
         str(len(base.get("failed_patterns", []))),
         str(len(prot.get("failed_patterns", [])))],
        ["Clean patterns",
         str(len(base.get("passed_patterns", []))),
         str(len(prot.get("passed_patterns", [])))],
        ["Total findings", str(b_findings), str(p_findings)],
    ]
    body.append(_table(["Metric", "Baseline", "Protected"], rows))
    delta = p_findings - b_findings
    body.append(f"<div class=\"note\">Findings reduced: <strong>{b_findings} -> "
                f"{p_findings} ({delta:+d})</strong>.</div>")

    body.append("<h2>Baseline severity distribution</h2>")
    body.append(_severity_bar(base.get("findings_by_severity", {})))
    body.append(_disclaimer_section())
    return _page("Risk-reduction comparison", "".join(body))


# --------------------------------------------------------------------------- matrix


def _render_matrix(run_dir: Path, manifest: dict | None) -> str:
    matrix = _load(run_dir / "matrix.json") or {}
    summary = matrix.get("summary", {})
    variants = matrix.get("variants", [])
    pattern_ids = matrix.get("selected_pattern_ids", [])

    body = [f"<h1>Matrix report - {_esc(matrix.get('scenario_id', ''))}</h1>"]
    body.append(f"<p class=\"sub\">target <code>{_esc(matrix.get('target_name', ''))}</code> - "
                f"{summary.get('total_variants', 0)} variants - "
                f"{summary.get('total_traces', 0)} traces - "
                f"{summary.get('failed_variants', 0)} failed / "
                f"{summary.get('passed_variants', 0)} passed variants</p>")
    if manifest:
        body.append("<h2>Run metadata</h2>")
        body.append(_kv(_manifest_pairs(manifest)))

    # Coverage heatmap: patterns (rows) x variants (cols)
    body.append("<h2>Coverage heatmap (pattern x variant)</h2>")
    fail_sets = {
        v.get("variant_id", ""): set(v.get("failed_patterns", [])) for v in variants
    }
    headers = ["Pattern"] + [v.get("variant_id", "") for v in variants] + ["Stability"]
    stable = set(summary.get("stable_failures", []))
    sensitive = set(summary.get("variant_sensitive_failures", []))
    rows = []
    for pid in pattern_ids:
        cells = [f"<code>{_esc(pid)}</code>"]
        for v in variants:
            vid = v.get("variant_id", "")
            if pid in fail_sets.get(vid, set()):
                cells.append("<span class=\"cell finding\">FAIL</span>")
            else:
                cells.append("<span class=\"cell pass\">PASS</span>")
        if pid in stable:
            stab = "<span class=\"cell finding\">stable_fail</span>"
        elif pid in sensitive:
            stab = "<span class=\"cell inconclusive\">variant_sensitive</span>"
        else:
            stab = "<span class=\"cell pass\">pass</span>"
        cells.append(stab)
        rows.append(cells)
    body.append(_table(headers, rows))

    fam = summary.get("findings_by_control_family", {})
    if fam:
        body.append("<h2>Findings by control family</h2>")
        body.append(_table(
            ["Control family", "Findings"],
            [[f"<code>{_esc(k)}</code>", str(v)] for k, v in sorted(
                fam.items(), key=lambda kv: (-kv[1], kv[0]))],
        ))
    body.append(_disclaimer_section())
    return _page("Matrix report", "".join(body))


# --------------------------------------------------------------------------- external


def _render_external(run_dir: Path, manifest: dict | None) -> str:
    summary = _load(run_dir / "external_summary.json") or {}
    config = _load(run_dir / "run_config.json") or {}

    body = [f"<h1>External run report - {_esc(summary.get('model', 'model'))}</h1>"]
    body.append("<div class=\"note\">Experimental external run. Prompt-based evaluation "
                "only; no tools executed. Not a benchmark-grade vendor comparison.</div>")

    body.append("<h2>Run metadata</h2>")
    pairs = _manifest_pairs(manifest)
    if not pairs:
        pairs = [
            ("adapter", _esc(config.get("adapter_type", ""))),
            ("model", _esc(config.get("model", ""))),
            ("endpoint", _esc(config.get("base_url_label", ""))),
            ("scenario", _esc(config.get("scenario_id", ""))),
            ("repeats", _esc(config.get("repeats", ""))),
            ("request_count", _esc(config.get("request_count", ""))),
            ("network_mode", _esc(config.get("network_mode", ""))),
            ("api_key_env", _esc(config.get("api_key_env", "") or "(none)")),
        ]
    body.append(_kv(pairs))

    body.append("<h2>Results</h2>")
    body.append(_table(
        ["Metric", "Count"],
        [
            ["Checks", str(summary.get("total_checks", 0))],
            ["Requests", str(summary.get("total_repeats", 0))],
            ["Patterns with findings", str(len(summary.get("patterns_with_findings", [])))],
            ["Flaky patterns", str(len(summary.get("flaky_patterns", [])))],
            ["Inconclusive patterns", str(len(summary.get("inconclusive_patterns", [])))],
            ["Error patterns", str(len(summary.get("error_patterns", [])))],
        ],
    ))

    repeats = summary.get("repeat_summaries", [])
    if repeats:
        body.append("<h2>Repeat summaries (stochastic view)</h2>")
        rows = []
        for rs in repeats:
            status = rs.get("stability_status", rs.get("dominant_outcome", ""))
            cls = {
                "stable_pass": "pass",
                "stable_finding": "finding",
                "flaky": "inconclusive",
                "inconclusive": "inconclusive",
                "adapter_error": "error",
            }.get(status, "")
            rows.append([
                f"<code>{_esc(rs.get('pattern_id', ''))}</code>",
                _esc(rs.get("variant_id", "")),
                str(rs.get("total_repeats", 0)),
                str(rs.get("pass_count", 0)),
                str(rs.get("finding_count", 0)),
                str(rs.get("inconclusive_count", 0)),
                str(rs.get("error_count", 0)),
                f"<span class=\"cell {cls}\">{_esc(status)}</span>",
            ])
        body.append(_table(
            ["Pattern", "Variant", "Repeats", "Pass", "Finding",
             "Inconcl.", "Error", "Status"],
            rows,
        ))

    # Explicit attention lists so the reader sees WHICH patterns need more data.
    attention = []
    for label, key in (
        ("Flaky", "flaky_patterns"),
        ("Inconclusive", "inconclusive_patterns"),
        ("Adapter errors", "error_patterns"),
    ):
        pids = summary.get(key, [])
        if pids:
            attention.append(
                f"<li><strong>{label}:</strong> "
                + ", ".join(f"<code>{_esc(p)}</code>" for p in pids) + "</li>"
            )
    if attention:
        body.append("<h2>Needs more data</h2>")
        body.append("<ul>" + "".join(attention) + "</ul>")
        body.append("<p class=\"sub\">Flaky/inconclusive/error are not pass or fail; "
                    "re-run with more <code>--repeats</code>.</p>")

    fam = summary.get("findings_by_control_family", {})
    if fam:
        body.append("<h2>Findings by control family</h2>")
        body.append(_table(
            ["Control family", "Findings"],
            [[f"<code>{_esc(k)}</code>", str(v)] for k, v in sorted(
                fam.items(), key=lambda kv: (-kv[1], kv[0]))],
        ))
    body.append(_disclaimer_section())
    return _page("External run report", "".join(body))


def _render_diff(run_dir: Path, manifest: dict | None) -> str:
    diff = _load(run_dir / "run_diff.json") or {}
    body = [f"<h1>Run diff - {_esc(diff.get('kind', ''))}</h1>"]
    body.append(
        f"<p class=\"sub\">left <code>{_esc(diff.get('left_label', ''))}</code> "
        f"vs right <code>{_esc(diff.get('right_label', ''))}</code></p>"
    )
    body.append("<div class=\"note\">Artifact comparison only: what changed between two "
                "recorded runs. Not a re-run and not a certification.</div>")
    body.append("<h2>Summary</h2>")
    body.append(_table(
        ["Change", "Count"],
        [
            ["Fixed (finding -> pass)", str(diff.get("fixed", 0))],
            ["New (pass -> finding)", str(diff.get("new", 0))],
            ["Changed (status/severity)", str(diff.get("changed", 0))],
            ["Unchanged", str(diff.get("unchanged", 0))],
            ["Only on left", str(diff.get("only_left", 0))],
            ["Only on right", str(diff.get("only_right", 0))],
        ],
    ))
    changed = [e for e in diff.get("entries", [])
               if e.get("change") in ("fixed", "new", "changed")]
    if changed:
        body.append("<h2>Changed patterns</h2>")
        rows = []
        for e in changed:
            cls = {"fixed": "pass", "new": "finding", "changed": "inconclusive"}.get(
                e.get("change", ""), "")
            rows.append([
                f"<code>{_esc(e.get('pattern_id', ''))}</code>",
                _esc(e.get("control_family", "")),
                _esc(e.get("left_status", "")),
                _esc(e.get("right_status", "")),
                f"<span class=\"cell {cls}\">{_esc(e.get('change', ''))}</span>",
            ])
        body.append(_table(["Pattern", "Family", "Left", "Right", "Change"], rows))
    body.append(_disclaimer_section())
    return _page("Run diff", "".join(body))


# --------------------------------------------------------------------------- public


def render_report(run_dir: Path) -> str:
    """Render a run directory into a single self-contained HTML string."""
    kind = detect_kind(run_dir)
    manifest = _load(run_dir / "run_index.json")
    if kind == "diff":
        return _render_diff(run_dir, manifest)
    if kind == "matrix":
        return _render_matrix(run_dir, manifest)
    if kind == "compare":
        return _render_compare(run_dir, manifest)
    if kind == "external":
        return _render_external(run_dir, manifest)
    return _render_run(run_dir, manifest)


def write_html_report(run_dir: Path, out: Path) -> Path:
    """Render ``run_dir`` and write the HTML to ``out`` (LF newlines)."""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(run_dir), encoding="utf-8", newline="\n")
    return out
