"""Generate a lightweight public showcase from recorded run artifacts.

The showcase is a curated view over JSON artifacts. It never upgrades a weak spot
into a finding and it writes an honest empty state when no runs are available.

Failure cards are *artifact-driven*: every field is read from a recorded trace /
scorecard / external artifact. The generator never writes a marketing summary that is not
backed by a trace reference, and every card carries an explicit limitation / non-claim.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentic_security_harness.run_manifest import RunManifest, load_run_manifests
from agentic_security_harness.safe_io import write_text_artifact

# Per-card non-claim. A card is evidence of one modeled boundary failure in a deterministic
# synthetic (or opt-in external) run - not proof of real-world exploitability or coverage.
_LOCAL_LIMITATION = (
    "Deterministic synthetic local trace. Evidence of one modeled boundary failure under "
    "fixed inputs, not proof of real-world exploitability or complete coverage."
)
_EXTERNAL_LIMITATION = (
    "Experimental opt-in external check. Weak evidence from a single endpoint; not a "
    "benchmark-grade or model-safety claim."
)


@dataclass(frozen=True)
class ShowcaseCard:
    """One reviewer-facing finding / weak-spot / problem card.

    The first block of fields is the stable card identity; the second block is the
    artifact-driven replay detail (populated from trace artifacts where available).
    """

    card_id: str
    card_type: str
    run_dir: str
    scenario: str
    target_or_model: str
    pattern_id: str
    status: str
    evidence: str
    artifact: str
    next_action: str
    # artifact-driven replay detail (empty when the source artifact does not carry it)
    control_family: str = ""
    failure_class: str = ""
    boundary: str = ""
    observed: str = ""
    broke_at: str = ""
    trace_ref: str = ""
    remediation: str = ""
    reproduce: str = ""
    limitation: str = ""
    evidence_refs: tuple[str, ...] = ()
    steps: tuple[str, ...] = field(default_factory=tuple)


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _target_or_model(manifest: RunManifest) -> str:
    return manifest.target or manifest.model or str(manifest.metadata.get("model") or "")


def _family(pattern_id: str) -> str:
    from agentic_security_harness.remediation import _FAMILY_MAP

    return _FAMILY_MAP.get(pattern_id, "provenance")


def _reproduce_run(target_name: str) -> str:
    """A correct command to re-derive a deterministic local run for this target.

    ``target_name`` in the manifest is the internal target name; map it back to the CLI
    ``--target`` id so the printed command actually runs. Falls back to the name itself.
    """
    from agentic_security_harness.adapters import list_targets

    target_id = target_name
    for info in list_targets():
        if info.name == target_name:
            target_id = info.target_id
            break
    return f"ash run --target {target_id} --out reports/{target_id}"


def _rel_artifact(run_rel: str, name: str) -> str:
    """Relative artifact path for a card link (stable across machines)."""
    return name if run_rel in ("", ".") else f"{run_rel}/{name}"


def _external_cards(
    run_dir: Path, manifest: RunManifest, run_rel: str
) -> list[ShowcaseCard]:
    summary = _load_json(run_dir / "external_summary.json") or {}
    results = _load_json(run_dir / "external_results.json") or []
    by_pattern: dict[str, list[dict[str, Any]]] = {}
    for row in results if isinstance(results, list) else []:
        if isinstance(row, dict):
            by_pattern.setdefault(str(row.get("pattern_id") or ""), []).append(row)

    cards: list[ShowcaseCard] = []
    for pid in summary.get("patterns_with_findings", []) or []:
        rows = by_pattern.get(str(pid), [])
        evidence = _first_nonempty(rows, "reason") or "external cross-check recorded a finding"
        boundary = _first_nonempty(rows, "boundary_assertion")
        cards.append(ShowcaseCard(
            card_id=f"finding.{manifest.run_id}.{pid}",
            card_type="finding",
            run_dir=run_rel,
            scenario=manifest.scenario,
            target_or_model=_target_or_model(manifest),
            pattern_id=str(pid),
            status="finding",
            evidence=evidence,
            artifact="external_results.json",
            next_action="Create a failure card and one bounded deepening variation.",
            control_family=_family(str(pid)),
            failure_class="external_finding",
            boundary=boundary,
            broke_at=_first_nonempty(rows, "decision"),
            remediation="Confirm with a stronger observation layer before treating as a finding.",
            reproduce=f"ash validate {run_rel}",
            limitation=_EXTERNAL_LIMITATION,
            evidence_refs=(_rel_artifact(run_rel, "external_results.json"),),
        ))
    for pid in summary.get("inconclusive_patterns", []) or []:
        rows = by_pattern.get(str(pid), [])
        evidence = _first_nonempty(rows, "recovery_hint") or "model output was inconclusive"
        cards.append(ShowcaseCard(
            card_id=f"weak.{manifest.run_id}.{pid}.inconclusive",
            card_type="weak-spot",
            run_dir=run_rel,
            scenario=manifest.scenario,
            target_or_model=_target_or_model(manifest),
            pattern_id=str(pid),
            status="inconclusive",
            evidence=evidence,
            artifact="external_results.json",
            next_action=(
                "Inspect raw_responses/ and rerun with more repeats or a stronger "
                "JSON-following model."
            ),
            control_family=_family(str(pid)),
            failure_class="inconclusive",
            limitation=_EXTERNAL_LIMITATION,
            evidence_refs=(_rel_artifact(run_rel, "external_results.json"),),
        ))
    for pid in summary.get("error_patterns", []) or []:
        rows = by_pattern.get(str(pid), [])
        evidence = _first_nonempty(rows, "recovery_hint") or _first_nonempty(rows, "error")
        cards.append(ShowcaseCard(
            card_id=f"problem.{manifest.run_id}.{pid}.adapter_error",
            card_type="problem",
            run_dir=run_rel,
            scenario=manifest.scenario,
            target_or_model=_target_or_model(manifest),
            pattern_id=str(pid),
            status="adapter_error",
            evidence=evidence or "adapter/runtime error",
            artifact="external_results.json",
            next_action=(
                "Fix runtime/profile or timeout, then rerun the same scenario before "
                "expanding."
            ),
            control_family=_family(str(pid)),
            failure_class="adapter_error",
            limitation=_EXTERNAL_LIMITATION,
            evidence_refs=(_rel_artifact(run_rel, "external_results.json"),),
        ))
    return cards


def _replay_steps(trace: dict[str, Any], broke_at: str) -> tuple[str, ...]:
    """Render trace steps as a compact replay; mark the step where the boundary broke."""
    lines: list[str] = []
    for step in trace.get("steps") or []:
        if not isinstance(step, dict):
            continue
        idx = step.get("index")
        actor = str(step.get("actor") or "")
        action = str(step.get("action") or "")
        observed = str(step.get("observed") or "")
        marker = "  <- broke_at" if broke_at and action == broke_at else ""
        lines.append(f"{idx}. {actor}/{action}: {observed}{marker}")
    return tuple(lines)


def _run_cards(
    run_dir: Path, manifest: RunManifest, run_rel: str
) -> list[ShowcaseCard]:
    traces = _load_json(run_dir / "traces.json") or []
    has_remediation = (run_dir / "remediation.json").exists()
    reproduce = _reproduce_run(manifest.target or _target_or_model(manifest))
    cards: list[ShowcaseCard] = []
    for trace in traces if isinstance(traces, list) else []:
        if not isinstance(trace, dict):
            continue
        findings = trace.get("findings") or []
        if not findings:
            continue
        pid = str(trace.get("pattern_id") or "")
        finding = findings[0] if isinstance(findings[0], dict) else {}
        evidence = str(
            finding.get("message") or finding.get("description")
            or finding.get("evidence") or "finding recorded"
        )
        broke_at = str(finding.get("broke_at") or "")
        trace_ref = str(trace.get("trace_id") or "")
        evidence_refs = [f"{_rel_artifact(run_rel, 'traces.json')}#{trace_ref}"]
        if has_remediation:
            evidence_refs.append(_rel_artifact(run_rel, "remediation.json"))
        cards.append(ShowcaseCard(
            card_id=f"finding.{manifest.run_id}.{pid}",
            card_type="finding",
            run_dir=run_rel,
            scenario=manifest.scenario,
            target_or_model=_target_or_model(manifest),
            pattern_id=pid,
            status=str(finding.get("severity") or "finding"),
            evidence=evidence,
            artifact="traces.json",
            next_action="Attach remediation and select one bounded deepening variation.",
            control_family=_family(pid),
            failure_class=str(finding.get("code") or pid),
            boundary=str(trace.get("expected_vulnerable_behavior") or ""),
            observed=str(trace.get("observed_behavior") or ""),
            broke_at=broke_at,
            trace_ref=trace_ref,
            remediation=str(finding.get("mitigation") or ""),
            reproduce=reproduce,
            limitation=_LOCAL_LIMITATION,
            evidence_refs=tuple(evidence_refs),
            steps=_replay_steps(trace, broke_at),
        ))
    return cards


def _first_nonempty(rows: list[dict[str, Any]], key: str) -> str:
    for row in rows:
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def _run_rel(root: Path, run_dir: Path) -> str:
    try:
        return run_dir.relative_to(root).as_posix()
    except ValueError:
        return run_dir.name


def build_showcase(root: Path) -> tuple[list[tuple[Path, RunManifest]], list[ShowcaseCard]]:
    """Return discovered manifests and generated cards."""
    manifests = load_run_manifests(root)
    cards: list[ShowcaseCard] = []
    for manifest_path, manifest in manifests:
        run_dir = manifest_path.parent
        run_rel = _run_rel(root, run_dir)
        if manifest.run_kind == "external":
            cards.extend(_external_cards(run_dir, manifest, run_rel))
        elif manifest.run_kind == "run":
            cards.extend(_run_cards(run_dir, manifest, run_rel))
    return manifests, cards


def _index_md(
    root: Path,
    manifests: list[tuple[Path, RunManifest]],
    cards: list[ShowcaseCard],
) -> str:
    lines = [
        "# Agentic Security Harness - generated showcase",
        "",
        "Generated from recorded run artifacts. JSON artifacts remain the source of truth.",
        "",
        f"- Source root: `{root.name}`",
        f"- Runs discovered: {len(manifests)}",
        f"- Cards generated: {len(cards)}",
        "",
        "## Run summary",
        "",
    ]
    if not manifests:
        lines += [
            "No run manifests found.",
            "",
            "Run a benchmark first, for example:",
            "",
            "```bash",
            "ash compare --baseline demo-agent --protected protected-demo-agent "
            "--out reports/comparison",
            "ash validate reports/comparison",
            "```",
            "",
        ]
    else:
        lines += [
            "| Run | Kind | Scenario | Target/model | Outcomes |",
            "|---|---|---|---|---|",
        ]
        for _run_dir, manifest in manifests:
            outcomes = ", ".join(f"{k}={v}" for k, v in sorted(manifest.outcomes.items()))
            lines.append(
                f"| `{manifest.run_id}` | {manifest.run_kind} | `{manifest.scenario}` | "
                f"`{_target_or_model(manifest)}` | {outcomes or '-'} |"
            )
        lines.append("")

    counts: dict[str, int] = {}
    for card in cards:
        counts[card.card_type] = counts.get(card.card_type, 0) + 1
    lines += [
        "## Card counts",
        "",
        "| Type | Count |",
        "|---|---|",
    ]
    if counts:
        for key in sorted(counts):
            lines.append(f"| {key} | {counts[key]} |")
    else:
        lines.append("| (none) | 0 |")
    lines += [
        "",
        "## Claim boundary",
        "",
        "- A `finding` card requires artifact evidence (a trace reference).",
        "- `weak-spot` and `problem` cards are not passes and not model-safety findings.",
        "- This generated page is a reviewer aid, not a certification or leaderboard.",
        "",
        "See `failure-cards.md` for the card ledger.",
        "",
    ]
    return "\n".join(lines)


def _card_md(card: ShowcaseCard) -> list[str]:
    """Render one artifact-driven card with replay detail."""
    lines = [
        f"## {card.card_id}",
        "",
        f"- Failure class: `{card.failure_class or card.card_type}`",
        f"- Type: `{card.card_type}`",
        f"- Scenario / family: `{card.scenario}` / `{card.control_family}`",
        f"- Target/model: `{card.target_or_model}`",
        f"- Pattern: `{card.pattern_id}`",
        f"- Verdict / status: `{card.status}`",
    ]
    if card.boundary:
        lines.append(f"- Boundary invariant (expected vulnerable behavior): {card.boundary}")
    if card.observed:
        lines.append(f"- Observed behavior: {card.observed}")
    if card.broke_at:
        lines.append(f"- Broke at: `{card.broke_at}`")
    lines.append(f"- Validator evidence: {card.evidence}")
    if card.trace_ref:
        lines.append(f"- Trace ref: `{card.trace_ref}`")
    if card.evidence_refs:
        refs = ", ".join(f"`{ref}`" for ref in card.evidence_refs)
        lines.append(f"- Artifact links: {refs}")
    else:
        lines.append(f"- Artifact: `{card.artifact}` in `{card.run_dir}`")
    if card.remediation:
        lines.append(f"- Control recommendation: {card.remediation}")
    if card.reproduce:
        lines.append(f"- Reproduce: `{card.reproduce}`")
    if card.steps:
        lines += ["", "Replay:", "", "```"]
        lines += list(card.steps)
        lines.append("```")
    lines += [
        "",
        f"> Limitation: {card.limitation or _LOCAL_LIMITATION}",
        "",
    ]
    return lines


def _cards_md(cards: list[ShowcaseCard]) -> str:
    lines = [
        "# Failure / weak-spot cards",
        "",
        "Cards are generated from artifacts. They are grouped by type, not by marketing value. "
        "Every finding card links a trace reference; no card is a hand-written summary.",
        "",
    ]
    if not cards:
        lines += [
            "No cards generated.",
            "",
            "This is an honest empty state: no recorded findings, weak spots, or adapter "
            "problems were found under the selected root.",
            "",
        ]
        return "\n".join(lines)

    for card in sorted(cards, key=lambda c: (c.card_type, c.scenario, c.pattern_id, c.card_id)):
        lines += _card_md(card)
    return "\n".join(lines)


def write_showcase(root: Path, out_dir: Path) -> dict[str, Path]:
    """Generate showcase markdown files from run artifacts."""
    manifests, cards = build_showcase(root)
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "index.md"
    cards_path = out_dir / "failure-cards.md"
    write_text_artifact(index_path, _index_md(root, manifests, cards))
    write_text_artifact(cards_path, _cards_md(cards))
    return {"index": index_path, "failure_cards": cards_path}
