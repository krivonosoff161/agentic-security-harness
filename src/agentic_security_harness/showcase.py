"""Generate a lightweight public showcase from recorded run artifacts.

The showcase is a curated view over JSON artifacts. It never upgrades a weak spot
into a finding and it writes an honest empty state when no runs are available.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentic_security_harness.run_manifest import RunManifest, load_run_manifests
from agentic_security_harness.safe_io import write_text_artifact


@dataclass(frozen=True)
class ShowcaseCard:
    """One reviewer-facing finding / weak-spot / problem card."""

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


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _target_or_model(manifest: RunManifest) -> str:
    return manifest.target or manifest.model or str(manifest.metadata.get("model") or "")


def _external_cards(run_dir: Path, manifest: RunManifest) -> list[ShowcaseCard]:
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
        cards.append(ShowcaseCard(
            card_id=f"finding.{manifest.run_id}.{pid}",
            card_type="finding",
            run_dir=run_dir.as_posix(),
            scenario=manifest.scenario,
            target_or_model=_target_or_model(manifest),
            pattern_id=str(pid),
            status="finding",
            evidence=evidence,
            artifact="external_results.json",
            next_action="Create a failure card and one bounded deepening variation.",
        ))
    for pid in summary.get("inconclusive_patterns", []) or []:
        rows = by_pattern.get(str(pid), [])
        evidence = _first_nonempty(rows, "recovery_hint") or "model output was inconclusive"
        cards.append(ShowcaseCard(
            card_id=f"weak.{manifest.run_id}.{pid}.inconclusive",
            card_type="weak-spot",
            run_dir=run_dir.as_posix(),
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
        ))
    for pid in summary.get("error_patterns", []) or []:
        rows = by_pattern.get(str(pid), [])
        evidence = _first_nonempty(rows, "recovery_hint") or _first_nonempty(rows, "error")
        cards.append(ShowcaseCard(
            card_id=f"problem.{manifest.run_id}.{pid}.adapter_error",
            card_type="problem",
            run_dir=run_dir.as_posix(),
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
        ))
    return cards


def _run_cards(run_dir: Path, manifest: RunManifest) -> list[ShowcaseCard]:
    traces = _load_json(run_dir / "traces.json") or []
    cards: list[ShowcaseCard] = []
    for trace in traces if isinstance(traces, list) else []:
        if not isinstance(trace, dict):
            continue
        findings = trace.get("findings") or []
        if not findings:
            continue
        pid = str(trace.get("pattern_id") or "")
        finding = findings[0] if isinstance(findings[0], dict) else {}
        evidence = str(finding.get("description") or finding.get("evidence") or "finding recorded")
        cards.append(ShowcaseCard(
            card_id=f"finding.{manifest.run_id}.{pid}",
            card_type="finding",
            run_dir=run_dir.as_posix(),
            scenario=manifest.scenario,
            target_or_model=_target_or_model(manifest),
            pattern_id=pid,
            status=str(finding.get("severity") or "finding"),
            evidence=evidence,
            artifact="traces.json",
            next_action="Attach remediation and select one bounded deepening variation.",
        ))
    return cards


def _first_nonempty(rows: list[dict[str, Any]], key: str) -> str:
    for row in rows:
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def build_showcase(root: Path) -> tuple[list[tuple[Path, RunManifest]], list[ShowcaseCard]]:
    """Return discovered manifests and generated cards."""
    manifests = load_run_manifests(root)
    cards: list[ShowcaseCard] = []
    for manifest_path, manifest in manifests:
        run_dir = manifest_path.parent
        if manifest.run_kind == "external":
            cards.extend(_external_cards(run_dir, manifest))
        elif manifest.run_kind == "run":
            cards.extend(_run_cards(run_dir, manifest))
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
        f"- Source root: `{root.as_posix()}`",
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
        "- A `finding` card requires artifact evidence.",
        "- `weak-spot` and `problem` cards are not passes and not model-safety findings.",
        "- This generated page is a reviewer aid, not a certification or leaderboard.",
        "",
        "See `failure-cards.md` for the card ledger.",
        "",
    ]
    return "\n".join(lines)


def _cards_md(cards: list[ShowcaseCard]) -> str:
    lines = [
        "# Failure / weak-spot cards",
        "",
        "Cards are generated from artifacts. They are grouped by type, not by marketing value.",
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
        lines += [
            f"## {card.card_id}",
            "",
            f"- Type: `{card.card_type}`",
            f"- Scenario: `{card.scenario}`",
            f"- Target/model: `{card.target_or_model}`",
            f"- Pattern: `{card.pattern_id}`",
            f"- Status: `{card.status}`",
            f"- Run dir: `{card.run_dir}`",
            f"- Artifact: `{card.artifact}`",
            f"- Evidence: {card.evidence}",
            f"- Next action: {card.next_action}",
            "",
        ]
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
