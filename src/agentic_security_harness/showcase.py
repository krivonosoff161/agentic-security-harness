"""Generate a lightweight public showcase from recorded run artifacts.

The showcase is a curated view over JSON artifacts. It never upgrades a weak spot
into a finding and it writes an honest empty state when no runs are available.

Failure cards are *artifact-driven*: every field is read from a recorded trace /
scorecard / external artifact. The generator never writes a marketing summary that is not
backed by a trace reference, and every card carries an explicit limitation / non-claim.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.run_manifest import (
    RunManifest,
    ValidatedRunRecord,
    build_manifest,
    expectation_validator_fingerprint,
    load_validated_run_records,
    write_run_manifest,
)
from agentic_security_harness.safe_io import (
    atomic_evidence_bundle,
    redact_artifact_text,
    require_fresh_output_dir,
    write_text_artifact,
)
from agentic_security_harness.safe_terminal import terminal_field
from agentic_security_harness.schema_versions import CORPUS_VERSION, SCHEMA_VERSIONS
from agentic_security_harness.version import __version__

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


_MARKDOWN_PUNCTUATION = re.compile(r"([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])")


class ShowcaseCard(BaseModel):
    """One reviewer-facing finding / weak-spot / problem card.

    The first block of fields is the stable card identity; the second block is the
    artifact-driven replay detail (populated from trace artifacts where available).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    card_id: str
    source_run_id: str
    source_run_label: str
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
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple)
    steps: tuple[str, ...] = Field(default_factory=tuple)


class ShowcaseSource(BaseModel):
    """Portable commitment to one validated source bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    run_label: str
    run_kind: str
    scenario: str = ""
    target_or_model: str = ""
    outcomes: dict[str, int] = Field(default_factory=dict)
    expectation_status: Literal["ok", "mismatch", "not_recorded"] = "not_recorded"
    expectation_mismatch_count: int = 0
    manifest_schema_version: str
    manifest_sha256: str
    artifact_validation: str = "current_content_bound"
    origin_authentication: str = "unsigned"


class ShowcaseBundle(BaseModel):
    """Authoritative structured projection behind the two Markdown views."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSIONS["showcase"]
    source_root: str
    expectation_validation_scope: Literal[
        "independently_recomputed_at_generation", "not_recorded"
    ] = "not_recorded"
    validator_tool_version: str = ""
    corpus_version: str = ""
    validator_source_fingerprint: str = ""
    sources: list[ShowcaseSource] = Field(default_factory=list)
    cards: list[ShowcaseCard] = Field(default_factory=list)


def _md_text(value: object) -> str:
    """Render untrusted scalar text as one inert CommonMark text line."""

    one_line = terminal_field(redact_artifact_text(str(value or "")))
    one_line = " ".join(one_line.split())
    return _MARKDOWN_PUNCTUATION.sub(r"\\\1", one_line)


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
            source_run_id=manifest.run_id,
            source_run_label=run_rel,
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
            source_run_id=manifest.run_id,
            source_run_label=run_rel,
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
            source_run_id=manifest.run_id,
            source_run_label=run_rel,
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
            source_run_id=manifest.run_id,
            source_run_label=run_rel,
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


def _build_showcase_records(
    root: Path,
) -> tuple[list[ValidatedRunRecord], list[ShowcaseCard]]:
    records = [
        record
        for record in load_validated_run_records(root)
        if record.manifest.run_kind in {"run", "external"}
    ]
    cards: list[ShowcaseCard] = []
    for record in records:
        manifest = record.manifest
        run_dir = record.path.parent
        run_rel = _run_rel(root, run_dir)
        if manifest.run_kind == "external":
            cards.extend(_external_cards(run_dir, manifest, run_rel))
        elif manifest.run_kind == "run":
            cards.extend(_run_cards(run_dir, manifest, run_rel))
    return records, cards


def build_showcase(root: Path) -> tuple[list[tuple[Path, RunManifest]], list[ShowcaseCard]]:
    """Return validated manifests and cards generated only from validated artifacts."""

    records, cards = _build_showcase_records(root)
    return [(record.path, record.manifest) for record in records], cards


def build_showcase_bundle(root: Path) -> ShowcaseBundle:
    """Build a portable, source-manifest-bound showcase projection."""

    records, cards = _build_showcase_records(root)
    validator_fingerprints = {
        record.validator_source_fingerprint for record in records
    }
    if len(validator_fingerprints) > 1:
        raise ValueError("showcase sources came from mixed validator source snapshots")
    validator_fingerprint = (
        next(iter(validator_fingerprints))
        if validator_fingerprints
        else expectation_validator_fingerprint()
    )
    sources = [
        ShowcaseSource(
            run_id=record.manifest.run_id,
            run_label=_run_rel(root, record.path.parent),
            run_kind=record.manifest.run_kind,
            scenario=record.manifest.scenario,
            target_or_model=_target_or_model(record.manifest),
            outcomes=dict(sorted(record.manifest.outcomes.items())),
            expectation_status=("ok" if record.expectations_ok else "mismatch"),
            expectation_mismatch_count=record.expectation_mismatch_count,
            manifest_schema_version=record.manifest.schema_version,
            manifest_sha256=record.manifest_sha256,
        )
        for record in records
    ]
    bundle = ShowcaseBundle(
        source_root=root.resolve(strict=False).name or ".",
        expectation_validation_scope="independently_recomputed_at_generation",
        validator_tool_version=__version__,
        corpus_version=CORPUS_VERSION,
        validator_source_fingerprint=validator_fingerprint,
        sources=sources,
        cards=cards,
    )
    errors = validate_showcase_projection(bundle)
    if errors:
        raise ValueError("invalid showcase projection: " + "; ".join(errors))
    return bundle


def validate_showcase_projection(bundle: ShowcaseBundle) -> list[str]:
    """Validate portable source commitments and card/source referential integrity."""

    errors: list[str] = []
    if bundle.schema_version == SCHEMA_VERSIONS["showcase"]:
        if bundle.expectation_validation_scope != "independently_recomputed_at_generation":
            errors.append("current showcase requires independently recomputed expectation status")
        if not bundle.validator_tool_version or not bundle.corpus_version:
            errors.append("current showcase requires validator and corpus version provenance")
        if not re.fullmatch(r"[0-9a-f]{64}", bundle.validator_source_fingerprint):
            errors.append("current showcase requires a SHA-256 validator source fingerprint")
    elif bundle.schema_version == "0.1":
        if (
            bundle.expectation_validation_scope != "not_recorded"
            or bundle.validator_tool_version
            or bundle.corpus_version
            or bundle.validator_source_fingerprint
        ):
            errors.append("legacy showcase cannot claim expectation-validation provenance")
    root_path = Path(bundle.source_root)
    if (
        not bundle.source_root
        or root_path.is_absolute()
        or len(root_path.parts) != 1
        or bundle.source_root in {".", ".."}
    ):
        errors.append("source_root must be a portable single-component label")
    source_keys: set[tuple[str, str]] = set()
    for source in bundle.sources:
        key = (source.run_id, source.run_label)
        if key in source_keys:
            errors.append(f"duplicate source identity: {source.run_id}/{source.run_label}")
        source_keys.add(key)
        if source.run_kind not in {"run", "external"}:
            errors.append(f"{source.run_id}: unsupported showcase source kind")
        if source.manifest_schema_version != SCHEMA_VERSIONS["run_manifest"]:
            errors.append(f"{source.run_id}: source manifest is not current")
        if not re.fullmatch(r"[0-9a-f]{64}", source.manifest_sha256):
            errors.append(f"{source.run_id}: manifest_sha256 is not SHA-256")
        if source.artifact_validation != "current_content_bound":
            errors.append(f"{source.run_id}: artifact_validation is not current_content_bound")
        if source.origin_authentication != "unsigned":
            errors.append(f"{source.run_id}: origin_authentication must be unsigned")
        if source.expectation_status == "ok" and source.expectation_mismatch_count != 0:
            errors.append(f"{source.run_id}: ok expectation status cannot have mismatches")
        if source.expectation_status == "mismatch" and source.expectation_mismatch_count < 1:
            errors.append(f"{source.run_id}: mismatch status requires a positive count")
        if source.expectation_status == "not_recorded" and source.expectation_mismatch_count != 0:
            errors.append(f"{source.run_id}: unrecorded expectation status cannot have a count")
        if bundle.schema_version == SCHEMA_VERSIONS["showcase"]:
            if source.expectation_status == "not_recorded":
                errors.append(f"{source.run_id}: current showcase requires expectation status")
        elif bundle.schema_version == "0.1" and source.expectation_status != "not_recorded":
            errors.append(f"{source.run_id}: legacy showcase cannot claim expectation status")
        if any(value < 0 for value in source.outcomes.values()):
            errors.append(f"{source.run_id}: outcomes contain a negative count")
        if not _portable_reference(source.run_label, allow_current=True):
            errors.append(f"{source.run_id}: run_label is not portable")
    card_ids: set[str] = set()
    for card in bundle.cards:
        if card.card_id in card_ids:
            errors.append(f"duplicate card_id: {card.card_id}")
        card_ids.add(card.card_id)
        if (card.source_run_id, card.source_run_label) not in source_keys:
            errors.append(f"{card.card_id}: card source is not declared")
        if card.card_type not in {"finding", "weak-spot", "problem"}:
            errors.append(f"{card.card_id}: unsupported card_type")
        for ref in card.evidence_refs:
            if not _portable_reference(ref):
                errors.append(f"{card.card_id}: evidence reference is not portable")
    return errors


def _portable_reference(value: str, *, allow_current: bool = False) -> bool:
    path_text = value.split("#", 1)[0]
    if allow_current and path_text in {"", "."}:
        return True
    path = PurePosixPath(path_text)
    return bool(path_text) and not path.is_absolute() and ".." not in path.parts


def _index_md(
    schema_version: str,
    source_root: str,
    sources: list[ShowcaseSource],
    cards: list[ShowcaseCard],
) -> str:
    lines = [
        "# Agentic Security Harness - generated showcase",
        "",
        "Generated from current content-bound validated run artifacts. JSON artifacts remain "
        "the source of truth.",
        "",
        f"- Source root: {_md_text(source_root)}",
        f"- Current content-bound runs: {len(sources)}",
        f"- Cards generated: {len(cards)}",
    ]
    if schema_version != "0.1":
        lines += [
            "- Behavioral expectation status: independently recomputed at generation",
            "",
        ]
    else:
        lines.append("")
    lines += ["## Run summary", ""]
    if not sources:
        lines += [
            "No current content-bound validated run manifests found.",
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
        if schema_version == "0.1":
            lines += [
                "| Run | Kind | Scenario | Target/model | Outcomes |",
                "|---|---|---|---|---|",
            ]
        else:
            lines += [
                "| Run | Kind | Scenario | Target/model | Expectations | Outcomes |",
                "|---|---|---|---|---|---|",
            ]
        for source in sources:
            outcomes = ", ".join(
                f"{_md_text(k)}={v}" for k, v in sorted(source.outcomes.items())
            )
            prefix = (
                f"| {_md_text(source.run_id)} | {_md_text(source.run_kind)} | "
                f"{_md_text(source.scenario)} | {_md_text(source.target_or_model)} | "
            )
            if schema_version == "0.1":
                lines.append(f"{prefix}{outcomes or '-'} |")
            else:
                lines.append(
                    f"{prefix}{_md_text(source.expectation_status)}"
                    f" ({source.expectation_mismatch_count}) | {outcomes or '-'} |"
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
        f"## {_md_text(card.card_id)}",
        "",
        f"- Failure class: {_md_text(card.failure_class or card.card_type)}",
        f"- Type: {_md_text(card.card_type)}",
        f"- Scenario / family: {_md_text(card.scenario)} / {_md_text(card.control_family)}",
        f"- Target/model: {_md_text(card.target_or_model)}",
        f"- Pattern: {_md_text(card.pattern_id)}",
        f"- Verdict / status: {_md_text(card.status)}",
    ]
    if card.boundary:
        lines.append(
            "- Boundary invariant (expected vulnerable behavior): "
            + _md_text(card.boundary)
        )
    if card.observed:
        lines.append(f"- Observed behavior: {_md_text(card.observed)}")
    if card.broke_at:
        lines.append(f"- Broke at: {_md_text(card.broke_at)}")
    lines.append(f"- Validator evidence: {_md_text(card.evidence)}")
    if card.trace_ref:
        lines.append(f"- Trace ref: {_md_text(card.trace_ref)}")
    if card.evidence_refs:
        refs = ", ".join(_md_text(ref) for ref in card.evidence_refs)
        lines.append(f"- Artifact links: {refs}")
    else:
        lines.append(
            f"- Artifact: {_md_text(card.artifact)} in {_md_text(card.run_dir)}"
        )
    if card.remediation:
        lines.append(f"- Control recommendation: {_md_text(card.remediation)}")
    if card.reproduce:
        lines.append(f"- Reproduce: {_md_text(card.reproduce)}")
    if card.steps:
        lines += ["", "Replay:", ""]
        lines += [f"- {_md_text(step)}" for step in card.steps]
    lines += [
        "",
        f"> Limitation: {_md_text(card.limitation or _LOCAL_LIMITATION)}",
        "",
    ]
    return lines


def _cards_md(cards: list[ShowcaseCard]) -> str:
    lines = [
        "# Failure / weak-spot cards",
        "",
        "Cards are generated from current content-bound validated artifacts. They are grouped by "
        "type, not by marketing value. Every finding card links a trace reference; no card is a "
        "hand-written summary.",
        "",
    ]
    if not cards:
        lines += [
            "No cards generated.",
            "",
            "No eligible current content-bound run produced cards. This empty view does not mean "
            "that no findings, weak spots, or adapter problems exist.",
            "",
        ]
        return "\n".join(lines)

    for card in sorted(cards, key=lambda c: (c.card_type, c.scenario, c.pattern_id, c.card_id)):
        lines += _card_md(card)
    return "\n".join(lines)


def showcase_manifest_projection(bundle: ShowcaseBundle) -> dict[str, object]:
    counts = Counter(card.card_type.replace("-", "_") for card in bundle.cards)
    outcomes = {
        "source_runs": len(bundle.sources),
        "cards": len(bundle.cards),
        **dict(sorted(counts.items())),
    }
    if bundle.schema_version != "0.1":
        outcomes.update({
            "expectations_ok_runs": sum(
                source.expectation_status == "ok" for source in bundle.sources
            ),
            "expectation_mismatch_runs": sum(
                source.expectation_status == "mismatch" for source in bundle.sources
            ),
            "expectation_mismatches": sum(
                source.expectation_mismatch_count for source in bundle.sources
            ),
        })
    metadata = {
        "artifact_validation": "current_content_bound",
        "origin_authentication": "unsigned",
    }
    if bundle.schema_version != "0.1":
        metadata.update({
            "expectation_validation_scope": bundle.expectation_validation_scope,
            "validator_tool_version": bundle.validator_tool_version,
            "corpus_version": bundle.corpus_version,
            "validator_source_fingerprint": bundle.validator_source_fingerprint,
        })
    return {
        "target": "validated-public-evidence-showcase",
        "scenario": bundle.source_root,
        "outcomes": outcomes,
        "metadata": metadata,
    }


def _showcase_output_overlaps_sources(
    out_dir: Path, manifests: list[tuple[Path, RunManifest]]
) -> bool:
    resolved_out = out_dir.resolve(strict=False)
    for manifest_path, _manifest in manifests:
        source = manifest_path.parent.resolve(strict=False)
        if (
            resolved_out == source
            or resolved_out in source.parents
            or source in resolved_out.parents
        ):
            return True
    return False


@atomic_evidence_bundle("out_dir")
def write_showcase(root: Path, out_dir: Path) -> dict[str, Path]:
    """Generate a source-bound showcase bundle without touching source runs."""

    manifests, _cards = build_showcase(root)
    if _showcase_output_overlaps_sources(out_dir, manifests):
        raise ValueError("showcase output must not equal, contain, or be inside a source run")
    require_fresh_output_dir(out_dir)
    bundle = build_showcase_bundle(root)
    projection_errors = validate_showcase_projection(bundle)
    if projection_errors:
        raise ValueError(
            "refusing to persist invalid showcase projection: "
            + "; ".join(projection_errors)
        )
    targets = [
        out_dir / "showcase.json",
        out_dir / "index.md",
        out_dir / "failure-cards.md",
        out_dir / "run_index.json",
    ]
    if any(target.is_symlink() for target in targets):
        raise ValueError("showcase output files must not be symbolic links")

    json_text = json.dumps(bundle.model_dump(mode="json"), indent=2) + "\n"
    index_text = _index_md(
        bundle.schema_version,
        bundle.source_root,
        bundle.sources,
        bundle.cards,
    )
    cards_text = _cards_md(bundle.cards)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "showcase.json"
    index_path = out_dir / "index.md"
    cards_path = out_dir / "failure-cards.md"
    write_text_artifact(json_path, json_text)
    write_text_artifact(index_path, index_text)
    write_text_artifact(cards_path, cards_text)
    projection = showcase_manifest_projection(bundle)
    manifest = build_manifest(
        "showcase",
        out_dir,
        target=str(projection["target"]),
        scenario=str(projection["scenario"]),
        outcomes=projection["outcomes"],  # type: ignore[arg-type]
        metadata=projection["metadata"],  # type: ignore[arg-type]
        artifacts=["showcase.json", "index.md", "failure-cards.md"],
    )
    manifest_path = write_run_manifest(out_dir, manifest)
    return {
        "json": json_path,
        "index": index_path,
        "failure_cards": cards_path,
        "run_index": manifest_path,
    }
