import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from agentic_security_harness import cli
from agentic_security_harness.run_manifest import (
    build_manifest,
    load_validated_run_records,
    write_run_manifest,
)
from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.showcase import (
    ShowcaseBundle,
    ShowcaseSource,
    _cards_md,
    _index_md,
    build_showcase,
    build_showcase_bundle,
    showcase_manifest_projection,
    write_showcase,
)
from agentic_security_harness.validation import validate_path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
GENERATED = ROOT / "docs" / "showcase" / "generated"

# Source run for the committed generated showcase example (issue #21 exit gate).
_COMMITTED_SOURCE = EXAMPLES / "demo-agent-report"

# Overclaim phrases that must never appear in generated public showcase text. These do not
# occur in legitimate negations ("not a certification or leaderboard" is fine).
_FORBIDDEN = (
    "complete protection",
    "fully secure",
    "provably secure",
    "mathematically proven",
    "100% secure",
    "guarantees security",
    "first and only",
    "production certified",
)


def test_showcase_empty_state(tmp_path: Path) -> None:
    out = tmp_path / "showcase"

    paths = write_showcase(tmp_path / "missing", out)

    index = paths["index"].read_text(encoding="utf-8")
    cards = paths["failure_cards"].read_text(encoding="utf-8")
    assert "Current content-bound runs: 0" in index
    assert "No current content-bound validated run manifests found" in index
    assert "No cards generated" in cards


def test_showcase_builds_external_weak_spot_cards(tmp_path: Path) -> None:
    run_dir = tmp_path / "external"
    shutil.copytree(EXAMPLES / "external-demo-report", run_dir)

    manifests, cards = build_showcase(tmp_path)

    assert manifests == []  # legacy manifest has no persisted-byte content binding
    assert cards == []  # fake server is stable pass; no weak spot or finding cards


def test_showcase_builds_run_finding_cards(tmp_path: Path) -> None:
    assert cli.main(["run", "--target", "demo-agent", "--out", str(tmp_path / "demo")]) == 0

    _, cards = build_showcase(tmp_path)

    finding_cards = [card for card in cards if card.card_type == "finding"]
    assert finding_cards
    assert any(card.pattern_id == "data_boundary_recipient_confusion" for card in finding_cards)


def test_showcase_carries_validated_record_expectation_mismatch(tmp_path: Path) -> None:
    run_dir = tmp_path / "demo"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(run_dir)]) == 0
    record = load_validated_run_records(run_dir)[0]
    adverse = replace(record, expectations_ok=False, expectation_mismatch_count=2)

    with patch(
        "agentic_security_harness.showcase.load_validated_run_records",
        return_value=[adverse],
    ):
        bundle = build_showcase_bundle(run_dir)

    assert bundle.sources[0].expectation_status == "mismatch"
    assert bundle.sources[0].expectation_mismatch_count == 2
    projection = showcase_manifest_projection(bundle)
    assert projection["outcomes"]["expectation_mismatch_runs"] == 1  # type: ignore[index]
    assert projection["outcomes"]["expectation_mismatches"] == 2  # type: ignore[index]


def test_write_showcase_outputs_markdown(tmp_path: Path) -> None:
    assert cli.main(["run", "--target", "demo-agent", "--out", str(tmp_path / "demo")]) == 0
    out = tmp_path / "showcase"

    paths = write_showcase(tmp_path, out)

    index = paths["index"].read_text(encoding="utf-8")
    cards = paths["failure_cards"].read_text(encoding="utf-8")
    assert "Current content-bound runs: 1" in index
    assert "finding" in index
    assert "## finding\\." in cards
    assert paths["json"].exists()
    assert paths["run_index"].exists()
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert payload["schema_version"] == "0.2"
    assert payload["expectation_validation_scope"] == (
        "independently_recomputed_at_generation"
    )
    assert len(payload["validator_source_fingerprint"]) == 64
    assert payload["sources"][0]["expectation_status"] == "ok"
    assert validate_path(out).ok


def test_nonempty_legacy_showcase_bundle_retains_v01_projection(tmp_path: Path) -> None:
    out = tmp_path / "legacy-showcase"
    out.mkdir()
    bundle = ShowcaseBundle(
        schema_version="0.1",
        source_root="legacy-root",
        sources=[
            ShowcaseSource(
                run_id="run_legacy",
                run_label="legacy-run",
                run_kind="run",
                scenario="legacy",
                target_or_model="legacy-target",
                outcomes={"failed": 1},
                manifest_schema_version="0.3",
                manifest_sha256="b" * 64,
            )
        ],
    )
    write_text_artifact(out / "showcase.json", bundle.model_dump_json(indent=2))
    write_text_artifact(
        out / "index.md",
        _index_md(bundle.schema_version, bundle.source_root, bundle.sources, bundle.cards),
    )
    write_text_artifact(out / "failure-cards.md", _cards_md(bundle.cards))
    projection = showcase_manifest_projection(bundle)
    write_run_manifest(
        out,
        build_manifest(
            "showcase",
            out,
            target=str(projection["target"]),
            scenario=str(projection["scenario"]),
            outcomes=projection["outcomes"],  # type: ignore[arg-type]
            metadata=projection["metadata"],  # type: ignore[arg-type]
            artifacts=["failure-cards.md", "index.md", "showcase.json"],
        ),
    )

    result = validate_path(out)

    assert result.ok, result.errors
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "| Run | Kind | Scenario | Target/model | Outcomes |" in index
    assert "Expectations" not in index


def test_cli_showcase_writes_files(tmp_path: Path) -> None:
    assert cli.main(["run", "--target", "demo-agent", "--out", str(tmp_path / "demo")]) == 0
    out = tmp_path / "showcase"

    assert cli.main(["showcase", "--root", str(tmp_path), "--out", str(out)]) == 0

    assert (out / "index.md").exists()
    assert (out / "failure-cards.md").exists()
    assert (out / "showcase.json").exists()
    assert (out / "run_index.json").exists()


def test_showcase_neutralizes_stored_markdown_from_validated_trace(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(run_dir)]) == 0
    traces_path = run_dir / "traces.json"
    traces = json.loads(traces_path.read_text(encoding="utf-8"))
    traces[0]["findings"][0]["message"] = (
        "evidence\n\n## Forged pass\n![probe](https://example.invalid/p.gif)"
        "\n<img src=https://example.invalid/p.gif>\x1b[31m\u202efake.exe"
    )
    traces_path.write_text(json.dumps(traces, indent=2) + "\n", encoding="utf-8")
    manifest_path = run_dir / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["traces.json"] = hashlib.sha256(
        traces_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    assert validate_path(run_dir).ok

    out = tmp_path / "showcase"
    write_showcase(run_dir, out)
    rendered = (out / "failure-cards.md").read_text(encoding="utf-8")

    assert "## Forged pass" not in rendered
    assert "![probe](" not in rendered
    assert "\\#\\# Forged pass" in rendered
    assert "\\!\\[probe\\]\\(" in rendered
    assert "\\<img src" in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "\\\\x1b" in rendered
    assert "\\\\u202e" in rendered


def test_cli_showcase_refuses_source_output_overlap_without_mutation(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(run_dir)]) == 0
    before = {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in run_dir.rglob("*")
        if path.is_file()
    }

    assert cli.main(["showcase", "--root", str(run_dir), "--out", str(run_dir)]) == 1

    after = {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_showcase_exact_markdown_validation_rejects_rehashed_claim_tamper(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(run_dir)]) == 0
    out = tmp_path / "showcase"
    write_showcase(run_dir, out)
    cards_path = out / "failure-cards.md"
    cards_path.write_text(
        cards_path.read_text(encoding="utf-8") + "\nForged claim.\n",
        encoding="utf-8",
    )
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["failure-cards.md"] = hashlib.sha256(
        cards_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("report projection mismatch" in error for error in result.errors)


def test_showcase_rejects_rehashed_expectation_status_tamper(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(run_dir)]) == 0
    out = tmp_path / "showcase"
    write_showcase(run_dir, out)
    json_path = out / "showcase.json"
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    payload["sources"][0]["expectation_mismatch_count"] = 1
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest_path = out / "run_index.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["showcase.json"] = hashlib.sha256(
        json_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.integrity_ok
    assert any("ok expectation status cannot have mismatches" in error for error in result.errors)


# --- artifact-driven failure cards (issue #21) -----------------------------------------


def _regenerate_from_committed_source(tmp_path: Path) -> Path:
    """Regenerate the showcase from a copy of the committed source run."""
    src = tmp_path / _COMMITTED_SOURCE.name
    shutil.copytree(_COMMITTED_SOURCE, src)
    out = tmp_path / "out"
    write_showcase(src, out)
    return out


def test_run_finding_card_is_artifact_driven(tmp_path: Path) -> None:
    src = tmp_path / "current-demo"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(src)]) == 0

    _, cards = build_showcase(src)

    card = next(c for c in cards if c.pattern_id == "data_boundary_recipient_confusion")
    # Every field is pulled from the trace, not hand-written.
    assert card.trace_ref  # links a specific trace
    assert any("traces.json#" in ref for ref in card.evidence_refs)
    assert card.boundary and card.observed  # boundary invariant + observed behavior
    assert card.broke_at == "recipient_check"
    assert card.remediation  # control recommendation from the finding mitigation
    assert card.reproduce.startswith("ash run --target demo-agent")
    assert card.steps  # trace replay present
    assert card.limitation  # explicit non-claim


def test_card_not_built_from_empty_or_invalid_artifact(tmp_path: Path) -> None:
    # A run manifest with no findings -> no cards (not an upgraded weak spot).
    empty = tmp_path / "empty"
    empty.mkdir()
    cli.main(["run", "--target", "protected-demo-agent", "--out", str(empty)])
    _, cards = build_showcase(empty)
    assert cards == []

    # Invalid/garbage traces.json under a manifest -> graceful, no cards, no crash.
    broken = tmp_path / "broken"
    shutil.copytree(_COMMITTED_SOURCE, broken)
    (broken / "traces.json").write_text("{ not valid json", encoding="utf-8")
    _, broken_cards = build_showcase(broken)
    assert broken_cards == []


def test_showcase_rejects_parseable_artifact_with_manifest_hash_mismatch(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "tampered"
    assert cli.main(["run", "--target", "demo-agent", "--out", str(run_dir)]) == 0
    traces_path = run_dir / "traces.json"
    traces = json.loads(traces_path.read_text(encoding="utf-8"))
    traces[0]["findings"][0]["message"] = "rewritten showcase evidence"
    traces_path.write_text(json.dumps(traces, indent=2) + "\n", encoding="utf-8")

    manifests, cards = build_showcase(run_dir)

    assert manifests == []
    assert cards == []


def test_generated_cards_have_no_overclaim_phrases(tmp_path: Path) -> None:
    out = _regenerate_from_committed_source(tmp_path)
    text = (
        (out / "failure-cards.md").read_text(encoding="utf-8").lower()
        + (out / "index.md").read_text(encoding="utf-8").lower()
    )
    for phrase in _FORBIDDEN:
        assert phrase not in text, phrase
    # Each finding card must carry an explicit limitation / non-claim.
    cards_md = (out / "failure-cards.md").read_text(encoding="utf-8")
    assert cards_md.count("> Limitation:") == cards_md.count("## finding.")


def test_committed_generated_showcase_is_reproducible(tmp_path: Path) -> None:
    # The committed docs/showcase/generated/* must be byte-reproducible from the committed
    # source run, so the public example is generated, never hand-edited.
    out = _regenerate_from_committed_source(tmp_path)
    for name in ("index.md", "failure-cards.md"):
        assert (out / name).read_text(encoding="utf-8") == (
            GENERATED / name
        ).read_text(encoding="utf-8"), name


def test_committed_source_has_manifest_and_findings() -> None:
    # Guard the committed example so the showcase has something to generate from.
    manifest = json.loads((_COMMITTED_SOURCE / "run_index.json").read_text(encoding="utf-8"))
    assert manifest["run_kind"] == "run"
    assert manifest["outcomes"]["failed"] > 0
    assert manifest["schema_version"] == "0.1"
    manifests, cards = build_showcase(_COMMITTED_SOURCE)
    assert manifests == []
    assert cards == []
