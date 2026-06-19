import json
import shutil
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.showcase import build_showcase, write_showcase

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
    assert "Runs discovered: 0" in index
    assert "No run manifests found" in index
    assert "No cards generated" in cards


def test_showcase_builds_external_weak_spot_cards(tmp_path: Path) -> None:
    run_dir = tmp_path / "external"
    shutil.copytree(EXAMPLES / "external-demo-report", run_dir)

    manifests, cards = build_showcase(tmp_path)

    assert len(manifests) == 1
    assert cards == []  # fake server is stable pass; no weak spot or finding cards


def test_showcase_builds_run_finding_cards(tmp_path: Path) -> None:
    assert cli.main(["run", "--target", "demo-agent", "--out", str(tmp_path / "demo")]) == 0

    _, cards = build_showcase(tmp_path)

    finding_cards = [card for card in cards if card.card_type == "finding"]
    assert finding_cards
    assert any(card.pattern_id == "data_boundary_recipient_confusion" for card in finding_cards)


def test_write_showcase_outputs_markdown(tmp_path: Path) -> None:
    assert cli.main(["run", "--target", "demo-agent", "--out", str(tmp_path / "demo")]) == 0
    out = tmp_path / "showcase"

    paths = write_showcase(tmp_path, out)

    index = paths["index"].read_text(encoding="utf-8")
    cards = paths["failure_cards"].read_text(encoding="utf-8")
    assert "Runs discovered: 1" in index
    assert "finding" in index
    assert "## finding." in cards


def test_cli_showcase_writes_files(tmp_path: Path) -> None:
    assert cli.main(["run", "--target", "demo-agent", "--out", str(tmp_path / "demo")]) == 0
    out = tmp_path / "showcase"

    assert cli.main(["showcase", "--root", str(tmp_path), "--out", str(out)]) == 0

    assert (out / "index.md").exists()
    assert (out / "failure-cards.md").exists()


# --- artifact-driven failure cards (issue #21) -----------------------------------------


def _regenerate_from_committed_source(tmp_path: Path) -> Path:
    """Regenerate the showcase from a copy of the committed source run."""
    src = tmp_path / _COMMITTED_SOURCE.name
    shutil.copytree(_COMMITTED_SOURCE, src)
    out = tmp_path / "out"
    write_showcase(src, out)
    return out


def test_run_finding_card_is_artifact_driven(tmp_path: Path) -> None:
    src = tmp_path / _COMMITTED_SOURCE.name
    shutil.copytree(_COMMITTED_SOURCE, src)

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
