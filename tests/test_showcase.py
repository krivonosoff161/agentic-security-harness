import shutil
from pathlib import Path

from agentic_security_harness import cli
from agentic_security_harness.showcase import build_showcase, write_showcase

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


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
