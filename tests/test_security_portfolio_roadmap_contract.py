from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "security-portfolio-roadmap-contract.json"
DOCUMENT = ROOT / "docs" / "security-portfolio-roadmap.md"


def test_security_portfolio_contract_is_self_contained_and_digest_bound() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["schema_version"] == "SecurityPortfolioLocalContract.v2"
    assert contract["repository_id"] == "agentic-security-harness"
    path = (ROOT / contract["vendored_projection_path"]).resolve()
    assert ROOT.resolve() in path.parents and path.is_file() and not path.is_symlink()
    raw = path.read_bytes()
    assert len(raw) == contract["public_projection_size"]
    assert hashlib.sha256(raw).hexdigest() == contract["public_projection_sha256"]
    projection = json.loads(raw)
    assert projection["schema_version"] == "SecurityPortfolioRoadmapPublic.v1"
    assert projection["roadmap_version"] == contract["roadmap_version"]
    assert projection["source_sha256"] == contract["upstream_private_source_sha256"]
    assert projection["authority"] == contract["authority"] == "none"
    repository = next(
        item for item in projection["repositories"] if item["id"] == contract["repository_id"]
    )
    assert repository["roadmap_authority"] == contract["roadmap_authority"]
    owned = [
        {"id": item["id"], "status": item["status"]}
        for item in projection["modules"]
        if item["owner"] == contract["repository_id"]
    ]
    forbidden = sorted(
        {
            claim
            for item in projection["modules"]
            if item["owner"] == contract["repository_id"]
            for claim in item["forbidden_claims"]
        }
        | {"operational_authority"}
    )
    assert contract["owned_modules"] == owned
    assert contract["forbidden_promotions"] == forbidden
    assert all(
        projection["status_profiles"][item["status"]]["authority"] == contract["authority"]
        for item in owned
    )


def test_human_contract_matches_machine_pin() -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    document = DOCUMENT.read_text(encoding="utf-8")
    assert value["roadmap_version"] in document
    assert all(
        item["id"] in document and item["status"] in document
        for item in value["owned_modules"]
    )
    assert "Authority: `none`" in document
