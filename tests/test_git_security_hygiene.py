import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sensitive_local_artifact_classes_are_ignored() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    required = (
        ".env.*",
        "!.env.example",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "credentials*.json",
        "secrets*.json",
        "private-traces/",
        "raw-model-responses/",
        "private-evidence/",
        "provider-responses/",
        "runtime-logs/",
        ".codex/",
        ".internal/",
    )
    assert all(pattern in ignore for pattern in required)
    for path in (
        ".env.local",
        "credentials-export.json",
        "signing.key",
        "certificate.pem",
        "runtime-logs/current.log",
        "provider-responses/result.json",
        "private-evidence/receipt.json",
    ):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", path],
            cwd=ROOT,
            check=False,
        )
        assert result.returncode == 0, path
    example = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", ".env.example"],
        cwd=ROOT,
        check=False,
    )
    assert example.returncode == 1


def test_gitleaks_allowlist_contains_only_exact_historical_fingerprints() -> None:
    lines = [
        line.strip()
        for line in (ROOT / ".gitleaksignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert set(lines) == {
        "a91e9d3ff3f8b859cfdca749afd269670e78c70b:tests/test_semantic_drift_campaign.py:generic-api-key:449",
        "b782054c25f5a4990a64b2ae56987bd383d14f33:tests/test_semantic_drift_campaign.py:generic-api-key:449",
        "8a9b43c8d227827788d815866e4013b1be2f795f:src/agentic_security_harness/reconciliation.py:generic-api-key:117",
        "ef55233d83579bcb8e13f199976fece7c76236a6:src/agentic_security_harness/reconciliation.py:generic-api-key:117",
        "515a356aa9316997eb586a8ad8d1cccfff36f954:tests/test_html_report.py:generic-api-key:124",
        "515a356aa9316997eb586a8ad8d1cccfff36f954:tests/test_external.py:generic-api-key:533",
        "515a356aa9316997eb586a8ad8d1cccfff36f954:tests/test_external.py:generic-api-key:555",
        "73054aeef732e49ec30c0398db5ae36f4be7b192:tests/test_local_suite.py:generic-api-key:156",
    }
    assert all(re.fullmatch(r"[0-9a-f]{40}:[^:*]+:generic-api-key:\d+", line) for line in lines)


def test_secret_scan_is_pinned_and_does_not_publish_findings() -> None:
    workflow = (ROOT / ".github/workflows/gitleaks.yml").read_text(encoding="utf-8")
    assert (
        "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e"
        in workflow
    )
    assert 'GITLEAKS_VERSION: "8.30.1"' in workflow
    assert 'GITLEAKS_ENABLE_COMMENTS: "false"' in workflow
    assert 'GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "false"' in workflow
    assert 'GITLEAKS_ENABLE_SUMMARY: "false"' in workflow
    assert "persist-credentials: false" in workflow


def test_portfolio_contract_and_model_assistance_are_visible() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pull_request_template = (
        ROOT / ".github/PULL_REQUEST_TEMPLATE.md"
    ).read_text(encoding="utf-8")
    governance = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")

    for path in (
        "docs/threat-ontology.md",
        "docs/scenario-adjudication-ledger.md",
        "docs/unified-event-envelope.md",
    ):
        assert path in readme
    assert "not 127 canonical attacks" in readme
    assert "not a repository-wide total" in readme
    assert "Model or agent assistance" in pull_request_template
    assert "external language models" in governance
    assert "Model agreement is not independent validation" in governance
