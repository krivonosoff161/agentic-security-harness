from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_links_methodology_docs() -> None:
    readme = _read("README.md")
    for link in (
        "docs/evaluation-topologies.md",
        "docs/corpus-expansion-plan.md",
        "docs/agentic-boundary-model.md",
        "GOVERNANCE.md",
    ):
        assert link in readme
    assert "not just standalone model answers" in readme


def test_evaluation_topologies_cover_required_system_shapes() -> None:
    doc = _read("docs/evaluation-topologies.md")
    for phrase in (
        "Single model prompt-only",
        "Local deterministic target",
        "Vulnerable vs protected agent",
        "Agent plus memory",
        "Agent plus tools",
        "Model chain / router",
        "Multi-agent handoff",
        "Cross-provider / cross-ecosystem handoff",
        "Human approval loop",
        "Provider boundary",
        "Recovery path / escalation",
    ):
        assert phrase in doc


def test_corpus_expansion_plan_is_bounded_and_structured() -> None:
    doc = _read("docs/corpus-expansion-plan.md")
    for column in (
        "Protection / boundary model",
        "Situation family",
        "Proposed pattern id",
        "Topology needed",
        "Evidence artifact",
        "Priority",
        "Status",
    ):
        assert column in doc
    for planned_id in (
        "model_trust.weak_to_strong_escalation",
        "provider_boundary.fallback_envelope_loss",
        "recovery.trust_gate_no_path",
        "handoff.signature_scope_ignored",
    ):
        assert planned_id in doc
    assert "Full cross-products" in doc


def test_boundary_model_mentions_current_control_families() -> None:
    doc = _read("docs/agentic-boundary-model.md")
    for phrase in (
        "Data envelope boundary",
        "Provenance / source trust",
        "Authority scope boundary",
        "Tool/schema honesty boundary",
        "Memory governance boundary",
        "Provider boundary",
        "Perception trust boundary",
        "Approval context boundary",
        "Audit integrity / completeness boundary",
        "Budget / recursion boundary",
        "Model trust asymmetry",
        "Cross-agent handoff trust",
        "Recovery path / escalation",
    ):
        assert phrase in doc


def test_github_project_surface_exists() -> None:
    for path in (
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/research_pattern.yml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        "GOVERNANCE.md",
        "MAINTAINERS.md",
        "SUPPORT.md",
        "CODE_OF_CONDUCT.md",
        "CITATION.cff",
    ):
        assert (ROOT / path).is_file(), path


def test_active_docs_do_not_use_stale_pattern_count() -> None:
    for path in (
        "README.md",
        "docs/harness.md",
        "docs/development.md",
        "docs/project-map.md",
    ):
        text = _read(path).lower()
        assert "passes all 13" not in text
        assert "implements 13" not in text
