from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_links_methodology_docs() -> None:
    readme = _read("README.md")
    for link in (
        "docs/current-state.md",
        "docs/authorized-testing-paths.md",
        "docs/evaluation-topologies.md",
        "docs/corpus-expansion-plan.md",
        "docs/agentic-boundary-model.md",
        "docs/project-tracker.md",
        "docs/metric-contract.md",
        "docs/local-prometheus-workflow.md",
        "docs/local-model-profiles.md",
        "docs/scenario-timeline.md",
        "docs/showcase/index.md",
        "docs/showcase/scenario-matrix.md",
        "docs/showcase/weak-spots-and-findings.md",
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


def test_status_and_authorization_docs_are_canonical() -> None:
    current_state = _read("docs/current-state.md")
    authorized_paths = _read("docs/authorized-testing-paths.md")
    project_map = _read("docs/project-map.md")
    release_checklist = _read("docs/release-checklist.md")

    for phrase in (
        "Shipped and verified",
        "Experimental",
        "Planned, not shipped",
        "Current active work",
        "Claim boundary",
    ):
        assert phrase in current_state

    for phrase in (
        "Demo synthetic lab",
        "Local runtime lab",
        "Owned system assessment",
        "Provider bug bounty / safe harbor",
        "Standards-aligned benchmark",
    ):
        assert phrase in authorized_paths

    assert "current-state.md" in project_map
    assert "authorized-testing-paths.md" in project_map
    assert "project-tracker.md" in project_map
    assert "metric-contract.md" in project_map
    assert "local-prometheus-workflow.md" in project_map
    assert "local-model-profiles.md" in project_map
    assert "scenario-timeline.md" in project_map
    assert "showcase/index.md" in project_map
    assert "docs/current-state.md" in release_checklist
    assert "docs/authorized-testing-paths.md" in release_checklist


def test_showcase_separates_weak_spots_findings_and_deepening() -> None:
    index = _read("docs/showcase/index.md")
    weak = _read("docs/showcase/weak-spots-and-findings.md")
    deepening = _read("docs/showcase/deepening-backlog.md")
    workflow = _read("docs/scenario-investigation-workflow.md")
    timeline = _read("docs/scenario-timeline.md")
    profiles = _read("docs/local-model-profiles.md")

    for phrase in (
        "Scenario matrix",
        "Weak spots and findings",
        "Deepening backlog",
        "local Prometheus",
    ):
        assert phrase in index

    for phrase in (
        "Current weak spots",
        "Current confirmed findings",
        "Current non-findings",
        "Promotion rule",
    ):
        assert phrase in weak

    for phrase in (
        "Active deepening candidates",
        "Variation budget",
        "Not scheduled",
    ):
        assert phrase in deepening

    for phrase in (
        "scenario family",
        "weak spot",
        "finding",
        "Deepening variation rules",
    ):
        assert phrase in workflow

    for phrase in (
        "timeline_id",
        "trust_zone",
        "validators",
        "First timeline candidates",
    ):
        assert phrase in timeline

    for phrase in (
        "prometheus-lowmem-smoke",
        "qwen2.5:1.5b",
        "Stop conditions",
        "adapter_error",
    ):
        assert phrase in profiles


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


def test_toy_multi_agent_status_is_documented_as_shipped() -> None:
    required_docs = (
        "README.md",
        "CHANGELOG.md",
        "docs/current-state.md",
        "docs/adapter-contract.md",
        "docs/capability-matrix.md",
        "docs/evaluation-topologies.md",
        "docs/harness.md",
        "docs/project-map.md",
        "docs/benchmark-semantics.md",
        "docs/agentic-boundary-model.md",
    )
    for path in required_docs:
        assert "toy-multi-agent" in _read(path), path

    current_state = _read("docs/current-state.md")
    planned_section = current_state.split("## Planned, not shipped", 1)[1].split(
        "## Current active work", 1
    )[0]
    assert "toy multi-agent handoff adapter" not in planned_section
    assert "toy-multi-agent" in current_state.split("## Shipped and verified", 1)[1]


def test_recovery_trust_gate_candidate_has_required_proposal_shape() -> None:
    expansion = _read("docs/corpus-expansion-plan.md")
    catalog = _read("docs/problem-solution-catalog.md")

    assert "Designed candidate: `recovery.trust_gate_no_path`" in expansion
    for phrase in (
        "Boundary invariant",
        "Problem",
        "Defensive scenario",
        "Expected vulnerable behavior",
        "Detection signal",
        "Mitigation",
        "Harness test",
        "Residual risk",
        "Implementation guardrails",
        "Do not expand by provider x model x country x document type x retry count",
    ):
        assert phrase in expansion

    assert "Trust gate without a recovery path" in catalog
    assert "planned ID `recovery.trust_gate_no_path`" in catalog


def test_public_showcase_checklist_is_linked_from_release_and_example_docs() -> None:
    checklist = _read("docs/showcase-report-checklist.md")
    release_checklist = _read("docs/release-checklist.md")
    examples_index = _read("examples/README.md")
    comparison_readme = _read("examples/comparison-report/README.md")
    readme = _read("README.md")

    for phrase in (
        "Required command record",
        "Required artifacts",
        "Required summary",
        "Claim boundary text",
        "Standards mapping caveat",
        "ash validate <showcase-dir>",
    ):
        assert phrase in checklist

    assert "showcase-report-checklist.md" in release_checklist
    assert "showcase-report-checklist.md" in examples_index
    assert "showcase-report-checklist.md" in comparison_readme
    assert "docs/showcase-report-checklist.md" in readme
    assert "Findings reduced: **22 -> 0**" in comparison_readme
    assert "Findings reduced: **17 -> 0**" not in comparison_readme


def test_project_tracker_separates_open_and_completed_work() -> None:
    tracker = _read("docs/project-tracker.md")
    open_work = tracker.split("## Open work in this track", 1)[1].split(
        "## Open maintenance work", 1
    )[0]
    completed = tracker.split("## Recently completed in this track", 1)[1]

    for issue in ("#22", "#23", "#24", "#25", "#30", "#31", "#32", "#33", "#34"):
        assert issue not in open_work
        assert issue in completed
    for issue in ("#19", "#20", "#21"):
        assert issue in open_work
    assert "#29" in tracker.split("## Open maintenance work", 1)[1]


def test_handoff_source_map_uses_corrected_research_ids() -> None:
    handoff = _read("docs/inter-agent-handoff-integrity.md")
    for bad_id in ("2504.15437", "2503.20006", "2602.18793", "2502.04150"):
        assert bad_id not in handoff
    for corrected_id in ("2505.02077", "2505.23847", "2601.11893", "2510.11108"):
        assert corrected_id in handoff
    assert "SLSA v1.2" in handoff
    assert "BlockA2A" in handoff


def test_handoff_toy_topology_documents_verifier_math_and_claim_boundary() -> None:
    readme = _read("README.md")
    tracker = _read("docs/project-tracker.md")
    handoff = _read("docs/inter-agent-handoff-integrity.md")
    topology = _read("docs/handoff-toy-topology.md")

    assert "docs/handoff-toy-topology.md" in readme
    assert "handoff-toy-topology.md" in tracker
    assert "handoff-toy-topology.md" in handoff
    for phrase in (
        "payload_hash = SHA-256(JSON-canonical(payload))",
        "S_structural = 1.0",
        "S_semantic = n_unsafe / n_consumptions",
        "S_combined = 0.7",
        "toy-multi-agent",
        "protected-toy-multi-agent",
        "This is not evidence about a live multi-agent runtime.",
    ):
        assert phrase in topology


def test_v1_readiness_matrix_is_linked_and_explicit_about_blockers() -> None:
    readiness = _read("docs/v1-readiness.md")
    release_checklist = _read("docs/release-checklist.md")
    readme = _read("README.md")

    for phrase in (
        "Stable vs experimental surface",
        "Clean install path",
        "Fake-server path",
        "Claim boundaries for v1.0",
        "Open v1.0 blockers",
        "Trace schema freeze",
        "Corpus manifest freeze",
        "not a claim that v1.0 is ready",
    ):
        assert phrase in readiness

    assert "v1-readiness.md" in release_checklist
    assert "docs/v1-readiness.md" in readme
