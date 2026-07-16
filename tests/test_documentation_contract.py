import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_links_methodology_docs() -> None:
    readme = _read("README.md")
    for phrase in (
        "In plain English",
        "If you only have one minute",
        "Visual evidence snapshot",
        "docs/assets/evidence-flow.svg",
        "trace-first benchmark",
        "committed before/after example",
        "24 modeled findings",
        "0 modeled findings",
    ):
        assert phrase in readme
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
        "docs/run-your-model.md",
        "docs/evidence-pack-format.md",
        "docs/scenario-timeline.md",
        "docs/showcase/index.md",
        "docs/showcase/evidence-map.md",
        "docs/showcase/scenario-matrix.md",
        "docs/showcase/weak-spots-and-findings.md",
        "docs/private-public-evidence-boundary.md",
        "GOVERNANCE.md",
    ):
        assert link in readme
    assert "not just standalone model answers" in readme


def test_run_your_model_path_is_public_and_cross_platform() -> None:
    readme = _read("README.md")
    run_doc = _read("docs/run-your-model.md")
    connect = _read("docs/connect-models.md")
    current_state = _read("docs/current-state.md")
    project_map = _read("docs/project-map.md")
    examples = _read("examples/README.md")

    for text in (readme, current_state, project_map, examples):
        assert "run-your-model.md" in text

    for phrase in (
        "Linux/macOS",
        "Windows PowerShell",
        "No-model deterministic demo",
        "Run one local or remote OpenAI-compatible model",
        "Run a deterministic local swarm comparison",
        "Run a local-model mini-swarm campaign",
        "Keep raw model responses under `.internal/`",
        "not `pass` or `finding`",
    ):
        assert phrase in run_doc

    assert "| `instruction-integrity` | 2 | 3 |" in connect


def test_evidence_pack_format_documents_public_private_promotion() -> None:
    readme = _read("README.md")
    evidence_pack = _read("docs/evidence-pack-format.md")
    current_state = _read("docs/current-state.md")
    project_map = _read("docs/project-map.md")
    examples = _read("examples/README.md")
    release = _read("docs/release-checklist.md")

    for text in (readme, current_state, project_map, examples, release):
        assert "evidence-pack-format.md" in text

    for phrase in (
        "research question -> run command -> sanitized artifacts -> validation -> claim row",
        "Public artifacts do not include raw transcripts",
        "private_transcript_sha256",
        "raw_private_material_committed",
        "This model is safe.",
            "`local_empirical_unreconciled`",
            "`local_empirical_reconciled`",
        "ash validate examples/",
        "Promotion checklist",
    ):
        assert phrase in evidence_pack


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
        "Shipped, historical, and documented status",
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
        "Evidence map",
        "Scenario matrix",
        "Weak spots and findings",
        "Deepening backlog",
        "local Prometheus",
        "Deterministic multi-agent handoff toy comparison",
        "toy-multi-agent",
        "protected-toy-multi-agent",
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
        "handoff.verifier-canary",
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
        "prometheus-lowctx-smoke",
        "prometheus-qwen15b-lowctx:latest",
        "prometheus-lowmem-smoke",
        "qwen2.5:1.5b",
        "Stop conditions",
        "adapter_error",
    ):
        assert phrase in profiles


def test_showcase_includes_handoff_topology_evidence_boundary() -> None:
    index = _read("docs/showcase/index.md")
    matrix = _read("docs/showcase/scenario-matrix.md")

    for phrase in (
        "ash compare --baseline toy-multi-agent --protected protected-toy-multi-agent",
        "ash validate examples/handoff-toy-comparison",
        "not a live multi-agent runtime claim",
    ):
        assert phrase in index

    for phrase in (
        "`inter-agent-handoff`",
        "local synthetic coordinator/worker handoff",
        "explicit deterministic invariants",
    ):
        assert phrase in matrix


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
        assert "twenty-three" not in text
        assert "23-pattern" not in text


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
    assert "toy-multi-agent" in current_state.split(
        "## Shipped, historical, and documented status", 1
    )[1]


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
    assert "Findings reduced: **24 -> 0**" in comparison_readme
    assert "Findings reduced: **17 -> 0**" not in comparison_readme


def test_project_tracker_separates_open_and_completed_work() -> None:
    tracker = _read("docs/project-tracker.md")
    open_work = tracker.split("## Open work in this track", 1)[1].split(
        "## Open maintenance work", 1
    )[0]
    completed = tracker.split("## Recently completed in this track", 1)[1]

    for issue in (
        "#21",
        "#20",
        "#22",
        "#23",
        "#24",
        "#25",
        "#29",
        "#30",
        "#31",
        "#32",
        "#33",
        "#34",
        "#19",
        "#48",
        "#50",
        "#57",
        "#61",
        "#63",
        "#64",
        "#65",
        "#66",
        "#67",
        "#80",
        "#82",
        "#84",
    ):
        assert issue not in open_work
        assert issue in completed
    for issue in ("#87", "#96", "#136", "#140"):
        assert issue not in open_work
        assert issue in completed
    assert "No open product or research issues as of 2026-07-14." in open_work
    assert (
        "`ash evidence-quality` summarizes recorded external/local artifacts"
        in completed
    )
    assert "Fresh bounded Prometheus/Ollama rerun" in completed
    assert "boundary-layer-evidence-matrix.md" in completed
    open_maintenance = tracker.split("## Open maintenance work", 1)[1].split(
        "## Recently completed in this track", 1
    )[0]
    assert "#29" not in open_maintenance
    for pull_request in ("#152", "#153", "#154", "#155"):
        assert pull_request in open_maintenance
    assert "maintenance PRs, not an active benchmark research roadmap" in open_maintenance
    assert "pending repository review/merge" not in tracker


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


def test_research_claims_registry_exists_and_has_required_structure() -> None:
    claims = _read("docs/research-claims.md")

    for phrase in (
        "hypothesis",
        "formal_model_draft",
        "executable_invariant",
        "synthetic_validation",
        "local_empirical",
        "local_empirical_unreconciled",
        "historical_local_empirical",
        "public_example",
        "planned",
        "superseded",
    ):
        assert phrase in claims

    for column in (
        "Claim",
        "Boundary / topic",
        "Status",
        "Theory doc",
        "Code mapping",
        "Tests",
        "Evidence artifacts",
        "What this proves",
        "What this does NOT prove",
        "Next step",
    ):
        assert column in claims

    for claim in (
        "Data boundary / envelope preservation",
        "Capability delegation / authority non-expansion",
        "Audit hash-chain integrity",
        "Memory governance / TTL / provenance",
        "Inter-agent handoff integrity",
        "Local Prometheus weak-model evidence quality",
        "Small-model swarm handoff evidence quality",
        "Synthetic secret-egress control attribution",
        "Secret-egress local variation evidence quality",
        "Semantic parameter drift in local mini-swarm",
        "Semantic drift propagation in worker-to-chief chains",
    ):
        assert claim in claims

    assert "docs/theory/data-boundary.md" in claims
    assert "fail-closed recovery for a missing required envelope" in claims
    assert "memory write/read envelope drift" in claims
    assert "Tool envelope uses are adjacent coverage, not primary proof." in claims
    assert (
        "cross-provider label survival are not yet covered as primary data-boundary claims"
        in claims
    )


def test_small_model_swarm_handoff_claim_is_unverified_declaration() -> None:
    claims = _read("docs/research-claims.md")
    row = next(
        line
        for line in claims.splitlines()
        if line.startswith("| Small-model swarm handoff evidence quality |")
    )

    assert "| `maintainer_declaration_unverified` |" in row
    assert "`public_example`" not in row
    assert "Tracked maintainer pages only" in row
    assert "versioned public result projection" in row
    assert "docs/local-swarm-real-model-evaluation.md" in row
    assert "Proof that a run occurred" in row
    assert "reconciliation receipt" in row
    assert "Public model benchmark finding" in row
    assert "Live multi-agent guarantee" in row
    assert "examples/" not in row


def test_local_swarm_attack_matrix_is_documented_as_deterministic_example() -> None:
    bounded = _read("docs/bounded-local-swarm.md")
    showcase = _read("docs/showcase/index.md")
    scenario_matrix = _read("docs/showcase/scenario-matrix.md")
    project_map = _read("docs/project-map.md")
    schemas = _read("docs/artifact-schemas.md")

    for text in (bounded, showcase, scenario_matrix, project_map):
        assert "examples/local-swarm-attack-matrix" in text

    assert "local-swarm-matrix --write" in bounded
    assert "cases=43" in bounded
    assert "deep probe cases=10" in bounded
    assert "bounded-swarm boundary failures=0" in bounded
    assert "cryptographic audit-chain integrity remains" in bounded
    assert "separate project claim" in bounded
    assert "local_swarm_attack_matrix.json" in schemas
    assert "local_swarm_matrix" in schemas


def test_evidence_assurance_model_documents_campaign_metrics() -> None:
    doc = _read("docs/evidence-assurance-model.md")
    project_map = _read("docs/project-map.md")
    claims = _read("docs/research-claims.md")
    schemas = _read("docs/artifact-schemas.md")

    for phrase in (
        "Private/Public Boundary",
        "attack_block_rate = fixture_TP / scenario_author_unsafe_cases",
        "benign_pass_rate = fixture_TN / scenario_author_safe_cases",
        "rule_derived_delta = naive_swarm.failure_rate - bounded_swarm.failure_rate",
        "usability_cost = bounded_swarm.false_block_rate - naive_swarm.false_block_rate",
        "ash evidence-campaign --write --out .internal/evidence-campaign/latest",
        "not a production safety proof",
    ):
        assert phrase in doc

    assert "evidence-assurance-model.md" in project_map
    assert "evidence_campaign.py" in project_map
    assert "docs/evidence-assurance-model.md" in claims
    assert "tests/test_evidence_campaign.py" in claims
    assert "evidence_campaign_summary.json" in schemas
    assert "evidence_campaign" in schemas


def test_public_evidence_map_links_current_campaign_metrics() -> None:
    evidence_map = _read("docs/showcase/evidence-map.md")
    readme = _read("README.md")
    showcase = _read("docs/showcase/index.md")
    prop_report = _read(
        "examples/semantic-propagation-sanitized/semantic_propagation_report.md"
    )

    for phrase in (
        "Deterministic corpus comparison",
        "Semantic propagation defense",
        "bounded acceptances `0`",
        "ablation acceptances `20`",
        "adapter errors `1`",
        "private calculations that must stay under `.internal/`",
        "Adapter errors are passes",
    ):
        assert phrase in evidence_map

    assert "docs/showcase/evidence-map.md" in readme
    assert "Evidence map" in showcase
    assert "Defense Control Model" in prop_report
    assert "Control Ablation Matrix" in prop_report
    assert "Adapter error" in prop_report
    assert "Response hashes" in prop_report
    adapter_error_row = (
        "| worker_relabel_to_chief | qwen2.5:0.5b | llama3.2:1b | pseudo_code | "
        "True | False | False | True | worker_only | adapter_error | - |"
    )
    assert adapter_error_row in prop_report


def test_private_public_evidence_boundary_is_linked_and_specific() -> None:
    boundary = _read("docs/private-public-evidence-boundary.md")
    readme = _read("README.md")
    evidence_map = _read("docs/showcase/evidence-map.md")
    live_doc = _read("docs/live-mini-swarm-defense-campaign.md")
    examples_index = _read("examples/README.md")

    for phrase in (
        "Public artifacts do not include raw transcripts",
        "SHA-256-shaped",
        "does not prove that matching private bytes exist",
        "owner-side reconciliation",
        "model names and runtime family labels",
        "worker/chief/runtime roles",
        "topology ids, scenario ids, pressure labels",
        "response SHA-256 hashes",
        "replay-ablation metrics",
        "raw prompts and prompt chains",
        "raw model responses and raw transcripts",
        "synthetic canary values",
        "local absolute paths",
        "not empirical or",
        "transcript-level proof",
    ):
        assert phrase in boundary

    for text in (readme, evidence_map, live_doc, examples_index):
        assert "private-public-evidence-boundary.md" in text

    assert ".internal/external-demo/latest" in readme
    assert "Do not" in readme
    assert "commit `raw_responses/`" in readme


def test_live_mini_swarm_reproduce_command_pins_base_pressure_modes() -> None:
    live_doc = _read("docs/live-mini-swarm-defense-campaign.md")
    examples_index = _read("examples/README.md")

    for mode in (
        "gentle_reframe",
        "pseudo_code",
        "memory_rewrite",
        "authority_pressure",
        "benign_debug",
        "consensus_pressure",
    ):
        assert f"--pressure-mode {mode}" in live_doc
        assert f"--pressure-mode {mode}" in examples_index

    assert "--pressure-mode long_session_relabel" in live_doc
    assert "legacy-readable schema `0.2`" in live_doc
    assert "schema `0.3`" in live_doc


def test_live_mini_swarm_claim_is_quarantined_as_historical() -> None:
    claims = _read("docs/research-claims.md")
    row = next(
        line
        for line in claims.splitlines()
        if line.startswith("| Historical loopback-endpoint mini-swarm campaign |")
    )
    closure = next(
        line for line in claims.splitlines() if line.startswith("| SEM-4 |")
    )

    assert "| `historical_local_empirical` |" in row
    assert "Canary-zero claims are withdrawn" in row
    assert "current `0.5` has no committed execution" in row
    assert "`historical_local_empirical`" in closure
    assert "predate the current contract" in closure


def test_legacy_live_examples_disclose_structural_status_before_metrics() -> None:
    for path in (
        "examples/swarm-defense-live-sanitized/swarm_defense_live_report.md",
        "examples/swarm-defense-live-long-session-sanitized/swarm_defense_live_report.md",
        "examples/swarm-defense-live-deep-sanitized/swarm_defense_live_report.md",
        "examples/marketing-web-live-sanitized/marketing_web_live_report.md",
    ):
        opening = "\n".join(_read(path).splitlines()[:8]).lower()
        assert "historical" in opening
        assert "structural-only" in opening
        assert "public validation does not replay private" in opening

    examples_index = _read("examples/README.md")
    assert "legacy structural snapshots" in examples_index.splitlines()[0].lower()


def test_contour_headline_count_matches_committed_rule_derived_metric() -> None:
    claims = _read("docs/research-claims.md")
    showcase = _read("docs/showcase/index.md")
    assert "112 rule-derived ablation acceptances" in claims
    assert "112 rule-derived ablation acceptances" in showcase


def test_research_claims_registry_status_definitions_are_unique() -> None:
    claims = _read("docs/research-claims.md")
    definitions = claims.split("## Claim maturity/status definitions", 1)[1].split(
        "## Claim registry", 1
    )[0]

    statuses = (
        "hypothesis",
        "formal_model_draft",
        "executable_invariant",
        "synthetic_validation",
        "local_empirical",
        "local_empirical_unreconciled",
        "historical_local_empirical",
        "public_example",
        "planned",
        "superseded",
    )
    for status in statuses:
        assert f"`{status}`" in claims
        assert definitions.count(f"| `{status}` |") == 1


def test_research_claims_registry_uses_real_paths_and_public_example_boundary() -> None:
    claims = _read("docs/research-claims.md")

    for path in (
        "src/agentic_security_harness/demo_agent.py",
        "src/agentic_security_harness/protected_demo_agent.py",
        "src/agentic_security_harness/external_runner.py",
        "tests/test_external.py",
        "tests/test_v07_patterns.py",
    ):
        assert path in claims

    for stale_path in (
        "demo-agent.py",
        "protected-demo-agent.py",
        "tests/test_external_runner.py",
    ):
        assert stale_path not in claims

    public_definition = claims.split("| `public_example` |", 1)[1].split("|", 1)[0]
    assert "reports/" not in public_definition
    assert "examples/" in public_definition


def test_handoff_theory_does_not_make_live_runtime_claim() -> None:
    theory = _read("docs/theory/handoff-integrity.md")

    expected = "Formal executable invariant prototype validated on deterministic synthetic topology"
    assert expected in theory

    non_claims_section = theory.split("## 10. Limits / non-claims", 1)[1]
    allowed_in_non_claims = non_claims_section.lower()

    claim_section = theory.split("## 1. Claim", 1)[1].split("## 2.", 1)[0].lower()
    assert "prevents all handoff failures in production" not in claim_section
    assert "complete multi-agent security solution" not in claim_section
    assert "live multi-agent framework" not in claim_section

    assert "prevents all handoff failures in production" in allowed_in_non_claims
    assert "complete multi-agent security solution" in allowed_in_non_claims


def test_handoff_theory_links_claim_to_code_tests_evidence() -> None:
    theory = _read("docs/theory/handoff-integrity.md")

    for section in (
        "## 1. Claim",
        "## 2. Formal objects",
        "## 3. Invariants",
        "## 7. Code mapping",
        "## 8. Tests",
        "## 9. Evidence",
        "## 10. Limits / non-claims",
    ):
        assert section in theory

    for link in (
        "handoff_integrity.py",
        "test_handoff_integrity.py",
        "toy-multi-agent",
        "protected-toy-multi-agent",
    ):
        assert link in theory


def test_authority_delegation_theory_links_axes_and_nonclaims() -> None:
    theory = _read("docs/theory/authority-delegation.md")

    for phrase in (
        "issuer, scope, purpose, TTL, or delegation depth",
        "child.issuer == parent.issuer",
        "set(child.scope) subseteq set(parent.scope)",
        "child.ttl_seconds <= parent.ttl_seconds",
        "authority_expansion",
        "examples/handoff-toy-comparison",
        "test_capability_authority_non_expansion_axes",
        "revocation propagation",
    ):
        assert phrase in theory

    non_claims = theory.split("## 7. Limits / Non-Claims", 1)[1].lower()
    assert "production authorization semantics" in non_claims
    assert "live multi-agent framework coverage" in non_claims


def test_memory_governance_theory_links_invariant_layer() -> None:
    theory = _read("docs/theory/memory-governance.md")

    for phrase in (
        "MemoryGovernanceRecord",
        "MemoryReadRequest",
        "untrusted < tool_output < user < trusted_policy < system",
        "TTL from write time",
        "trust_precedence_violation",
        "src/agentic_security_harness/memory_governance.py",
        "tests/test_memory_governance.py",
        "synthetic_validation",
    ):
        assert phrase in theory

    non_claims = theory.split("## 7. Limits / Non-Claims", 1)[1].lower()
    assert "production memory-store isolation" in non_claims
    assert "semantic truthfulness" in non_claims


def test_data_boundary_theory_separates_primary_adjacent_and_gaps() -> None:
    theory = _read("docs/theory/data-boundary.md")

    for section in (
        "## 1. Claim",
        "## 2. Formal Object",
        "## 3. Boundary Invariants",
        "## 4. Current Coverage",
        "## 7. Coverage Gaps",
        "## 8. Claim Table",
        "## 10. Limits / Non-Claims",
    ):
        assert section in theory

    for pattern in (
        "data_boundary_recipient_confusion",
        "data_boundary_classification_mutation",
        "data_boundary_handoff_label_stripping",
        "provider_boundary_leakage_sanitized",
        "data_boundary_missing_envelope_recovery",
        "data_boundary_memory_envelope_drift",
    ):
        assert pattern in theory

    for phrase in (
        "Primary Data-Boundary Patterns",
        "Adjacent Envelope-Field Patterns",
        "Restriction model",
        "E_out <= E_in",
        "set(E_out.allowed_recipients) subseteq set(E_in.allowed_recipients)",
        "rank(E_out.data_class) >= rank(E_in.data_class)",
        "t_use <= t_created + ttl_seconds",
        "This is a partial order, not a universal security proof",
        "individual patterns do not themselves prove the whole 24 -> 0 result",
        "Memory write/read envelope drift",
        "Missing envelope recovery",
        "`public_example`",
    ):
        assert phrase in theory


def test_data_boundary_theory_does_not_overclaim_memory_or_production_security() -> None:
    theory = _read("docs/theory/data-boundary.md")
    claim_section = (
        theory.split("## 1. Claim", 1)[1]
        .split("This does not claim", 1)[0]
        .lower()
    )
    limits_section = theory.split("## 10. Limits / Non-Claims", 1)[1].lower()

    assert "deployed agent framework preserves labels" not in claim_section
    assert "semantic truthfulness is solved" not in claim_section
    assert "every possible boundary type is covered" not in claim_section

    for phrase in (
        "complete memory-governance behavior for real deployed memory stores",
        "complete recovery behavior",
        "complete formal security proof",
    ):
        assert phrase in limits_section


def test_theory_readme_documents_public_private_boundary() -> None:
    readme = _read("docs/theory/README.md")

    for phrase in (
        "Public (this directory)",
        "Private / local only",
        "Cleaned invariant statements",
        "Scratch derivations",
        "Claim boundaries",
        "No theory doc may claim",
        "Local-empirical summaries",
        "Raw local model responses",
        "scratch `reports/`",
        "`local_empirical` claims",
    ):
        assert phrase in readme

    assert "handoff-integrity.md" in readme
    assert "| `data-boundary.md` | Active |" in readme
    assert "| `authority-delegation.md` | Active |" in readme
    assert "| `memory-governance.md` | Active |" in readme


def test_small_model_swarm_handoff_track_is_bounded_not_shipped_profile() -> None:
    workflow = _read("docs/local-prometheus-workflow.md")
    profiles = _read("docs/local-model-profiles.md")
    evidence_quality = _read("docs/evidence-quality.md")

    assert "Small-model swarm handoff" in workflow
    assert "unverified maintainer declaration" in workflow
    assert "not model safety" in workflow
    assert "does not orchestrate a swarm" in workflow
    assert "not yet a named runnable profile" in profiles
    assert "ash evidence-quality" in profiles
    assert "Derived analysis only" in evidence_quality
    assert "not a model leaderboard" in evidence_quality


def test_project_tracker_links_research_claims_registry() -> None:
    tracker = _read("docs/project-tracker.md")
    assert "research-claims.md" in tracker


def test_project_map_links_research_claims_and_theory() -> None:
    project_map = _read("docs/project-map.md")
    assert "research-claims.md" in project_map
    assert "theory/" in project_map
    assert "Research claims registry" in project_map
    assert "Theory docs" in project_map
    assert "boundary-layer-evidence-matrix.md" in project_map
    assert "Boundary-layer reviewer" in project_map


def test_git_evidence_workflow_is_publicly_linked() -> None:
    workflow = _read("docs/git-evidence-workflow.md")
    readme = _read("README.md")
    contributing = _read("CONTRIBUTING.md")
    agent_guide = _read("docs/agent-operating-guide.md")
    project_map = _read("docs/project-map.md")

    for phrase in (
        "idea -> issue -> branch -> implementation -> tests/artifacts -> PR",
        "GitHub checks",
        "review gate",
        "Definition Of Done",
        "docs make a stronger claim than tests/artifacts prove",
    ):
        assert phrase in workflow

    for text in (readme, contributing, agent_guide, project_map):
        assert "git-evidence-workflow.md" in text


def test_boundary_layer_evidence_matrix_is_explicit_and_bounded() -> None:
    matrix = _read("docs/boundary-layer-evidence-matrix.md")

    for phrase in (
        "declared_matrix_rows = 9 + 5 + 8 = 22",
        "validated_declared_rows = 22",
        "declared_matrix_coverage = 22 / 22 = 1.0",
        "tests/test_boundary_variation_matrices.py",
        "missing_envelope",
        "authority_expansion",
        "trust_precedence_violation",
        "Private calculations may guide a public doc",
        "Private scratch calculations are public evidence",
    ):
        assert phrase in matrix

    limits = matrix.split("## Gaps", 1)[1]
    for phrase in (
        "Live multi-agent runtime handoff behavior",
        "Capability revocation propagation",
        "Purpose hierarchy / semantic purpose matching",
        "Production memory-store isolation",
        "Semantic truthfulness of payload or memory content",
    ):
        assert phrase in limits


def test_theory_docs_link_to_boundary_layer_matrix() -> None:
    docs = (
        "docs/theory/handoff-integrity.md",
        "docs/theory/authority-delegation.md",
        "docs/theory/memory-governance.md",
        "docs/theory/README.md",
    )
    for path in docs:
        text = _read(path)
        assert "boundary-layer-evidence-matrix.md" in text, path

    handoff = _read("docs/theory/handoff-integrity.md")
    authority = _read("docs/theory/authority-delegation.md")
    memory = _read("docs/theory/memory-governance.md")

    assert "The public variation matrix currently declares 9 handoff rows" in handoff
    assert "issuer + scope + purpose + TTL + delegation_depth = 5" in authority
    assert "The declared memory-governance matrix has 8 rows" in memory


def test_no_mathematically_proven_overclaim_in_docs() -> None:
    for path in (
        "docs/inter-agent-handoff-integrity.md",
        "docs/handoff-toy-topology.md",
        "docs/theory/handoff-integrity.md",
        "docs/theory/data-boundary.md",
        "docs/theory/authority-delegation.md",
        "docs/theory/memory-governance.md",
    ):
        text = _read(path).lower()
        assert "mathematically proven" not in text, path
        assert "mathematically secure" not in text, path
        assert "provably secure" not in text, path

    theory_readme = _read("docs/theory/README.md").lower()
    assert "no theory doc may claim" in theory_readme
    forbidden_section = theory_readme.split("no theory doc may claim", 1)[0]
    assert "what does not belong" in forbidden_section
    assert "mathematically proven" in theory_readme


def test_research_problem_map_declares_evidence_strength_per_contour() -> None:
    problem_map = _read("docs/research-problem-map.md")

    assert "What the current evidence supports" in problem_map
    assert "| What it proves |" not in problem_map
    for phrase in (
        "executable specification",
        "mark declared naive branches as leaking",
        "rule-encoded dependencies",
        "legacy detector observations remain historical",
        "| Evidence classification |",
        "Evidence classification:",
        "evidence class, schema state, causal scope",
        "validation status alone",
    ):
        assert phrase in problem_map

    for overclaim in (
        "Drift can be modeled, detected, and bounded",
        "Worker-to-chief propagation can be attributed",
        "with replay-ablation attribution",
    ):
        assert overclaim not in problem_map


def test_showcase_evidence_map_separates_rules_history_and_validation() -> None:
    evidence_map = _read("docs/showcase/evidence-map.md")
    compact_map = " ".join(evidence_map.split())
    showcase_index = _read("docs/showcase/index.md")

    for phrase in (
        "private-byte and execution-origin reconciliation is absent",
        "The legacy artifact retains declared detector labels",
        "legacy artifact retains internally consistent",
        "rule-derived control-dependency counts",
        "legacy local-model summaries receive limited structural validation",
    ):
        assert phrase in compact_map

    assert "research-problem-map.md" in evidence_map
    assert "research-problem-map.md" in showcase_index
    assert "hash commitments require separate owner-side reconciliation" in showcase_index
    assert "response hashes anchor owner-side replay" not in showcase_index

    for text in (evidence_map, showcase_index):
        assert "evidence-status-registry.json" in text

    assert "ash validate docs/evidence-status-registry.json" in evidence_map

    for overclaim in (
        "Private local-model pressure runs can be summarized",
        "produced detector-observed signals",
        "cannot turn disagreement into acceptance",
        "reports rule-derived ablation reopenings",
        "`ash validate` is an artifact-integrity check",
    ):
        assert overclaim not in evidence_map


def test_machine_readable_evidence_registry_is_linked_from_public_entrypoints() -> None:
    evidence_classes = _read("docs/evidence-classes.md")
    evidence_pack = _read("docs/evidence-pack-format.md")
    project_map = _read("docs/project-map.md")
    readme = _read("README.md")

    for text in (evidence_classes, evidence_pack, project_map, readme):
        assert "evidence-status-registry.json" in text

    for text in (evidence_classes, evidence_pack, readme):
        assert "ash validate docs/evidence-status-registry.json" in text

    assert "Publication as a public example does not" in evidence_pack
    assert "unverified-private-projection" in evidence_classes

    evidence_map = _read("docs/showcase/evidence-map.md")
    assert "unverified-private-projection" in evidence_map
    assert "--format json" in evidence_map


def test_trading_history_and_identity_scope_are_not_promoted() -> None:
    observation = _read("docs/trading-bot-real-artifact-observation-2026-07-03.md")
    experiment = _read("docs/trading-bot-controlled-experiment-plan-2026-07-03.md")
    profile = _read("docs/trading-bot-paper-stand-target-profile.md")

    assert "Historical ASH gate output" in observation
    assert "The current ASH evidence-quality gate passes" not in observation
    assert "## Historical Gate Result" in experiment
    assert "## Current Gate Result" not in experiment
    assert "requires cross-artifact identity-chain consistency" in profile
    assert "requires a verified causal chain" not in profile


def test_artifact_authenticity_design_separates_trust_domains_and_non_claims() -> None:
    design = _read("docs/artifact-authenticity-design.md")
    current_state = _read("docs/current-state.md")
    project_map = _read("docs/project-map.md")

    for phrase in (
        "Public release and deterministic evidence bundles",
        "Private/local empirical reconciliation",
        "The harness must never generate an \"owner\" signature for itself.",
        "A transparency-log inclusion time",
        "does not authenticate the run's self-declared `created_at`",
        "no signing authority or external workflow change is implemented",
    ):
        assert phrase in design

    assert "GitHub Actions workload identity plus GitHub artifact attestations/Sigstore" in design
    assert "No artifact may be promoted to `signed_attested`" in design
    assert "https://slsa.dev/provenance/v1" in design
    assert "signing/workload identity and provenance `builder.id` pair" in design
    assert "they are not required to be distinct identities" in design
    assert "SLSA v1.2" in design
    assert "slsa.dev/spec/v1.0" not in design
    assert "artifact-authenticity-design.md" in project_map
    assert "Current release/evidence artifacts are content-bound but unsigned" in current_state


def test_security_audit_causal_map_covers_every_task_finding_and_open_boundary() -> None:
    causal_map = _read("docs/security-audit-causal-map-2026-07-15.md")
    project_map = _read("docs/project-map.md")
    readme = _read("README.md")
    mapped_ids = re.findall(
        r"^\| `((?:TB-AUD|ASH-TB|ASH-AUD)-\d+)` \|",
        causal_map,
        flags=re.MULTILINE,
    )
    expected_ids = {
        *(f"TB-AUD-{number:02d}" for number in range(1, 12)),
        "ASH-TB-01",
        *(f"ASH-AUD-{number:02d}" for number in range(2, 40)),
    }

    assert len(expected_ids) == 50
    assert set(mapped_ids) == expected_ids
    assert len(mapped_ids) == len(set(mapped_ids))

    for phrase in (
        "not a completion or security-certification claim",
        "No trading target module",
        "Current signed evidence",
        "Current empirical campaign",
        "Static ASH repairs cannot close defects in a read-only target",
        "The audit is not complete until every open/partial row",
    ):
        assert phrase in causal_map

    for text in (project_map, readme):
        assert "security-audit-causal-map-2026-07-15.md" in text
