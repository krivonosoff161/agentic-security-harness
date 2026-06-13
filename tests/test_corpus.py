from agentic_security_harness.corpus import corpus_manifest
from agentic_security_harness.demo_adapter import DemoAgentTarget
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.protected_demo_agent import ProtectedDemoAgentTarget
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import build_scorecard


def test_manifest_has_twenty_two_implemented_entries() -> None:
    manifest = corpus_manifest()
    assert len(manifest) == 22
    assert all(entry.implemented for entry in manifest)


def test_manifest_ids_match_seed_patterns_in_order() -> None:
    manifest_ids = [entry.pattern_id for entry in corpus_manifest()]
    seed_ids = [pattern.pattern_id for pattern in seed_patterns()]
    assert manifest_ids == seed_ids


def test_no_duplicate_pattern_ids() -> None:
    ids = [entry.pattern_id for entry in corpus_manifest()]
    assert len(ids) == len(set(ids))


def test_manifest_severity_and_broke_at_match_baseline() -> None:
    by_id = {entry.pattern_id: entry for entry in corpus_manifest()}
    traces = {t.pattern_id: t for t in HarnessRunner(DemoAgentTarget()).run_many(seed_patterns())}
    for pid, entry in by_id.items():
        finding = traces[pid].findings[0]
        assert finding.severity == entry.severity
        assert finding.broke_at == entry.broke_at


def test_baseline_and_protected_outcomes_match_manifest() -> None:
    patterns = seed_patterns()
    base = build_scorecard(HarnessRunner(DemoAgentTarget()).run_many(patterns))
    prot = build_scorecard(HarnessRunner(ProtectedDemoAgentTarget()).run_many(patterns))
    for entry in corpus_manifest():
        assert entry.baseline_expected == "FAIL"
        assert entry.protected_expected == "PASS"
        assert entry.pattern_id in base.failed_patterns
        assert entry.pattern_id in prot.passed_patterns


def test_agentic_standards_mapping_is_present_for_implemented_patterns() -> None:
    for entry in corpus_manifest():
        assert entry.owasp_agentic
        assert all(item.startswith("ASI") for item in entry.owasp_agentic)
        assert entry.owasp_llm == []
        assert entry.mitre_atlas == []
