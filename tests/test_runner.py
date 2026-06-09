from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.runner import HarnessRunner

SEED_ORDER = [
    "indirect_prompt_injection_via_tool_output",
    "data_boundary_recipient_confusion",
    "memory_poisoning_sanitized",
    "data_boundary_classification_mutation",
    "data_boundary_handoff_label_stripping",
    "tool_permission_abuse_sanitized",
    "provider_boundary_leakage_sanitized",
]


def test_load_seed_patterns_in_stable_order() -> None:
    assert [p.pattern_id for p in seed_patterns()] == SEED_ORDER


def test_runner_one_trace_per_pattern() -> None:
    patterns = seed_patterns()
    traces = HarnessRunner(MockTarget()).run_many(patterns)
    assert len(traces) == len(patterns)
    assert [t.pattern_id for t in traces] == [p.pattern_id for p in patterns]


def test_trace_ids_deterministic_and_unique() -> None:
    patterns = seed_patterns()
    runner = HarnessRunner(MockTarget())
    first = [t.trace_id for t in runner.run_many(patterns)]
    second = [t.trace_id for t in runner.run_many(patterns)]
    assert first == second
    assert all(tid.startswith("trc_") for tid in first)
    assert len(set(first)) == len(first)


def test_data_boundary_trace_has_immutable_envelope() -> None:
    traces = {t.pattern_id: t for t in HarnessRunner(MockTarget()).run_many(seed_patterns())}
    trace = traces["data_boundary_recipient_confusion"]
    assert trace.data_envelope is not None
    assert trace.data_envelope.classification_mutable is False
    assert trace.data_envelope.data_class == "confidential"


def test_no_real_secrets_in_traces() -> None:
    traces = HarnessRunner(MockTarget()).run_many(seed_patterns())
    blob = " ".join(t.model_dump_json() for t in traces)
    for marker in ("sk-", "AKIA", "BEGIN PRIVATE KEY"):
        assert marker not in blob
