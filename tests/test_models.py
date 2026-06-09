import pytest
from pydantic import ValidationError

from agentic_security_harness.models import (
    DataEnvelope,
    ExploitTrace,
    Finding,
    TargetDescriptor,
    TraceStep,
)


def test_data_envelope_defaults() -> None:
    env = DataEnvelope()
    assert env.data_class == "public"
    assert env.allowed_recipients == []
    assert env.allowed_purpose == []
    assert env.can_store is True
    assert env.can_forward is True
    assert env.ttl_seconds is None
    assert env.requires_confirmation is False
    assert env.classification_source == "unknown"
    assert env.classification_mutable is False


def _valid_trace_kwargs() -> dict:
    return {
        "trace_id": "trc_demo",
        "pattern_id": "demo_pattern",
        "target": TargetDescriptor(type="mock_agent", name="demo", adapter="mock"),
        "graph_path": ["exposed_input", "observed_behavior"],
        "steps": [TraceStep(index=0, actor="harness", action="exposed_input")],
        "expected_vulnerable_behavior": "x",
        "observed_behavior": "y",
    }


def test_exploit_trace_rejects_empty_steps() -> None:
    kwargs = _valid_trace_kwargs()
    kwargs["steps"] = []
    with pytest.raises(ValidationError):
        ExploitTrace(**kwargs)


def test_exploit_trace_rejects_empty_required_strings_and_paths() -> None:
    for field, bad in (("trace_id", ""), ("pattern_id", ""), ("graph_path", [])):
        kwargs = _valid_trace_kwargs()
        kwargs[field] = bad
        with pytest.raises(ValidationError):
            ExploitTrace(**kwargs)


def test_exploit_trace_accepts_valid_trace_with_envelope() -> None:
    kwargs = _valid_trace_kwargs()
    kwargs["data_envelope"] = DataEnvelope(data_class="confidential", classification_mutable=False)
    kwargs["findings"] = [Finding(code="c", severity="high", message="m")]
    trace = ExploitTrace(**kwargs)
    assert trace.schema_version == "0.1"
    assert trace.data_envelope is not None
    assert trace.data_envelope.classification_mutable is False
    assert trace.findings[0].severity == "high"
