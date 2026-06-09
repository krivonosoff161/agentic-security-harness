"""Agentic Security Harness - v0.1 core.

Pipeline: ``pattern -> mock target -> trace -> scorecard``. No real LLM calls, no network,
no gateway. A ``DataEnvelope`` is a policy label, not encryption.
"""

from agentic_security_harness.mock_target import MockTarget, Observation
from agentic_security_harness.models import (
    DataEnvelope,
    DefensivePattern,
    ExploitTrace,
    Finding,
    TargetDescriptor,
    TraceStep,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.reporting import (
    build_summary_md,
    scorecard_to_json,
    traces_to_json,
    write_reports,
)
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard

__all__ = [
    "DataEnvelope",
    "DefensivePattern",
    "ExploitTrace",
    "Finding",
    "TargetDescriptor",
    "TraceStep",
    "MockTarget",
    "Observation",
    "HarnessRunner",
    "ScorecardSummary",
    "build_scorecard",
    "seed_patterns",
    "write_reports",
    "build_summary_md",
    "traces_to_json",
    "scorecard_to_json",
]

__version__ = "0.1.0"
