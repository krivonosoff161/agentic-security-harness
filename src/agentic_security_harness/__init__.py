"""Agentic Security Harness - defensive benchmark core.

Pipeline: ``pattern -> target -> trace -> scorecard``. No real LLM calls, no network,
no gateway. A ``DataEnvelope`` is a policy label, not encryption.
"""

from agentic_security_harness.corpus import CorpusEntry, corpus_manifest
from agentic_security_harness.demo_adapter import DemoAgentTarget, run_scenarios
from agentic_security_harness.demo_agent import DemoAgent
from agentic_security_harness.mock_target import MockTarget
from agentic_security_harness.models import (
    AuditEntry,
    CapabilityCheckResult,
    CapabilityToken,
    DataEnvelope,
    DefensivePattern,
    ExploitTrace,
    Finding,
    HealthStatus,
    Observation,
    Target,
    TargetDescriptor,
    TargetMetadata,
    ToolSchemaRecord,
    TraceStep,
)
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.protected_demo_agent import (
    ProtectedDemoAgent,
    ProtectedDemoAgentTarget,
)
from agentic_security_harness.remediation import (
    ControlRecommendation,
    RemediationReport,
    build_recommendations,
    build_remediation_md,
    remediation_to_json,
    write_remediation,
)
from agentic_security_harness.reporting import (
    build_comparison_md,
    build_executive_md,
    build_summary_md,
    scorecard_to_json,
    traces_to_json,
    write_comparison,
    write_reports,
)
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard
from agentic_security_harness.validation import ValidationResult, validate_path

__all__ = [
    "DataEnvelope",
    "CapabilityToken",
    "CapabilityCheckResult",
    "ToolSchemaRecord",
    "AuditEntry",
    "DefensivePattern",
    "ExploitTrace",
    "Finding",
    "HealthStatus",
    "Observation",
    "Target",
    "TargetDescriptor",
    "TargetMetadata",
    "TraceStep",
    "MockTarget",
    "DemoAgent",
    "DemoAgentTarget",
    "ProtectedDemoAgent",
    "ProtectedDemoAgentTarget",
    "run_scenarios",
    "HarnessRunner",
    "ScorecardSummary",
    "build_scorecard",
    "seed_patterns",
    "CorpusEntry",
    "corpus_manifest",
    "write_reports",
    "write_comparison",
    "build_summary_md",
    "build_executive_md",
    "build_comparison_md",
    "traces_to_json",
    "scorecard_to_json",
    "ValidationResult",
    "validate_path",
    "ControlRecommendation",
    "RemediationReport",
    "build_recommendations",
    "build_remediation_md",
    "remediation_to_json",
    "write_remediation",
]

__version__ = "0.10.0"
