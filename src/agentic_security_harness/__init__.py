"""Agentic Security Harness - defensive benchmark core.

Pipeline: ``pattern -> target -> trace -> scorecard``. Built-in/local targets are
deterministic and offline (no network, no provider calls). The experimental
``run-external`` path makes OpenAI-compatible calls only on explicit opt-in; native
provider and agent-host adapters are future. A ``DataEnvelope`` is a policy label, not
encryption.
"""

from agentic_security_harness.adapter_base import TargetAdapterBase
from agentic_security_harness.corpus import CorpusEntry, corpus_manifest
from agentic_security_harness.demo_adapter import DemoAgentTarget, run_scenarios
from agentic_security_harness.demo_agent import DemoAgent
from agentic_security_harness.doctor import DoctorReport, run_doctor
from agentic_security_harness.html_report import render_report, write_html_report
from agentic_security_harness.local_swarm import (
    LocalSwarmSummary,
    SwarmMetrics,
    SwarmScenarioResult,
    estimate_request_count,
    run_local_swarm,
)
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
from agentic_security_harness.presets import Preset, apply_preset, list_presets
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
from agentic_security_harness.run_diff import RunDiff, diff_runs, write_run_diff
from agentic_security_harness.run_manifest import (
    RunManifest,
    build_manifest,
    load_run_manifests,
    write_run_manifest,
)
from agentic_security_harness.rundb import index_runs, list_db_runs
from agentic_security_harness.runner import HarnessRunner
from agentic_security_harness.scenario_timeline import (
    ScenarioTimeline,
    TimelineReplay,
    TimelineReplayStep,
    TimelineValidatorResult,
    replay_timeline,
    validate_timeline,
)
from agentic_security_harness.schema_versions import (
    SCHEMA_VERSIONS,
    check_schema_version,
    schema_version,
)
from agentic_security_harness.scorecard import ScorecardSummary, build_scorecard
from agentic_security_harness.standards_mapping import (
    CategoryStandards,
    standards_mapping,
    validate_standards_mapping,
)
from agentic_security_harness.stats import (
    RetentionCandidate,
    RetentionPlan,
    RunStats,
    apply_retention_plan,
    build_retention_plan,
    build_run_stats,
    write_run_stats,
)
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
    "TargetAdapterBase",
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
    "SCHEMA_VERSIONS",
    "schema_version",
    "check_schema_version",
    "RunDiff",
    "diff_runs",
    "write_run_diff",
    "ScenarioTimeline",
    "TimelineReplay",
    "TimelineReplayStep",
    "TimelineValidatorResult",
    "replay_timeline",
    "validate_timeline",
    "Preset",
    "list_presets",
    "apply_preset",
    "index_runs",
    "list_db_runs",
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
    "RunManifest",
    "build_manifest",
    "write_run_manifest",
    "load_run_manifests",
    "render_report",
    "write_html_report",
    "LocalSwarmSummary",
    "SwarmMetrics",
    "SwarmScenarioResult",
    "run_local_swarm",
    "estimate_request_count",
    "run_doctor",
    "DoctorReport",
    "CategoryStandards",
    "standards_mapping",
    "validate_standards_mapping",
    "RunStats",
    "RetentionCandidate",
    "RetentionPlan",
    "build_run_stats",
    "write_run_stats",
    "build_retention_plan",
    "apply_retention_plan",
    "ControlRecommendation",
    "RemediationReport",
    "build_recommendations",
    "build_remediation_md",
    "remediation_to_json",
    "write_remediation",
]

__version__ = "0.14.0"
