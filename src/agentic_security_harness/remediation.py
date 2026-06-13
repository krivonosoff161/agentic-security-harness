"""Structured control recommendations for benchmark findings.

Produces deterministic, pattern-mapped remediation advice: what control family is
missing, what minimal fix exists, what stronger architecture looks like, and how
to verify the fix.  All content is synthetic benchmark language — no real exploit
guidance, no real system instructions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.models import ExploitTrace, Severity
from agentic_security_harness.scorecard import ScorecardSummary

Severity = Severity  # re-export for type annotations

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

ControlFamily = Literal[
    "provenance",
    "data_boundary",
    "memory_governance",
    "tool_selection",
    "capability_control",
    "approval_context",
    "audit_completeness",
    "budget_control",
    "perception_boundary",
    "provider_boundary",
    "adapter_metadata",
]

ControlPriority = Literal["p0", "p1", "p2", "p3"]


class ControlRecommendation(BaseModel):
    """A single structured control recommendation for a finding."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    finding_code: str
    control_family: ControlFamily
    priority: ControlPriority
    quick_fix: str
    engineering_fix: str
    architecture_fix: str
    verification: str
    residual_risk: str


class RemediationReport(BaseModel):
    """Aggregated remediation recommendations for a benchmark run."""

    model_config = ConfigDict(extra="forbid")

    target_name: str
    total_patterns: int
    total_findings: int
    recommendations: list[ControlRecommendation]
    control_families: list[str] = Field(default_factory=list)
    generated_from: str


# ---------------------------------------------------------------------------
# Pattern → control family mapping (deterministic)
# ---------------------------------------------------------------------------

_FAMILY_MAP: dict[str, ControlFamily] = {
    # indirect injection
    "indirect_prompt_injection_via_tool_output": "provenance",
    # data boundary
    "data_boundary_recipient_confusion": "data_boundary",
    "data_boundary_classification_mutation": "data_boundary",
    "data_boundary_handoff_label_stripping": "data_boundary",
    "provider_boundary_leakage_sanitized": "provider_boundary",
    # memory
    "memory_poisoning_sanitized": "memory_governance",
    "sleeping_prompt.delayed_activation": "memory_governance",
    "memory_governance.unscoped_memory_persistence": "memory_governance",
    "memory_governance.environment_injected_poisoning": "memory_governance",
    "memory_governance.unintentional_cross_user": "memory_governance",
    # tool
    "tool_permission_abuse_sanitized": "tool_selection",
    "mcp.tool_schema_deception": "tool_selection",
    "mcp.tool_selection_manipulation": "tool_selection",
    # capability
    "capability.delegation_chain_drift": "capability_control",
    "ambient_authority.environmental_privilege_escalation": "capability_control",
    # approval
    "approval_laundering.underjustified_confirmation": "approval_context",
    # audit
    "audit.spam_label_abuse": "audit_completeness",
    "audit.hash_chain_tamper": "audit_completeness",
    # budget
    "budget.loop_abuse": "budget_control",
    "budget.recursive_execution_amplification": "budget_control",
    # perception
    "perception_boundary.sensor_command_confusion": "perception_boundary",
    # multi-turn
    "indirect_instruction.multi_turn_escalation": "provenance",
}

# ---------------------------------------------------------------------------
# Finding severity → priority mapping
# ---------------------------------------------------------------------------

_SEV_PRIORITY: dict[str, ControlPriority] = {
    "critical": "p0",
    "high": "p1",
    "medium": "p2",
    "low": "p3",
    "info": "p3",
}

# ---------------------------------------------------------------------------
# Control recommendation templates (deterministic, per family)
# ---------------------------------------------------------------------------

_TEMPLATES: dict[ControlFamily, dict[str, str]] = {
    "provenance": {
        "quick_fix": (
            "Tag all external/tool/retrieval output with a source provenance label "
            "before it enters the agent context."
        ),
        "engineering_fix": (
            "Implement a provenance propagation layer: every content item carries "
            "source_channel, trust_level, and classification_source through the "
            "full pipeline (ingest → context → decision → action → memory)."
        ),
        "architecture_fix": (
            "Adopt a formal information-flow control model (e.g. CaMeL/FIDES-style "
            "label separation) where untrusted content cannot influence privileged "
            "actions without explicit declassification."
        ),
        "verification": (
            "Re-run the affected pattern with the control active; the baseline "
            "finding should disappear and the protected trace should show "
            "provenance tags in every step."
        ),
        "residual_risk": (
            "Semantic similarity between trusted and untrusted content may still "
            "cause confusion; cross-modal injection vectors require additional "
            "perception-layer controls."
        ),
    },
    "data_boundary": {
        "quick_fix": (
            "Enforce the data envelope recipient allow-list and forward gate "
            "before any routing or handoff."
        ),
        "engineering_fix": (
            "Propagate the full DataEnvelope (data_class, allowed_recipients, "
            "allowed_purpose, can_forward, can_store, ttl) across every agent "
            "handoff, memory write, tool call, and provider route. Reject "
            "operations where envelope fields are missing or mutated."
        ),
        "architecture_fix": (
            "Implement label-propagation middleware that intercepts every data "
            "transfer and validates envelope integrity against a policy engine. "
            "Classify the envelope as immutable by default."
        ),
        "verification": (
            "Re-run boundary patterns (recipient, classification, handoff, "
            "provider); all should produce PASS traces with envelope intact."
        ),
        "residual_risk": (
            "Labels can be missing or wrong at ingestion time; users may "
            "manually exfiltrate data outside the envelope; detection has "
            "false negatives."
        ),
    },
    "memory_governance": {
        "quick_fix": (
            "Preserve source provenance and TTL on every memory write; treat "
            "all retrieved/stored content as untrusted at read time."
        ),
        "engineering_fix": (
            "Implement per-entry memory governance: provenance tracking, "
            "trust-level precedence on conflict, TTL enforcement at read, "
            "per-user scope isolation, and deletion requiring trusted "
            "authorization."
        ),
        "architecture_fix": (
            "Adopt a trust-scored memory store with Bayesian or deterministic "
            "trust-level precedence, cross-session provenance, and memory-"
            "persistent information-flow control (per SuperLocalMemory / "
            "Misattribution Gap research)."
        ),
        "verification": (
            "Re-run all memory governance patterns; verify provenance tags "
            "survive cross-session and cross-user scenarios."
        ),
        "residual_risk": (
            "Semantic norm drift (trust laundering through legitimate recall) "
            "and unintentional cross-user contamination without adversarial "
            "intent remain hard to detect deterministically."
        ),
    },
    "tool_selection": {
        "quick_fix": (
            "Validate the selected tool against the task intent before "
            "execution; reject selection influenced by untrusted content."
        ),
        "engineering_fix": (
            "Pin tool-schema provenance per run; treat annotations as "
            "untrusted until approved; validate tool output against the "
            "declared schema; re-check schema hash before each call."
        ),
        "architecture_fix": (
            "Implement a tool-registry trust layer with cryptographic schema "
            "attestation, selection-integrity checks, and least-privilege "
            "tool scoping per task."
        ),
        "verification": (
            "Re-run tool-selection and schema-deception patterns; verify "
            "the agent rejects biased selection and detects schema drift."
        ),
        "residual_risk": (
            "Context-agnostic tool-selection attacks (e.g. Function Hijacking) "
            "may bypass task-relevance defenses; adaptive tool selection "
            "requires runtime integrity monitoring."
        ),
    },
    "capability_control": {
        "quick_fix": (
            "Enforce most-restrictive-scope-wins on every delegation; "
            "reject ambient capabilities not explicitly bound in the envelope."
        ),
        "engineering_fix": (
            "Implement capability tokens with issuer, subject, scope, "
            "purpose, TTL, delegation depth, and revocation. Check "
            "capability at every use; enforce bounded delegation depth."
        ),
        "architecture_fix": (
            "Adopt a capability-based security model (per Progent / MAPL) "
            "with monotonic confinement: effective action space can only "
            "shrink without explicit approval."
        ),
        "verification": (
            "Re-run delegation-drift and ambient-authority patterns; "
            "verify scope never expands and ambient use is denied."
        ),
        "residual_risk": (
            "Capability revocation propagation in multi-agent systems "
            "may have latency windows; capability token format is not "
            "yet standardized across agent frameworks."
        ),
    },
    "approval_context": {
        "quick_fix": (
            "Include data_class, recipient, purpose, and risk level in "
            "every approval request; one action per confirmation."
        ),
        "engineering_fix": (
            "Implement structured approval requests with mandatory envelope "
            "context; reject on ambiguity; log approval framing for audit."
        ),
        "architecture_fix": (
            "Adopt a formal approval protocol with cryptographic attestation "
            "of what was presented to the human vs. what was authorized; "
            "detect batch-laundering and euphemism patterns."
        ),
        "verification": (
            "Re-run approval-laundering pattern; verify the protected "
            "agent's approval request includes full envelope context."
        ),
        "residual_risk": (
            "Social engineering of human approvers remains a residual risk; "
            "approval protocol cannot fully prevent informed-consent failures "
            "if the human does not read the request carefully."
        ),
    },
    "audit_completeness": {
        "quick_fix": (
            "Log every sensitive event regardless of labels; never suppress "
            "audit entries based on untrusted content."
        ),
        "engineering_fix": (
            "Implement append-only, hash-chained audit trails with "
            "decision context (what triggered the action), data envelope, "
            "and policy rule recorded in each entry."
        ),
        "architecture_fix": (
            "Adopt a structured audit representation (e.g. Agent-BOM "
            "graph model) with causal-chain provenance, tamper-evidence, "
            "and informational completeness requirements."
        ),
        "verification": (
            "Re-run audit patterns; verify hash-chain integrity and that "
            "audit entries include decision context."
        ),
        "residual_risk": (
            "Covert inter-agent channels (per Vaikuntanathan-Zamir) can "
            "produce transcripts computationally indistinguishable from "
            "honest interactions; transcript auditing alone is insufficient."
        ),
    },
    "budget_control": {
        "quick_fix": (
            "Enforce per-run step budgets and loop guards; stop at the "
            "configured cap and surface the overrun."
        ),
        "engineering_fix": (
            "Implement recursion depth limits, call-graph cycle detection, "
            "and energy budget enforcement; detect recursive amplification "
            "patterns (Semantic Closure)."
        ),
        "architecture_fix": (
            "Adopt a resource-governance layer with per-agent, per-tool, "
            "and per-session budget caps; integrate with the permission "
            "layer to prevent budget bypass."
        ),
        "verification": (
            "Re-run budget and recursion patterns; verify the depth guard "
            "and step budget are enforced."
        ),
        "residual_risk": (
            "Semantic Closure exploitation (per Mobius Injection research) "
            "is model-specific; deterministic tests may not capture all "
            "recursive patterns in real LLM agents."
        ),
    },
    "perception_boundary": {
        "quick_fix": (
            "Treat all perception-channel content (OCR, ASR, HTML parse) "
            "as untrusted data; never execute actions from perception "
            "transcripts without explicit user instruction."
        ),
        "engineering_fix": (
            "Implement perception provenance tagging: every transcript "
            "carries source_channel, confidence, and human_perceptibility; "
            "low-confidence content is quarantined, not acted on."
        ),
        "architecture_fix": (
            "Adopt a cross-modal consistency check layer; lowest-confidence "
            "channel quarantine; explicit user disambiguation for "
            "conflicting perception inputs."
        ),
        "verification": (
            "Re-run perception-boundary pattern; verify the agent does not "
            "act on transcript content as user instruction."
        ),
        "residual_risk": (
            "Cross-modal coordinated injection (per CrossInject research) "
            "and 3D environment injection (per PI3D) are not yet tested; "
            "confidence-based quarantine may have false positives."
        ),
    },
    "provider_boundary": {
        "quick_fix": (
            "Enforce can_forward before any provider routing; redact "
            "restricted data at the boundary."
        ),
        "engineering_fix": (
            "Implement provider-boundary gate with envelope validation; "
            "log all provider-boundary crossings; block restricted data "
            "egress."
        ),
        "architecture_fix": (
            "Adopt a provider-boundary firewall with structured policy "
            "enforcement, redaction pipelines, and audit logging for "
            "every provider interaction."
        ),
        "verification": (
            "Re-run provider-boundary pattern; verify can_forward=false "
            "data is blocked before provider routing."
        ),
        "residual_risk": (
            "Multi-provider chaining may create implicit trust paths; "
            "provider-boundary controls must cover all egress points."
        ),
    },
    "adapter_metadata": {
        "quick_fix": (
            "Record adapter name, version, model family, and "
            "deterministic/stochastic flag in report artifacts."
        ),
        "engineering_fix": (
            "Implement TargetMetadata emission for all adapters; include "
            "runtime settings, tool registry hash, memory mode, and "
            "permission model."
        ),
        "architecture_fix": (
            "Adopt a provider/runtime-agnostic adapter contract with "
            "mandatory metadata, safety gates, and health checks before "
            "any non-synthetic adapter is accepted."
        ),
        "verification": (
            "Run ash validate; verify adapter-metadata.json is present "
            "and contains all required fields."
        ),
        "residual_risk": (
            "Adapter metadata is informational; it does not prevent "
            "boundary failures — it enables reproducibility and audit."
        ),
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_recommendations(
    traces: list[ExploitTrace],
    scorecard: ScorecardSummary | None = None,
) -> RemediationReport:
    """Build deterministic remediation recommendations from traces.

    Returns a ``RemediationReport`` with one ``ControlRecommendation`` per
    finding, grouped by control family.
    """
    recs: list[ControlRecommendation] = []
    for trace in traces:
        for finding in trace.findings:
            family = _FAMILY_MAP.get(trace.pattern_id, "provenance")
            template = _TEMPLATES[family]
            recs.append(
                ControlRecommendation(
                    pattern_id=trace.pattern_id,
                    finding_code=finding.code,
                    control_family=family,
                    priority=_SEV_PRIORITY.get(finding.severity, "p3"),
                    quick_fix=template["quick_fix"],
                    engineering_fix=template["engineering_fix"],
                    architecture_fix=template["architecture_fix"],
                    verification=template["verification"],
                    residual_risk=template["residual_risk"],
                )
            )
    families = sorted({r.control_family for r in recs})
    target = traces[0].target.name if traces else "unknown"
    total = scorecard.total_traces if scorecard else len(traces)
    return RemediationReport(
        target_name=target,
        total_patterns=total,
        total_findings=len(recs),
        recommendations=recs,
        control_families=[str(f) for f in families],
        generated_from="deterministic synthetic benchmark",
    )


def remediation_to_json(report: RemediationReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def build_remediation_md(report: RemediationReport) -> str:
    """Deterministic markdown remediation report."""
    lines: list[str] = [
        "# Agentic Security Harness - remediation recommendations",
        "",
        f"Target: `{report.target_name}`",
        "",
        f"- Total patterns: {report.total_patterns}",
        f"- Total findings with recommendations: {report.total_findings}",
        f"- Control families: "
        f"{', '.join(report.control_families) if report.control_families else '(none)'}",
        "",
    ]

    if not report.recommendations:
        lines += [
            "## Result",
            "",
            "No findings in this deterministic run. No control recommendations needed.",
            "",
        ]
        return "\n".join(lines)

    # Group by priority
    by_priority: dict[str, list[ControlRecommendation]] = {}
    for rec in report.recommendations:
        by_priority.setdefault(rec.priority, []).append(rec)

    lines += ["## Control priorities", ""]
    for p in ("p0", "p1", "p2", "p3"):
        recs = by_priority.get(p, [])
        if recs:
            families = sorted({r.control_family for r in recs})
            lines.append(f"- **{p.upper()}** ({len(recs)} findings): {', '.join(families)}")

    lines += ["", "## Findings mapped to controls", ""]
    lines.append("| Pattern | Finding | Family | Priority |")
    lines.append("|---|---|---|---|")
    for rec in report.recommendations:
        lines.append(
            f"| `{rec.pattern_id}` | {rec.finding_code} | {rec.control_family} | {rec.priority} |"
        )

    lines += ["", "## Quick fixes", ""]
    seen_families: set[str] = set()
    for rec in report.recommendations:
        if rec.control_family not in seen_families:
            seen_families.add(rec.control_family)
            lines.append(f"- **{rec.control_family}**: {rec.quick_fix}")

    lines += ["", "## Engineering fixes", ""]
    seen_families = set()
    for rec in report.recommendations:
        if rec.control_family not in seen_families:
            seen_families.add(rec.control_family)
            lines.append(f"- **{rec.control_family}**: {rec.engineering_fix}")

    lines += ["", "## Architecture fixes", ""]
    seen_families = set()
    for rec in report.recommendations:
        if rec.control_family not in seen_families:
            seen_families.add(rec.control_family)
            lines.append(f"- **{rec.control_family}**: {rec.architecture_fix}")

    lines += ["", "## Verification steps", ""]
    seen_families = set()
    for rec in report.recommendations:
        if rec.control_family not in seen_families:
            seen_families.add(rec.control_family)
            lines.append(f"- **{rec.control_family}**: {rec.verification}")

    lines += ["", "## Residual risk", ""]
    seen_families = set()
    for rec in report.recommendations:
        if rec.control_family not in seen_families:
            seen_families.add(rec.control_family)
            lines.append(f"- **{rec.control_family}**: {rec.residual_risk}")

    lines += [
        "",
        "> Recommendations are deterministic and synthetic. "
        "They do not guarantee real-world protection.",
        "",
    ]
    return "\n".join(lines)


def write_remediation(
    report: RemediationReport, out_dir: Path
) -> dict[str, Path]:
    """Write remediation artifacts into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "remediation_json": out_dir / "remediation.json",
        "remediation_md": out_dir / "remediation.md",
    }
    paths["remediation_json"].write_text(
        remediation_to_json(report), encoding="utf-8", newline="\n"
    )
    paths["remediation_md"].write_text(
        build_remediation_md(report), encoding="utf-8", newline="\n"
    )
    return paths
