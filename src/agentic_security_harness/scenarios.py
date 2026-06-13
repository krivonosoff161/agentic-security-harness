"""Scenario template layer: groups seed patterns into scenario families.

Each scenario defines a subset of patterns that share a common defensive boundary.
This does not mutate patterns or corpus definitions.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ScenarioTemplate(BaseModel):
    """A named family of patterns that share a defensive boundary theme."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    title: str
    description: str
    pattern_ids: list[str] = Field(default_factory=list)
    default_variant_knobs: dict[str, str] = Field(default_factory=dict)
    safety_note: str = (
        "Sanitized synthetic scenario; mock-only; no real data, network, or payloads."
    )


_SCENARIOS: list[ScenarioTemplate] = [
    ScenarioTemplate(
        scenario_id="data-boundary",
        title="Data boundary failures",
        description="Patterns where data-envelope labels, recipients, or forwarding rules fail.",
        pattern_ids=[
            "data_boundary_recipient_confusion",
            "data_boundary_classification_mutation",
            "data_boundary_handoff_label_stripping",
            "provider_boundary_leakage_sanitized",
        ],
        default_variant_knobs={
            "scope": "single-step",
            "recipient_count": "one",
            "tool_mode": "none",
        },
    ),
    ScenarioTemplate(
        scenario_id="memory-governance",
        title="Memory governance failures",
        description="Patterns where memory provenance, trust levels, TTL, "
        "or scope isolation break.",
        pattern_ids=[
            "memory_poisoning_sanitized",
            "sleeping_prompt.delayed_activation",
            "memory_governance.unscoped_memory_persistence",
            "memory_governance.environment_injected_poisoning",
            "memory_governance.unintentional_cross_user",
        ],
        default_variant_knobs={
            "scope": "multi-step",
            "memory_mode": "session",
            "tool_mode": "none",
        },
    ),
    ScenarioTemplate(
        scenario_id="tool-selection",
        title="Tool selection and schema failures",
        description="Patterns where tool-selection integrity, schema provenance, "
        "or permissions break.",
        pattern_ids=[
            "tool_permission_abuse_sanitized",
            "mcp.tool_schema_deception",
            "mcp.tool_selection_manipulation",
        ],
        default_variant_knobs={
            "scope": "single-step",
            "tool_mode": "read-write",
            "approval_mode": "none",
        },
    ),
    ScenarioTemplate(
        scenario_id="authority-control",
        title="Authority and capability control failures",
        description="Patterns where capability delegation, ambient authority, "
        "or scope expansion break.",
        pattern_ids=[
            "capability.delegation_chain_drift",
            "ambient_authority.environmental_privilege_escalation",
        ],
        default_variant_knobs={
            "scope": "multi-step",
            "approval_mode": "none",
            "budget_profile": "normal",
        },
    ),
    ScenarioTemplate(
        scenario_id="approval-audit",
        title="Approval context and audit integrity failures",
        description="Patterns where approval framing, audit completeness, "
        "or hash-chain integrity break.",
        pattern_ids=[
            "approval_laundering.underjustified_confirmation",
            "audit.spam_label_abuse",
            "audit.hash_chain_tamper",
        ],
        default_variant_knobs={
            "scope": "single-step",
            "approval_mode": "explicit",
            "budget_profile": "normal",
        },
    ),
    ScenarioTemplate(
        scenario_id="budget-control",
        title="Budget and recursion control failures",
        description="Patterns where step budgets, loop guards, or recursion depth limits break.",
        pattern_ids=[
            "budget.loop_abuse",
            "budget.recursive_execution_amplification",
        ],
        default_variant_knobs={
            "scope": "multi-step",
            "budget_profile": "constrained",
            "tool_mode": "none",
        },
    ),
    ScenarioTemplate(
        scenario_id="perception-boundary",
        title="Perception-boundary trust failures",
        description="Patterns where perception-channel content is mistaken "
        "for user intent or system directive.",
        pattern_ids=[
            "perception_boundary.sensor_command_confusion",
        ],
        default_variant_knobs={
            "scope": "single-step",
            "memory_mode": "off",
            "tool_mode": "none",
        },
    ),
    ScenarioTemplate(
        scenario_id="all",
        title="All patterns",
        description="Every implemented seed pattern in the corpus (22 patterns).",
        pattern_ids=[
            "indirect_prompt_injection_via_tool_output",
            "data_boundary_recipient_confusion",
            "memory_poisoning_sanitized",
            "data_boundary_classification_mutation",
            "data_boundary_handoff_label_stripping",
            "tool_permission_abuse_sanitized",
            "provider_boundary_leakage_sanitized",
            "sleeping_prompt.delayed_activation",
            "audit.spam_label_abuse",
            "budget.loop_abuse",
            "capability.delegation_chain_drift",
            "mcp.tool_schema_deception",
            "audit.hash_chain_tamper",
            "perception_boundary.sensor_command_confusion",
            "ambient_authority.environmental_privilege_escalation",
            "approval_laundering.underjustified_confirmation",
            "memory_governance.unscoped_memory_persistence",
            "memory_governance.environment_injected_poisoning",
            "memory_governance.unintentional_cross_user",
            "budget.recursive_execution_amplification",
            "mcp.tool_selection_manipulation",
            "indirect_instruction.multi_turn_escalation",
        ],
        default_variant_knobs={
            "scope": "single-step",
            "memory_mode": "off",
            "recipient_count": "one",
            "tool_mode": "none",
            "approval_mode": "none",
            "budget_profile": "normal",
        },
    ),
]


def list_scenarios() -> list[ScenarioTemplate]:
    """Return all registered scenario templates."""
    return list(_SCENARIOS)


def get_scenario(scenario_id: str) -> ScenarioTemplate:
    """Get a scenario template by id.

    Raises ``KeyError`` with a helpful message if the id is unknown.
    """
    for scenario in _SCENARIOS:
        if scenario.scenario_id == scenario_id:
            return scenario
    known = ", ".join(s.scenario_id for s in _SCENARIOS)
    raise KeyError(f"unknown scenario id '{scenario_id}'. Known scenarios: {known}")


def scenario_ids() -> list[str]:
    """Return just the registered scenario ids."""
    return [s.scenario_id for s in _SCENARIOS]
