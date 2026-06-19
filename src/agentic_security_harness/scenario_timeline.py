"""Typed contract for time-shaped, multi-actor scenarios.

A *timeline* models a failure that does not appear in a single prompt: multi-turn drift,
delayed activation, context overload, or a handoff. It is a design/fixtures contract, not a
live multi-agent runtime - validating a timeline fixture says the scenario is well-formed,
not that real agents are covered.

The validator is *fail-closed*: a timeline without a boundary invariant, without a trace
evidence requirement, or with swapped protected/vulnerable expectations is rejected.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TIMELINE_SCHEMA_VERSION = "0.1"

# Allowed step actors and trust zones (kept in sync with docs/scenario-timeline.md).
ACTORS = frozenset(
    {"system", "user", "untrusted_source", "agent", "tool_result", "memory",
     "human_approver"}
)
TRUST_ZONES = frozenset({"trusted", "untrusted", "delegated", "ambient", "unknown"})
# Zones that carry pressure / must not silently gain authority.
_NON_TRUSTED_ZONES = TRUST_ZONES - {"trusted"}

# Outcome a deterministic validator must record for each kind of target. Stated explicitly
# so a fixture cannot quietly swap them.
_VULNERABLE_OUTCOME = "finding"
_PROTECTED_OUTCOME = "pass"


class TimelineStep(BaseModel):
    """One ordered step: who acts, from which trust zone, with what intended effect."""

    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1)
    actor: str
    trust_zone: str
    content_role: str = Field(min_length=1)
    expected_effect: str = Field(min_length=1)


class ValidatorExpectation(BaseModel):
    """What a deterministic validator must record on a vulnerable vs a protected target."""

    model_config = ConfigDict(extra="forbid")

    validator: str = Field(min_length=1)
    on_vulnerable: str
    on_protected: str


class ScenarioTimeline(BaseModel):
    """A time-shaped, multi-actor scenario contract with a deterministic invariant."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = TIMELINE_SCHEMA_VERSION
    timeline_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    failure_class: str = Field(min_length=1)
    topology: str = Field(min_length=1)
    invariant: str = Field(min_length=1)
    expected_vulnerable_behavior: str = Field(min_length=1)
    expected_protected_behavior: str = Field(min_length=1)
    steps: list[TimelineStep] = Field(min_length=2)
    validator_expectations: list[ValidatorExpectation] = Field(min_length=1)
    trace_evidence: list[str] = Field(min_length=1)
    stop_condition: str = Field(min_length=1)
    non_goals: list[str] = Field(default_factory=list)

    @property
    def actors(self) -> list[str]:
        """Distinct actors used across the timeline, in first-seen order."""
        seen: list[str] = []
        for step in self.steps:
            if step.actor not in seen:
                seen.append(step.actor)
        return seen


def _semantic_errors(tl: ScenarioTimeline) -> list[str]:
    """Fail-closed semantic checks beyond structural schema validation."""
    errors: list[str] = []
    if "trace" not in tl.trace_evidence:
        errors.append("trace_evidence must require a 'trace' artifact")
    if tl.expected_vulnerable_behavior == tl.expected_protected_behavior:
        errors.append("expected_vulnerable_behavior and expected_protected_behavior are identical")
    step_ids = [s.step_id for s in tl.steps]
    if len(set(step_ids)) != len(step_ids):
        errors.append("step_id values are not unique")
    for s in tl.steps:
        if s.actor not in ACTORS:
            errors.append(f"step '{s.step_id}' has unknown actor '{s.actor}'")
        if s.trust_zone not in TRUST_ZONES:
            errors.append(f"step '{s.step_id}' has unknown trust_zone '{s.trust_zone}'")
    zones = {s.trust_zone for s in tl.steps}
    if "trusted" not in zones:
        errors.append("timeline has no trusted boundary step")
    if not (zones & _NON_TRUSTED_ZONES):
        errors.append("timeline has no untrusted/delegated/ambient pressure step")
    for ve in tl.validator_expectations:
        # Protected/vulnerable expectations must not be swapped or collapsed.
        if ve.on_vulnerable != _VULNERABLE_OUTCOME or ve.on_protected != _PROTECTED_OUTCOME:
            errors.append(
                f"validator '{ve.validator}' expectations must be "
                f"on_vulnerable='{_VULNERABLE_OUTCOME}' / on_protected='{_PROTECTED_OUTCOME}' "
                f"(got '{ve.on_vulnerable}' / '{ve.on_protected}')"
            )
    return errors


def validate_timeline(raw: Any) -> list[str]:
    """Validate one timeline mapping. Returns a list of errors ([] means valid).

    Structural problems (missing invariant, missing evidence, extra keys, too few steps)
    surface as schema errors; semantic problems (swapped expectations, unknown actors,
    no pressure step) surface from ``_semantic_errors``. Either way an invalid timeline is
    rejected rather than silently accepted.
    """
    if not isinstance(raw, dict):
        return ["timeline must be a JSON object"]
    try:
        tl = ScenarioTimeline.model_validate(raw)
    except ValidationError as exc:
        return [
            f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg', 'invalid')}"
            for e in exc.errors()
        ]
    return _semantic_errors(tl)
