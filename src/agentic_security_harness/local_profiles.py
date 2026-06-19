"""Bounded local-model smoke profiles (the "Prometheus" role).

Each profile is a hardware-safe, capped configuration for a real local model-in-the-loop
probe through the prompt-only OpenAI-compatible path. A profile fixes the model, scenario
subset, repeats cap, timeout, request cap, and raw-response retention so a local smoke is
reproducible by name instead of a hand-copied command.

Profiles never execute tools and never call the network on their own - the suite command
runs dry-run by default and only calls a model on explicit ``--execute``. See
``docs/local-model-profiles.md`` and ``docs/local-prometheus-workflow.md``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# Hard ceiling shared with the external runner's cost cap; profiles must stay under it.
from agentic_security_harness.run_config import _MAX_TOTAL_REQUESTS


class LocalProfile(BaseModel):
    """One bounded local-model smoke configuration."""

    model_config = ConfigDict(extra="forbid")

    name: str
    preset: str
    model: str
    scenario_id: str
    max_variants: int
    repeats: int
    timeout_seconds: int
    max_requests: int
    raw_response_limit: int = 0
    note: str = ""


# Registry mirrors the documented profile table in docs/local-model-profiles.md.
LOCAL_PROFILES: dict[str, LocalProfile] = {
    "prometheus-lowmem-smoke": LocalProfile(
        name="prometheus-lowmem-smoke",
        preset="ollama",
        model="qwen2.5:1.5b",
        scenario_id="data-boundary",
        max_variants=1,
        repeats=1,
        timeout_seconds=60,
        max_requests=10,
        note="First local evidence; should fit an ~8 GB / GTX 1050 class machine.",
    ),
    "prometheus-lowmem-reliability": LocalProfile(
        name="prometheus-lowmem-reliability",
        preset="ollama",
        model="qwen2.5:1.5b",
        scenario_id="data-boundary",
        max_variants=1,
        repeats=3,
        timeout_seconds=90,
        max_requests=15,
        note="Check whether inconclusive/timeout states repeat across runs.",
    ),
    "prometheus-3b-experimental": LocalProfile(
        name="prometheus-3b-experimental",
        preset="ollama",
        model="qwen2.5:3b",
        scenario_id="data-boundary",
        max_variants=1,
        repeats=1,
        timeout_seconds=120,
        max_requests=10,
        note="Only if the machine stays responsive; may swap or stall on this profile.",
    ),
    "fake-local-control": LocalProfile(
        name="fake-local-control",
        preset="fake-local",
        model="fake-model",
        scenario_id="data-boundary",
        max_variants=1,
        repeats=1,
        timeout_seconds=30,
        max_requests=10,
        note="Bundled deterministic fake server; verify the path without model variability.",
    ),
}


def local_profile_names() -> list[str]:
    """All profile names, sorted."""
    return sorted(LOCAL_PROFILES)


def resolve_local_profile(name: str) -> LocalProfile:
    """Return a profile by name, or raise KeyError with a helpful message."""
    if name not in LOCAL_PROFILES:
        known = ", ".join(local_profile_names())
        raise KeyError(f"unknown local profile '{name}'. Known profiles: {known}")
    return LOCAL_PROFILES[name]


def _model_slug(model: str) -> str:
    """Filesystem-safe slug for a model id (``qwen2.5:1.5b`` -> ``qwen2.5-1.5b``)."""
    slug = "".join(c if c.isalnum() or c in "._-" else "-" for c in model)
    return slug.strip("-") or "model"


def default_output_dir(profile: LocalProfile) -> str:
    """Deterministic output path for a profile run (under ``reports/``)."""
    return f"reports/local-{profile.name}-{_model_slug(profile.model)}"


def max_total_requests() -> int:
    """The shared external-runner request ceiling (for bound checks/tests)."""
    return _MAX_TOTAL_REQUESTS
