"""Run configuration for external model/runtime adapter paths.

Stores metadata about an external run. Never stores API key values.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

_MAX_REPEATS = 10
_MAX_TOTAL_REQUESTS = 50


def _redact_url(url: str) -> str:
    """Redact credentials from a URL for safe storage."""
    if "@" in url:
        scheme_end = url.find("://")
        if scheme_end >= 0:
            after_scheme = url[scheme_end + 3 :]
            if "@" in after_scheme:
                _auth, host_part = after_scheme.rsplit("@", 1)
                return f"{url[:scheme_end + 3]}[REDACTED]@{host_part}"
    return url


class RunConfig(BaseModel):
    """Configuration for an external model/runtime benchmark run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.1"
    adapter_type: str = "openai-compatible"
    provider_label: str = ""
    base_url_label: str = ""
    model: str = ""
    temperature: float = 0.0
    timeout_seconds: int = 30
    repeats: int = 1
    scenario_id: str = ""
    max_variants: int = 1
    selected_variants: list[str] = Field(default_factory=list)
    request_count: int = 0
    deterministic: bool = False
    network_mode: str = "explicit-external"
    api_key_env: str = ""
    created_by: str = "ash run-external"
    safety_note: str = (
        "Experimental external run. Not a benchmark-grade measurement. "
        "Synthetic prompts only. No real data or tool execution."
    )


class ExternalRuntimeMetadata(BaseModel):
    """Runtime metadata for an external adapter run."""

    model_config = ConfigDict(extra="forbid")

    adapter_type: str = "openai-compatible"
    base_url_hash: str = ""
    model: str = ""
    temperature: float = 0.0
    timeout_seconds: int = 30
    deterministic: bool = False
    network_mode: str = "explicit-external"
    api_key_env: str = ""
    run_id: str = ""


class ExternalResult(BaseModel):
    """Outcome of one external prompt evaluation."""

    model_config = ConfigDict(extra="forbid")

    result_id: str
    pattern_id: str
    variant_id: str = ""
    repeat_index: int = 0
    decision: str = "unclear"
    reason: str = ""
    control_family: str = ""
    would_preserve_boundary: bool | None = None
    raw_response: str = ""
    parse_error: str = ""
    error: str = ""
    latency_ms: int = 0


class RepeatSummary(BaseModel):
    """Aggregated outcomes for one pattern across repeats."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    variant_id: str = ""
    total_repeats: int = 0
    pass_count: int = 0
    finding_count: int = 0
    inconclusive_count: int = 0
    error_count: int = 0
    flaky: bool = False
    dominant_outcome: str = "inconclusive"
    # One of: stable_pass, stable_finding, flaky, inconclusive, adapter_error.
    stability_status: str = "inconclusive"


class ExternalSummary(BaseModel):
    """Aggregated summary across all external results."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.1"
    scenario_id: str = ""
    adapter_type: str = ""
    model: str = ""
    total_checks: int = 0
    total_repeats: int = 0
    patterns_with_findings: list[str] = Field(default_factory=list)
    flaky_patterns: list[str] = Field(default_factory=list)
    inconclusive_patterns: list[str] = Field(default_factory=list)
    error_patterns: list[str] = Field(default_factory=list)
    repeat_summaries: list[RepeatSummary] = Field(default_factory=list)
    findings_by_decision: dict[str, int] = Field(default_factory=dict)
    findings_by_pattern: dict[str, int] = Field(default_factory=dict)
    findings_by_control_family: dict[str, int] = Field(default_factory=dict)
    generated_by: str = "ash run-external"
    safety_note: str = (
        "Experimental external run. Not a benchmark-grade measurement."
    )
