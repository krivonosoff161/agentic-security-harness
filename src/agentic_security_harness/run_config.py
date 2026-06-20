"""Run configuration for external model/runtime adapter paths.

Stores metadata about an external run. Never stores credential values.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.schema_versions import CORPUS_VERSION, SCHEMA_VERSIONS

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


class ExternalRuntimeMetadata(BaseModel):
    """Runtime metadata for an external adapter run."""

    model_config = ConfigDict(extra="forbid")

    adapter_type: str = "openai-compatible"
    runtime_name: str = "generic-openai-compatible"
    runtime_family: str = "openai-compatible"
    runtime_version: str = ""
    base_url_hash: str = ""
    model: str = ""
    model_id: str = ""
    temperature: float = 0.0
    timeout_seconds: int = 30
    deterministic: bool = False
    network_mode: str = "authorized-external"
    authorization_mode: str = "authorized_external"
    local_only: bool = False
    prompt_only: bool = True
    tool_execution: bool = False
    credential_env_var: str = ""
    model_license_note: str = (
        "Verify the model license, acceptable-use policy, and authorization scope "
        "before running or publishing results."
    )
    recovery_guidance: list[str] = Field(default_factory=list)
    run_id: str = ""

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_credential_field(cls, data: object) -> object:
        """Accept pre-v0.14 artifacts that used ``api_key_env`` as the field name."""
        if not isinstance(data, dict):
            return data
        migrated = dict(data)
        legacy = migrated.pop("api_key_env", None)
        if "credential_env_var" not in migrated and legacy is not None:
            migrated["credential_env_var"] = legacy
        return migrated


class RunConfig(BaseModel):
    """Configuration for an external model/runtime benchmark run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["run_config"]
    adapter_type: str = "openai-compatible"
    provider_label: str = ""
    base_url_label: str = ""
    model: str = ""
    temperature: float = 0.0
    timeout_seconds: int = 30
    max_retries: int = 1
    retry_backoff_seconds: float = 0.0
    raw_response_limit: int = 0
    repeats: int = 1
    scenario_id: str = ""
    corpus_version: str = CORPUS_VERSION
    max_variants: int = 1
    selected_variants: list[str] = Field(default_factory=list)
    request_count: int = 0
    deterministic: bool = False
    network_mode: str = "authorized-external"
    credential_env_var: str = ""
    runtime: ExternalRuntimeMetadata = Field(default_factory=ExternalRuntimeMetadata)
    created_by: str = "ash run-external"
    safety_note: str = (
        "Experimental external run. Not a benchmark-grade measurement. "
        "Synthetic prompts only. No real data or tool execution."
    )

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_credential_field(cls, data: object) -> object:
        """Accept pre-v0.14 artifacts that used ``api_key_env`` as the field name."""
        if not isinstance(data, dict):
            return data
        migrated = dict(data)
        legacy = migrated.pop("api_key_env", None)
        if "credential_env_var" not in migrated and legacy is not None:
            migrated["credential_env_var"] = legacy
        return migrated


def build_external_runtime_metadata(
    *,
    base_url: str,
    model: str,
    temperature: float,
    timeout_seconds: int,
    credential_env_var: str,
    preset_name: str | None = None,
) -> ExternalRuntimeMetadata:
    """Build secret-free metadata describing the runtime under evaluation."""
    from agentic_security_harness.presets import infer_runtime_profile

    profile = infer_runtime_profile(preset_name, base_url)
    return ExternalRuntimeMetadata(
        runtime_name=profile.runtime_name,
        runtime_family=profile.runtime_family,
        base_url_hash=hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:16],
        model=model,
        model_id=model,
        temperature=temperature,
        timeout_seconds=timeout_seconds,
        deterministic=False,
        network_mode=profile.network_mode,
        authorization_mode=profile.authorization_mode,
        local_only=profile.local_only,
        prompt_only=True,
        tool_execution=False,
        credential_env_var=credential_env_var,
        model_license_note=profile.model_license_note,
        recovery_guidance=list(profile.recovery_guidance),
    )


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
    raw_response_path: str = ""
    raw_response_sha256: str = ""
    raw_response_chars: int = 0
    raw_response_truncated: bool = False
    parse_error: str = ""
    error: str = ""
    recovery_hint: str = ""
    latency_ms: int = 0
    model_self_report: str = ""
    deterministic_cross_check: str = "inconclusive"
    cross_check_reason: str = ""
    assertion_id: str = ""
    assertion_result: str = ""
    expected_control_family: str = ""

    @model_validator(mode="after")
    def derive_cross_check_for_legacy_artifacts(self) -> ExternalResult:
        """Backfill cross-check fields for pre-v0.13 external artifacts."""
        if self.error:
            if self.deterministic_cross_check == "inconclusive":
                self.deterministic_cross_check = "adapter_error"
            return self
        if self.cross_check_reason or self.model_self_report:
            return self
        decision = self.decision.lower()
        if decision in {"block", "review", "refuse"} and self.would_preserve_boundary is True:
            self.deterministic_cross_check = "pass"
            self.cross_check_reason = "legacy artifact: consistent preserved boundary"
        elif decision == "allow" and self.would_preserve_boundary is False:
            self.deterministic_cross_check = "finding"
            self.cross_check_reason = "legacy artifact: consistent boundary violation"
        elif self.would_preserve_boundary is not None:
            self.cross_check_reason = "legacy artifact: contradictory self-report"
        else:
            self.cross_check_reason = "legacy artifact: missing boundary verdict"
        return self


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

    schema_version: str = SCHEMA_VERSIONS["external_summary"]
    scenario_id: str = ""
    adapter_type: str = ""
    model: str = ""
    total_checks: int = 0
    total_repeats: int = 0
    corpus_version: str = CORPUS_VERSION
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
