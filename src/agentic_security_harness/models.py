"""Pydantic v2 models for the v0.1 harness core.

A ``DataEnvelope`` is a *policy label* that must survive transformation across agent
handoffs, memory writes, tool calls, and provider routing. It is **NOT encryption** -
encryption protects transport/storage and does not solve prompt injection.
"""

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class DataEnvelope(BaseModel):
    """Policy label travelling alongside a data item. Not encryption."""

    model_config = ConfigDict(extra="forbid")

    data_class: str = "public"
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_purpose: list[str] = Field(default_factory=list)
    can_store: bool = True
    can_forward: bool = True
    ttl_seconds: int | None = None
    requires_confirmation: bool = False
    classification_source: str = "unknown"
    classification_mutable: bool = False


class CapabilityToken(BaseModel):
    """Synthetic authority grant used by delegation-chain tests."""

    model_config = ConfigDict(extra="forbid")

    issuer: str
    subject: str
    scope: list[str] = Field(default_factory=list)
    purpose: str
    ttl_steps: int
    can_delegate: bool = False
    depth: int = 0


class ToolSchemaRecord(BaseModel):
    """Pinned mock tool-schema metadata for schema-provenance tests."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    schema_hash: str
    source: str
    read_only: bool = True
    annotations_trusted: bool = False


class AuditEntry(BaseModel):
    """Append-only local audit/trace entry with a hash-chain link."""

    model_config = ConfigDict(extra="forbid")

    index: int
    event: str
    previous_hash: str
    entry_hash: str


class PerceptionTranscript(BaseModel):
    """Synthetic perception-channel content with provenance metadata."""

    model_config = ConfigDict(extra="forbid")

    source_channel: str
    content: str
    confidence: float = 1.0
    human_perceptibility: str = "low"


class MemoryEntry(BaseModel):
    """A memory record with full governance metadata."""

    model_config = ConfigDict(extra="forbid")

    key: str
    value: str
    source: str
    trust_level: str
    classification_source: str
    ttl_seconds: int | None = None
    write_timestamp: int = 0


class Finding(BaseModel):
    """A single observed violation in a trace."""

    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Severity
    message: str
    broke_at: str | None = None
    mitigation: str | None = None


class TraceStep(BaseModel):
    """One step along a trace's path through the attack graph."""

    model_config = ConfigDict(extra="forbid")

    index: int
    actor: str
    action: str
    input_ref: str | None = None
    observed: str | None = None


class TargetDescriptor(BaseModel):
    """Abstract description of the system under test (keeps traces portable)."""

    model_config = ConfigDict(extra="forbid")

    type: str
    name: str
    adapter: str


class ExploitTrace(BaseModel):
    """The core artifact: a portable, machine-readable record of one pattern run."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(min_length=1)
    schema_version: str = "0.1"
    pattern_id: str = Field(min_length=1)
    target: TargetDescriptor
    graph_path: list[str] = Field(min_length=1)
    steps: list[TraceStep] = Field(min_length=1)
    expected_vulnerable_behavior: str
    observed_behavior: str
    findings: list[Finding] = Field(default_factory=list)
    data_envelope: DataEnvelope | None = None
    reproducibility: dict[str, str | int | bool] = Field(default_factory=dict)


class DefensivePattern(BaseModel):
    """A sanitized defensive test pattern the runner drives against a target."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str = Field(min_length=1)
    name: str
    category: str
    description: str
    graph_path: list[str] = Field(min_length=1)
    expected_vulnerable_behavior: str
    mitigation: str
    data_envelope: DataEnvelope | None = None


class Observation(BaseModel):
    """What a target reports back to the runner for one pattern run."""

    model_config = ConfigDict(extra="forbid")

    steps: list[TraceStep]
    observed_behavior: str
    findings: list[Finding] = Field(default_factory=list)


class Target(Protocol):
    """Structural interface every target adapter implements for the runner."""

    name: str

    def descriptor_fields(self) -> tuple[str, str, str]: ...

    def observe(self, pattern: DefensivePattern) -> Observation: ...
