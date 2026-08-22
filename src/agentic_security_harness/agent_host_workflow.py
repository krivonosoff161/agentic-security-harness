"""Privacy-minimized owned-workflow instrumentation and offline quickstart.

The collector accepts only canonical metadata and digest references.  Raw prompts,
tool arguments, tool results, credentials, endpoints, model output, and exception text
are intentionally absent from the API and from every public artifact.
"""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.agent_host_adapter import (
    AgentHostContractError,
    AgentHostDescriptorV1,
    AgentHostRecordingV1,
    build_agent_host_recording_v1,
    commit_agent_host_recording_v1,
    decode_agent_host_recording_v1,
    encode_agent_host_recording_v1,
)
from agentic_security_harness.agent_host_evaluator import (
    ADAPTER_ERROR_ACTIVITY,
    FINDING_ACTIVITY,
    INCONCLUSIVE_ACTIVITY,
    PASS_ACTIVITY,
    AgentHostEvaluationV1,
    agent_host_evaluation_ruleset_v1,
    commit_agent_host_evaluation_v1,
    decode_agent_host_evaluation_v1,
    encode_agent_host_evaluation_v1,
    evaluate_agent_host_recording_v1,
)
from agentic_security_harness.corpus import V1_PATTERN_IDS, corpus_manifest_sha256
from agentic_security_harness.models import DefensivePattern
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1
from agentic_security_harness.run_manifest import build_manifest, write_run_manifest
from agentic_security_harness.safe_io import (
    atomic_evidence_bundle,
    is_link_or_reparse,
    require_fresh_output_dir,
    write_text_artifact,
)
from agentic_security_harness.version import __version__

AGENT_HOST_RUN_SUMMARY_V1: Final[Literal["agent-host-run-summary-v1.0"]] = (
    "agent-host-run-summary-v1.0"
)
AGENT_HOST_QUICKSTART_WORKFLOW_ID: Final[
    Literal["synthetic.owned-agent-workflow"]
] = "synthetic.owned-agent-workflow"
AGENT_HOST_QUICKSTART_WORKFLOW_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
MAX_AGENT_HOST_SUMMARY_BYTES = 1_048_576
_TOKEN_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_RELATIVE_JSON_PATTERN = r"^(?:recordings|evaluations)/[a-z0-9_.-]+\.json$"
_FIXTURE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_FIXTURE_REPOSITORY_SHA = "0" * 40

AgentHostWorkflowMode = Literal["protected", "vulnerable"]
AgentHostWorkflowOutcome = Literal["pass", "finding", "inconclusive", "adapter_error"]


class AgentHostWorkflowContractError(AgentHostContractError):
    """Raised when the owned-workflow or bundle contract fails closed."""


class AgentHostCaseResultV1(BaseModel):
    """Content-bound public projection for one workflow case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_id: str = Field(pattern=_TOKEN_PATTERN)
    mode: AgentHostWorkflowMode
    recording_path: str = Field(pattern=_RELATIVE_JSON_PATTERN)
    evaluation_path: str = Field(pattern=_RELATIVE_JSON_PATTERN)
    recording_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    recording_commitment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_commitment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: AgentHostWorkflowOutcome


class AgentHostRunSummaryV1(BaseModel):
    """Closed public summary of deterministic owned-workflow observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["agent-host-run-summary-v1.0"]
    summary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_version: Literal["1.0.0"]
    corpus_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ruleset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workflow_id: Literal["synthetic.owned-agent-workflow"]
    workflow_version: Literal["1.0.0"]
    case_count: int = Field(ge=1, le=48)
    cases: tuple[AgentHostCaseResultV1, ...] = Field(min_length=1, max_length=48)
    outcomes: dict[AgentHostWorkflowOutcome, int]
    network_mode: Literal["off"]
    raw_payload_policy: Literal["digests_only"]
    producer_attestation: Literal["unattested"]
    outcome_scope: Literal["synthetic_fixture_not_security_certification"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_summary(self) -> AgentHostRunSummaryV1:
        if self.corpus_manifest_sha256 != corpus_manifest_sha256():
            raise ValueError("summary does not bind frozen corpus 1.0.0")
        if self.ruleset_sha256 != agent_host_evaluation_ruleset_v1().ruleset_sha256:
            raise ValueError("summary does not bind current Agent Host ruleset")
        if self.case_count != len(self.cases):
            raise ValueError("case_count must equal the number of cases")
        keys = tuple((case.pattern_id, case.mode) for case in self.cases)
        if len(keys) != len(set(keys)):
            raise ValueError("pattern and mode pairs must be unique")
        if any(case.pattern_id not in V1_PATTERN_IDS for case in self.cases):
            raise ValueError("summary contains a pattern outside frozen corpus 1.0.0")
        expected_outcomes = {name: 0 for name in _OUTCOME_ORDER}
        for case in self.cases:
            expected_outcomes[case.outcome] += 1
        if self.outcomes != expected_outcomes:
            raise ValueError("summary outcome counts do not match its cases")
        if self.summary_sha256 != _summary_identity(self):
            raise ValueError("summary_sha256 does not bind exact summary fields")
        return self


class AgentHostWorkflowResultV1(BaseModel):
    """In-memory result returned to an owned caller before publication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recording: AgentHostRecordingV1
    evaluation: AgentHostEvaluationV1


class OwnedAgentWorkflowV1(Protocol):
    """Explicit Python integration point for one owned workflow.

    Applications call this interface themselves.  The Harness never imports a caller
    supplied module, evaluates a command string, or executes instructions from evidence.
    """

    def run(self, pattern: DefensivePattern, session: AgentHostSessionV1) -> None: ...


class AgentHostSessionV1:
    """Append-only digest-only event collector for one explicitly owned workflow."""

    def __init__(
        self,
        *,
        pattern_id: str,
        repository_sha: str,
        occurred_at: datetime,
        host: AgentHostDescriptorV1 | None = None,
    ) -> None:
        if pattern_id not in V1_PATTERN_IDS:
            raise AgentHostWorkflowContractError("pattern_id is outside frozen corpus")
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise AgentHostWorkflowContractError("occurred_at must be timezone-aware")
        self.pattern_id = pattern_id
        self.repository_sha = repository_sha
        self.occurred_at = occurred_at.astimezone(UTC)
        self.host = host or _owned_fixture_host()
        self._events: list[CanonicalObservationEventV1] = []
        self._closed = False

    @property
    def events(self) -> tuple[CanonicalObservationEventV1, ...]:
        return tuple(self._events)

    @property
    def closed(self) -> bool:
        return self._closed

    def observe(
        self,
        *,
        source_surface: Literal[
            "agent",
            "tool",
            "mcp",
            "retrieval",
            "memory",
            "document",
            "app",
            "sensor",
            "environment",
            "provider",
            "audit",
            "model",
        ],
        activity: str,
        data_commitment_sha256: str,
        authority_commitment_sha256: str | None = None,
    ) -> CanonicalObservationEventV1:
        if self._closed:
            raise AgentHostWorkflowContractError("session is already terminal")
        sequence = len(self._events)
        parents = (self._events[-1].event_id,) if self._events else ()
        event_id = _digest_json(
            "agentic-security-harness/owned-workflow-event/v1.0",
            {
                "pattern_id": self.pattern_id,
                "repository_sha": self.repository_sha,
                "sequence": sequence,
                "occurred_at": self.occurred_at.isoformat(timespec="microseconds"),
                "source_surface": source_surface,
                "activity": activity,
                "data_commitment_sha256": data_commitment_sha256,
                "authority_commitment_sha256": authority_commitment_sha256,
                "parent_event_ids": parents,
            },
        )
        event = CanonicalObservationEventV1(
            schema_version="portfolio-observation-v1.0",
            event_id=event_id,
            project_id="agentic-security-harness",
            repository_id="example/owned-agent-host",
            repository_sha=self.repository_sha,
            occurred_at=self.occurred_at + timedelta(microseconds=sequence),
            producer_id_hash=_digest_text("synthetic-owned-agent-workflow-v1"),
            producer_attestation="unattested",
            source_surface=source_surface,
            activity=activity,
            entity_refs=(),
            parent_event_ids=parents,
            data_envelope_ref=data_commitment_sha256,
            authority_envelope_ref=authority_commitment_sha256,
            telemetry_state="complete",
            operational_authority="none",
        )
        self._events.append(event)
        return event

    def boundary_preserved(self) -> None:
        self._terminal(PASS_ACTIVITY, "protected-boundary-preserved")

    def boundary_violated(self) -> None:
        self._terminal(FINDING_ACTIVITY, "synthetic-boundary-violation")

    def inconclusive(self) -> None:
        self._terminal(INCONCLUSIVE_ACTIVITY, "synthetic-inconclusive")

    def adapter_error(self) -> None:
        self._terminal(ADAPTER_ERROR_ACTIVITY, "sanitized-adapter-error")

    def _terminal(self, activity: str, safe_reason: str) -> None:
        self.observe(
            source_surface="audit",
            activity=activity,
            data_commitment_sha256=_digest_text(safe_reason),
        )
        self._closed = True


class SyntheticOwnedAgentWorkflowV1:
    """Built-in no-network workflow exercising protected or vulnerable outcomes."""

    def __init__(self, mode: AgentHostWorkflowMode) -> None:
        self.mode = mode

    def run(self, pattern: DefensivePattern, session: AgentHostSessionV1) -> None:
        task_ref = _digest_text(f"task:{pattern.pattern_id}")
        session.observe(
            source_surface="app",
            activity="agent_host.task_received",
            data_commitment_sha256=task_ref,
        )
        session.observe(
            source_surface="tool",
            activity="tool.requested",
            data_commitment_sha256=_digest_text(f"request:{pattern.pattern_id}"),
        )
        synthetic_result = hashlib.sha256(
            f"synthetic-tool-result:{pattern.pattern_id}".encode("ascii")
        ).hexdigest()
        session.observe(
            source_surface="tool",
            activity="tool.completed",
            data_commitment_sha256=synthetic_result,
        )
        if self.mode == "protected":
            session.boundary_preserved()
        else:
            session.boundary_violated()


def run_owned_agent_workflow_v1(
    *,
    pattern: DefensivePattern,
    workflow: OwnedAgentWorkflowV1,
    repository_sha: str,
    occurred_at: datetime,
    host: AgentHostDescriptorV1 | None = None,
) -> AgentHostWorkflowResultV1:
    """Run one explicitly supplied owned workflow and sanitize adapter failures."""

    session = AgentHostSessionV1(
        pattern_id=pattern.pattern_id,
        repository_sha=repository_sha,
        occurred_at=occurred_at,
        host=host,
    )
    try:
        workflow.run(pattern, session)
    except Exception:  # noqa: BLE001 - raw exception content must never enter evidence
        if session.closed:
            raise AgentHostWorkflowContractError(
                "owned workflow failed after recording a terminal event"
            ) from None
        session.adapter_error()
    if not session.closed:
        session.inconclusive()
    terminal_status: Literal["completed", "inconclusive", "adapter_error"]
    terminal = session.events[-1].activity
    if terminal == ADAPTER_ERROR_ACTIVITY:
        terminal_status = "adapter_error"
    elif terminal == INCONCLUSIVE_ACTIVITY:
        terminal_status = "inconclusive"
    else:
        terminal_status = "completed"
    recording = build_agent_host_recording_v1(
        pattern_id=pattern.pattern_id,
        host=session.host,
        events=session.events,
        terminal_status=terminal_status,
    )
    return AgentHostWorkflowResultV1(
        recording=recording,
        evaluation=evaluate_agent_host_recording_v1(recording),
    )


def build_agent_host_quickstart_v1() -> tuple[
    AgentHostRunSummaryV1,
    tuple[AgentHostWorkflowResultV1, ...],
]:
    """Build the deterministic 24-pattern protected/vulnerable reference contour."""

    results: list[AgentHostWorkflowResultV1] = []
    cases: list[AgentHostCaseResultV1] = []
    offset = 0
    for pattern in seed_patterns():
        for mode in ("protected", "vulnerable"):
            result = run_owned_agent_workflow_v1(
                pattern=pattern,
                workflow=SyntheticOwnedAgentWorkflowV1(mode),
                repository_sha=_FIXTURE_REPOSITORY_SHA,
                occurred_at=_FIXTURE_TIME + timedelta(seconds=offset),
            )
            stem = f"{pattern.pattern_id}.{mode}"
            recording_commitment = commit_agent_host_recording_v1(result.recording)
            evaluation_commitment = commit_agent_host_evaluation_v1(result.evaluation)
            cases.append(
                AgentHostCaseResultV1(
                    pattern_id=pattern.pattern_id,
                    mode=mode,
                    recording_path=f"recordings/{stem}.json",
                    evaluation_path=f"evaluations/{stem}.json",
                    recording_id=result.recording.recording_id,
                    recording_commitment_sha256=recording_commitment.commitment_sha256,
                    evaluation_id=result.evaluation.evaluation_id,
                    evaluation_commitment_sha256=evaluation_commitment.commitment_sha256,
                    outcome=result.evaluation.outcome,
                )
            )
            results.append(result)
            offset += 1
    return _build_summary(tuple(cases)), tuple(results)


@atomic_evidence_bundle("out_dir")
def write_agent_host_quickstart_v1(out_dir: Path) -> AgentHostRunSummaryV1:
    """Write and atomically publish one fully validated public quickstart bundle."""

    require_fresh_output_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary, results = build_agent_host_quickstart_v1()
    for case, result in zip(summary.cases, results, strict=True):
        _write_canonical_bytes(
            out_dir / case.recording_path,
            encode_agent_host_recording_v1(result.recording),
        )
        _write_canonical_bytes(
            out_dir / case.evaluation_path,
            encode_agent_host_evaluation_v1(result.evaluation),
        )
    _write_canonical_bytes(
        out_dir / "agent_host_summary.json",
        encode_agent_host_summary_v1(summary),
    )
    write_text_artifact(out_dir / "summary.md", _summary_markdown(summary))
    artifacts = [
        "agent_host_summary.json",
        "summary.md",
        *(case.recording_path for case in summary.cases),
        *(case.evaluation_path for case in summary.cases),
    ]
    manifest = build_manifest(
        "agent_host",
        out_dir,
        target="synthetic-owned-agent-workflow",
        scenario="frozen-corpus-1.0.0",
        variants=["protected", "vulnerable"],
        outcomes={str(name): count for name, count in summary.outcomes.items()},
        metadata={
            "evidence_class": "deterministic_rule_derived_unattested_observation",
            "network_mode": "off",
            "raw_payload_policy": "digests_only",
            "operational_authority": "none",
            "summary_sha256": summary.summary_sha256,
        },
        artifacts=list(artifacts),
        tool_version=__version__,
    )
    write_run_manifest(out_dir, manifest)
    return summary


def encode_agent_host_summary_v1(summary: AgentHostRunSummaryV1) -> bytes:
    """Return the sole canonical UTF-8 JSON representation of a V1 summary."""

    encoded = json.dumps(
        summary.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_AGENT_HOST_SUMMARY_BYTES:
        raise AgentHostWorkflowContractError("summary exceeds the V1 byte limit")
    return encoded


def decode_agent_host_summary_v1(payload: bytes) -> AgentHostRunSummaryV1:
    """Decode exact canonical summary bytes with duplicate-field rejection."""

    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_AGENT_HOST_SUMMARY_BYTES:
        raise AgentHostWorkflowContractError("summary payload size is outside V1")
    try:
        decoded = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_json_object)
        summary = AgentHostRunSummaryV1.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AgentHostWorkflowContractError("summary payload violates canonical V1") from exc
    if encode_agent_host_summary_v1(summary) != payload:
        raise AgentHostWorkflowContractError("summary JSON is not canonical V1")
    return summary


def validate_agent_host_bundle_v1(root: Path) -> AgentHostRunSummaryV1:
    """Rebuild every recording/evaluation relationship in a public bundle."""

    summary = decode_agent_host_summary_v1(
        _safe_read_under(root, "agent_host_summary.json")
    )
    expected_files = {"agent_host_summary.json", "summary.md", "run_index.json"}
    for case in summary.cases:
        expected_files.update((case.recording_path, case.evaluation_path))
        recording = decode_agent_host_recording_v1(
            _safe_read_under(root, case.recording_path)
        )
        evaluation = decode_agent_host_evaluation_v1(
            _safe_read_under(root, case.evaluation_path)
        )
        rebuilt = evaluate_agent_host_recording_v1(recording)
        if evaluation != rebuilt:
            raise AgentHostWorkflowContractError("evaluation differs from deterministic rebuild")
        if (
            recording.pattern_id != case.pattern_id
            or recording.recording_id != case.recording_id
            or commit_agent_host_recording_v1(recording).commitment_sha256
            != case.recording_commitment_sha256
            or evaluation.evaluation_id != case.evaluation_id
            or commit_agent_host_evaluation_v1(evaluation).commitment_sha256
            != case.evaluation_commitment_sha256
            or evaluation.outcome != case.outcome
        ):
            raise AgentHostWorkflowContractError("case projection does not bind its artifacts")
    actual_files = {
        candidate.relative_to(root).as_posix()
        for candidate in root.rglob("*")
        if candidate.is_file()
    }
    if actual_files != expected_files:
        raise AgentHostWorkflowContractError("bundle file inventory differs from V1")
    return summary


def agent_host_run_summary_v1_json_schema() -> dict[str, Any]:
    """Return the public JSON Schema for the closed summary artifact."""

    return AgentHostRunSummaryV1.model_json_schema()


_OUTCOME_ORDER: Final[tuple[AgentHostWorkflowOutcome, ...]] = (
    "pass",
    "finding",
    "inconclusive",
    "adapter_error",
)


def _build_summary(cases: tuple[AgentHostCaseResultV1, ...]) -> AgentHostRunSummaryV1:
    outcomes = {name: 0 for name in _OUTCOME_ORDER}
    for case in cases:
        outcomes[case.outcome] += 1
    provisional = AgentHostRunSummaryV1.model_construct(
        schema_version=AGENT_HOST_RUN_SUMMARY_V1,
        summary_sha256="0" * 64,
        corpus_version="1.0.0",
        corpus_manifest_sha256=corpus_manifest_sha256(),
        ruleset_sha256=agent_host_evaluation_ruleset_v1().ruleset_sha256,
        workflow_id=AGENT_HOST_QUICKSTART_WORKFLOW_ID,
        workflow_version=AGENT_HOST_QUICKSTART_WORKFLOW_VERSION,
        case_count=len(cases),
        cases=cases,
        outcomes=outcomes,
        network_mode="off",
        raw_payload_policy="digests_only",
        producer_attestation="unattested",
        outcome_scope="synthetic_fixture_not_security_certification",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["summary_sha256"] = _summary_identity(provisional)
    return AgentHostRunSummaryV1.model_validate(payload)


def _owned_fixture_host() -> AgentHostDescriptorV1:
    return AgentHostDescriptorV1(
        schema_version="agent-host-descriptor-v1.0",
        adapter_id="reference.owned-workflow",
        adapter_version="1.0.0",
        host_type="owned.local.fixture",
        runtime_id="python",
        runtime_version="3.11-plus",
        capture_mode="recorded_offline",
        network_mode="off",
        raw_payload_policy="digests_only",
        producer_attestation="unattested",
        operational_authority="none",
    )


def _summary_identity(summary: AgentHostRunSummaryV1) -> str:
    return _digest_json(
        "agentic-security-harness/agent-host-run-summary/v1.0",
        summary.model_dump(mode="json", exclude={"summary_sha256"}),
    )


def _summary_markdown(summary: AgentHostRunSummaryV1) -> str:
    return (
        "# Agent Host owned-workflow quickstart\n\n"
        "Deterministic offline synthetic evidence; not a security certification.\n\n"
        f"- Cases: {summary.case_count}\n"
        f"- Pass: {summary.outcomes['pass']}\n"
        f"- Finding: {summary.outcomes['finding']}\n"
        f"- Inconclusive: {summary.outcomes['inconclusive']}\n"
        f"- Adapter error: {summary.outcomes['adapter_error']}\n"
        "- Network: off\n"
        "- Public payload policy: digests only\n"
        "- Producer attestation: unattested\n"
        "- Operational authority: none\n"
    )


def _write_canonical_bytes(path: Path, payload: bytes) -> None:
    write_text_artifact(path, payload.decode("utf-8"))


def _safe_read_under(root: Path, relative_path: str) -> bytes:
    root = root.absolute()
    candidate = root / relative_path
    try:
        relative = candidate.relative_to(root)
        root_stat = root.lstat()
    except (OSError, ValueError) as exc:
        raise AgentHostWorkflowContractError("bundle root is unavailable or unsafe") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or is_link_or_reparse(root):
        raise AgentHostWorkflowContractError("bundle root must be a real directory")
    component = root
    for part in relative.parts[:-1]:
        component /= part
        try:
            component_stat = component.lstat()
        except OSError as exc:
            raise AgentHostWorkflowContractError("bundle directory is unavailable") from exc
        if not stat.S_ISDIR(component_stat.st_mode) or is_link_or_reparse(component):
            raise AgentHostWorkflowContractError(
                "bundle inputs must not traverse links or reparse points"
            )
    if is_link_or_reparse(candidate):
        raise AgentHostWorkflowContractError("bundle inputs must not be links or reparse points")
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise AgentHostWorkflowContractError("required bundle input is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise AgentHostWorkflowContractError("bundle input must be a regular single-link file")
    try:
        payload = candidate.read_bytes()
        after = candidate.lstat()
    except OSError as exc:
        raise AgentHostWorkflowContractError("bundle input could not be read stably") from exc
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise AgentHostWorkflowContractError("bundle input changed while being read")
    return payload


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_json(domain: str, payload: object) -> str:
    encoded = json.dumps(
        {"domain": domain, "payload": payload},
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentHostWorkflowContractError("duplicate JSON field")
        result[key] = value
    return result
