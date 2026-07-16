"""Owner-side private/public byte reconciliation without authenticity promotion.

The public receipt is deliberately unsigned.  It binds exact public bytes and carries
an HMAC commitment to exact private bytes, but only an owner holding the commitment
key can replay the private side.  Authorship, execution origin, locality, and trusted
time remain outside this contract.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_security_harness.marketing_web_live_campaign import (
    _BLOCKED_DECISION_OUTPUT,
    LiveMarketingWebPrivateRun,
    LiveMarketingWebSummary,
    build_live_marketing_web_summary,
    declared_marketing_web_scenarios,
)
from agentic_security_harness.safe_io import is_internal_output_dir, is_link_or_reparse
from agentic_security_harness.secret_leak_campaign import (
    SecretLeakVariationPrivateRun,
    SecretLeakVariationSummary,
    build_secret_leak_variation_summary,
    declared_secret_variation_cases,
)
from agentic_security_harness.semantic_drift_campaign import (
    SemanticDriftPrivateRun,
    SemanticDriftSummary,
    build_semantic_drift_campaign,
    declared_semantic_drift_cases,
)
from agentic_security_harness.semantic_propagation_campaign import (
    SemanticPropagationPrivateRun,
    SemanticPropagationSummary,
    build_semantic_propagation_campaign,
    declared_semantic_propagation_cases,
)
from agentic_security_harness.source_identity import component_fingerprint
from agentic_security_harness.swarm_defense_contour import (
    build_defense_topologies,
    declared_defense_scenarios,
)
from agentic_security_harness.swarm_defense_live_campaign import (
    LiveDefensePrivateRun,
    LiveDefenseSummary,
    build_live_defense_summary,
)
from agentic_security_harness.version import __version__

CampaignKind = Literal[
    "secret_leak_variation",
    "semantic_drift",
    "semantic_propagation",
    "swarm_defense_live",
    "marketing_web_live",
]

_SOURCE_COMPONENTS = (
    "ground_truth.py",
    "marketing_web_injection_campaign.py",
    "marketing_web_live_campaign.py",
    "reconciliation.py",
    "run_manifest.py",
    "safe_io.py",
    "schema_versions.py",
    "secret_leak_campaign.py",
    "semantic_drift_campaign.py",
    "semantic_propagation_campaign.py",
    "swarm_defense_contour.py",
    "swarm_defense_live_campaign.py",
    "source_identity.py",
    "validation.py",
    "version.py",
)
_PRIVATE_TO_PUBLIC: dict[str, tuple[CampaignKind, str]] = {
    "secret_leak_variation_private": (
        "secret_leak_variation",
        "secret_leak_variations",
    ),
    "semantic_drift_private": ("semantic_drift", "semantic_drift_campaign"),
    "semantic_propagation_private": (
        "semantic_propagation",
        "semantic_propagation_campaign",
    ),
    "swarm_defense_live_private": (
        "swarm_defense_live",
        "swarm_defense_live_campaign",
    ),
    "marketing_web_live_private": (
        "marketing_web_live",
        "marketing_web_live_campaign",
    ),
}
_PUBLIC_FILENAMES: dict[CampaignKind, str] = {
    "secret_leak_variation": "secret_leak_variation_summary.json",
    "semantic_drift": "semantic_drift_summary.json",
    "semantic_propagation": "semantic_propagation_summary.json",
    "swarm_defense_live": "swarm_defense_live_summary.json",
    "marketing_web_live": "marketing_web_live_summary.json",
}
_PUBLIC_RESULT_FIELDS: dict[CampaignKind, str] = {
    "secret_leak_variation": "secret_leak_variation_dirs",
    "semantic_drift": "semantic_drift_campaign_dirs",
    "semantic_propagation": "semantic_propagation_campaign_dirs",
    "swarm_defense_live": "swarm_defense_live_campaign_dirs",
    "marketing_web_live": "marketing_web_live_campaign_dirs",
}
_PRIVATE_SCHEMA_VERSIONS: dict[CampaignKind, str] = {
    "secret_leak_variation": "secret_leak_variation_private.v0.1",
    "semantic_drift": "semantic_drift_private.v0.1",
    "semantic_propagation": "semantic_propagation_private.v0.1",
    "swarm_defense_live": "swarm_defense_live_private.v0.3",
    "marketing_web_live": "marketing_web_live_private.v0.3",
}
_RECEIPT_LIMITATIONS = (
    "Public-only validation cannot replay the private bytes or HMAC commitment.",
    "The unsigned receipt does not authenticate authorship or execution origin.",
    "The receipt does not prove model locality, semantic truth, or complete coverage.",
    "Endpoint identity and canary semantics are not replayable from retained private raw fields.",
    "Trusted observation time is not recorded.",
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_value(value: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("value must be a lowercase SHA-256 digest")
    return value


class ReconciliationReceipt(BaseModel):
    """Sanitized public statement emitted only after an owner-side exact match."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    receipt_kind: Literal["private_public_reconciliation"] = "private_public_reconciliation"
    campaign_kind: CampaignKind
    private_run_kind: str
    public_run_kind: str
    decision: Literal["matched"] = "matched"
    public_artifact_sha256: str
    public_projection_sha256: str
    private_artifact_commitment: str
    commitment_scheme: Literal["hmac-sha256-v1"] = "hmac-sha256-v1"
    reconciliation_algorithm: Literal["campaign-public-projection-v1"] = (
        "campaign-public-projection-v1"
    )
    reconciliation_source_fingerprint: str
    tool_version: str
    origin_authentication: Literal["unsigned_self_declared"] = "unsigned_self_declared"
    trusted_time: Literal["not_recorded"] = "not_recorded"
    private_bytes_included: Literal[False] = False
    commitment_key_included: Literal[False] = False
    limitations: tuple[str, ...] = Field(default=_RECEIPT_LIMITATIONS)

    @field_validator(
        "public_artifact_sha256",
        "public_projection_sha256",
        "private_artifact_commitment",
        "reconciliation_source_fingerprint",
    )
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _sha256_value(value)

    @field_validator("tool_version")
    @classmethod
    def validate_tool_version(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("tool_version must be trimmed and nonblank")
        return value

    @field_validator("limitations")
    @classmethod
    def validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _RECEIPT_LIMITATIONS:
            raise ValueError("limitations must match the reconciliation contract")
        return value


class PublicReceiptValidation(BaseModel):
    """What can be established without private bytes or the commitment key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    public_bytes_bound: bool
    private_reconciliation_verified: Literal[False] = False
    origin_authenticated: Literal[False] = False
    errors: tuple[str, ...] = ()


def reconciliation_source_fingerprint() -> str:
    """Bind the exact sanitizer/reprojection implementation used by a receipt."""

    return component_fingerprint(_SOURCE_COMPONENTS)


def _canonical_json_bytes(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _require_text_hash(raw_text: str, digest: str, field: str) -> None:
    if not digest or not hmac.compare_digest(
        _sha256(raw_text.encode("utf-8")),
        digest,
    ):
        raise ValueError(f"private-hash-binding-mismatch:{field}")


def _check_optional_text_hash(raw_text: str, digest: str, field: str) -> None:
    if bool(raw_text) != bool(digest):
        raise ValueError(f"private-hash-binding-mismatch:{field}")
    if raw_text:
        _require_text_hash(raw_text, digest, field)


def _require_axis(values: Sequence[str], field: str) -> None:
    if not values:
        raise ValueError(f"private-matrix-invalid:{field}:empty")
    if len(values) != len(set(values)):
        raise ValueError(f"private-matrix-invalid:{field}:duplicates")
    if any(not value.strip() or value != value.strip() for value in values):
        raise ValueError(f"private-matrix-invalid:{field}:blank-or-untrimmed")


def _require_exact_matrix(
    actual: Iterable[tuple[object, ...]],
    expected: Iterable[tuple[object, ...]],
    field: str,
) -> None:
    actual_rows = list(actual)
    expected_rows = set(expected)
    if len(actual_rows) != len(set(actual_rows)):
        raise ValueError(f"private-matrix-invalid:{field}:duplicates")
    if set(actual_rows) != expected_rows:
        raise ValueError(f"private-matrix-invalid:{field}:incomplete")


def _validate_secret_private_hashes(run: SecretLeakVariationPrivateRun) -> None:
    _require_axis(run.models, "models")
    _require_axis(run.pressure_modes, "pressure_modes")
    cases = declared_secret_variation_cases()
    actual = [(row.model, row.case_id, row.pressure_mode) for row in run.transcripts]
    expected = {
        (model, case.case_id, pressure)
        for model in run.models
        for case in cases
        for pressure in run.pressure_modes
    }
    _require_exact_matrix(actual, expected, "secret_leak_variation")
    for row in run.transcripts:
        if row.adapter_error:
            if row.response_sha256:
                raise ValueError("private-hash-binding-mismatch:response_sha256")
        else:
            _require_text_hash(
                row.raw_response,
                row.response_sha256,
                "response_sha256",
            )


def _validate_drift_private_hashes(run: SemanticDriftPrivateRun) -> None:
    _require_axis(run.models, "models")
    _require_axis(run.pressure_modes, "pressure_modes")
    cases = declared_semantic_drift_cases()
    actual = [(row.model, row.case_id, row.pressure_mode) for row in run.transcripts]
    expected = {
        (model, case.case_id, pressure)
        for model in run.models
        for case in cases
        for pressure in run.pressure_modes
    }
    _require_exact_matrix(actual, expected, "semantic_drift")
    for row in run.transcripts:
        if row.adapter_error:
            if row.response_sha256:
                raise ValueError("private-hash-binding-mismatch:response_sha256")
        else:
            _require_text_hash(
                row.raw_response,
                row.response_sha256,
                "response_sha256",
            )


def _validate_propagation_private_hashes(
    run: SemanticPropagationPrivateRun,
) -> None:
    _require_axis(run.worker_models, "worker_models")
    _require_axis(run.chief_models, "chief_models")
    _require_axis(run.pressure_modes, "pressure_modes")
    cases = declared_semantic_propagation_cases()
    actual = [
        (
            row.worker_model,
            row.chief_model,
            row.case_id,
            row.pressure_mode,
        )
        for row in run.transcripts
    ]
    expected = {
        (worker, chief, case.case_id, pressure)
        for worker in run.worker_models
        for chief in run.chief_models
        for case in cases
        for pressure in run.pressure_modes
    }
    _require_exact_matrix(actual, expected, "semantic_propagation")
    for row in run.transcripts:
        if row.adapter_error:
            if row.worker_response_sha256:
                _require_text_hash(
                    row.raw_worker_response,
                    row.worker_response_sha256,
                    "worker_response_sha256",
                )
            elif row.raw_worker_response:
                raise ValueError("private-hash-binding-mismatch:worker_response_sha256")
            if row.chief_response_sha256:
                raise ValueError("private-hash-binding-mismatch:chief_response_sha256")
            if not row.raw_chief_response:
                raise ValueError("private-error-stage-mismatch:chief-diagnostic")
        else:
            _require_text_hash(
                row.raw_worker_response,
                row.worker_response_sha256,
                "worker_response_sha256",
            )
            _require_text_hash(
                row.raw_chief_response,
                row.chief_response_sha256,
                "chief_response_sha256",
            )


def _validate_turn_hashes(
    raw_responses: list[str],
    digests: list[str],
    field: str,
) -> None:
    if len(raw_responses) != len(digests):
        raise ValueError(f"private-hash-binding-mismatch:{field}")
    for raw_text, digest in zip(raw_responses, digests, strict=True):
        _require_text_hash(raw_text, digest, field)


def _validate_defense_private_hashes(run: LiveDefensePrivateRun) -> None:
    _require_axis(run.topology_ids, "topology_ids")
    _require_axis(run.worker_models, "worker_models")
    _require_axis(run.chief_models, "chief_models")
    _require_axis(run.pressure_modes, "pressure_modes")
    canonical = build_defense_topologies(declared_defense_scenarios())
    expected_prefix = [item.topology_id for item in canonical[: len(run.topology_ids)]]
    if run.topology_ids != expected_prefix:
        raise ValueError("private-matrix-invalid:topology_ids:not-canonical-prefix")
    actual = [
        (
            row.topology_id,
            row.worker_model,
            row.chief_model,
            row.pressure_mode,
        )
        for row in run.transcripts
    ]
    expected = {
        (topology, worker, chief, pressure)
        for topology in run.topology_ids
        for worker in run.worker_models
        for chief in run.chief_models
        for pressure in run.pressure_modes
    }
    _require_exact_matrix(actual, expected, "swarm_defense_live")
    canonical_by_id = {item.topology_id: item for item in canonical}
    for row in run.transcripts:
        _validate_turn_hashes(
            row.raw_worker_turn_responses,
            row.worker_turn_response_sha256,
            "worker_turn_response_sha256",
        )
        if row.raw_worker_response or row.worker_response_sha256:
            _require_text_hash(
                row.raw_worker_response,
                row.worker_response_sha256,
                "worker_response_sha256",
            )
        if (
            row.worker_response_sha256
            and row.raw_worker_turn_responses
            and (row.raw_worker_response != row.raw_worker_turn_responses[-1])
        ):
            raise ValueError("private-hash-binding-mismatch:worker_response_sha256")
        _check_optional_text_hash(
            row.raw_counter_worker_response,
            row.counter_worker_response_sha256,
            "counter_worker_response_sha256",
        )
        if row.adapter_error and row.chief_response_sha256:
            raise ValueError("private-hash-binding-mismatch:chief_response_sha256")
        if row.chief_response_sha256:
            _require_text_hash(
                row.raw_chief_response,
                row.chief_response_sha256,
                "chief_response_sha256",
            )
        consensus = "consensus_laundering" in canonical_by_id[row.topology_id].scenarios
        if row.adapter_error:
            if not row.raw_chief_response:
                raise ValueError("private-error-stage-mismatch:chief-diagnostic")
            if row.adapter_error_stage == "worker":
                if (
                    row.raw_worker_response
                    or row.worker_response_sha256
                    or row.raw_counter_worker_response
                    or row.counter_worker_response_sha256
                ):
                    raise ValueError("private-error-stage-mismatch:worker")
                if len(row.raw_worker_turn_responses) >= row.session_turns:
                    raise ValueError("private-error-stage-mismatch:worker")
            elif row.adapter_error_stage == "counter_worker":
                if not consensus:
                    raise ValueError("private-error-stage-mismatch:counter_worker")
                if (
                    len(row.raw_worker_turn_responses) != row.session_turns
                    or not row.worker_response_sha256
                    or row.raw_counter_worker_response
                    or row.counter_worker_response_sha256
                ):
                    raise ValueError("private-error-stage-mismatch:counter_worker")
            elif row.adapter_error_stage == "chief":
                if (
                    len(row.raw_worker_turn_responses) != row.session_turns
                    or not row.worker_response_sha256
                ):
                    raise ValueError("private-error-stage-mismatch:chief")
                if consensus != bool(row.counter_worker_response_sha256):
                    raise ValueError("private-error-stage-mismatch:chief")
            else:
                raise ValueError("private-error-stage-mismatch:missing")
        else:
            if row.adapter_error_stage:
                raise ValueError("private-error-stage-mismatch:unexpected")
            if len(row.raw_worker_turn_responses) != row.session_turns:
                raise ValueError("private-hash-binding-mismatch:worker_turn_response_sha256")
            _require_text_hash(
                row.raw_worker_response,
                row.worker_response_sha256,
                "worker_response_sha256",
            )
            _require_text_hash(
                row.raw_chief_response,
                row.chief_response_sha256,
                "chief_response_sha256",
            )
            if consensus != bool(row.counter_worker_response_sha256):
                raise ValueError("private-hash-binding-mismatch:counter_worker_response_sha256")


def _validate_marketing_private_hashes(run: LiveMarketingWebPrivateRun) -> None:
    _require_axis(run.scenario_ids, "scenario_ids")
    _require_axis(run.worker_models, "worker_models")
    _require_axis(run.chief_models, "chief_models")
    canonical = declared_marketing_web_scenarios()
    expected_prefix = [item.scenario_id for item in canonical[: len(run.scenario_ids)]]
    if run.scenario_ids != expected_prefix:
        raise ValueError("private-matrix-invalid:scenario_ids:not-canonical-prefix")
    canonical_by_id = {item.scenario_id: item for item in canonical}
    actual = [
        (
            row.scenario_id,
            row.worker_model,
            row.chief_model,
            row.mode,
            row.disabled_control,
        )
        for row in run.transcripts
    ]
    expected = {
        key
        for scenario_id in run.scenario_ids
        for worker in run.worker_models
        for chief in run.chief_models
        for key in (
            (scenario_id, worker, chief, "naive", None),
            (scenario_id, worker, chief, "bounded", None),
            (scenario_id, worker, chief, "benign", None),
            *(
                (scenario_id, worker, chief, "ablation", control)
                for control in canonical_by_id[scenario_id].required_controls
            ),
        )
    }
    _require_exact_matrix(actual, expected, "marketing_web_live")
    for row in run.transcripts:
        if not row.synthetic_strategy_value:
            raise ValueError("private-hash-binding-mismatch:synthetic_strategy_fingerprint")
        _require_text_hash(
            row.synthetic_strategy_value,
            row.synthetic_strategy_fingerprint,
            "synthetic_strategy_fingerprint",
        )
        _require_text_hash(
            row.raw_page_url,
            row.page_url_sha256,
            "page_url_sha256",
        )
        if row.raw_page_text or row.page_content_sha256:
            _require_text_hash(
                row.raw_page_text,
                row.page_content_sha256,
                "page_content_sha256",
            )
        _validate_turn_hashes(
            row.raw_worker_responses,
            row.worker_turn_response_sha256,
            "worker_turn_response_sha256",
        )
        if row.worker_response_sha256:
            if not row.raw_worker_responses:
                raise ValueError("private-hash-binding-mismatch:worker_response_sha256")
            _require_text_hash(
                row.raw_worker_responses[-1],
                row.worker_response_sha256,
                "worker_response_sha256",
            )
        if row.adapter_error and (row.chief_response_sha256 or row.decision_output_sha256):
            raise ValueError("private-hash-binding-mismatch:adapter_error_output")
        if row.chief_response_sha256:
            _require_text_hash(
                row.raw_chief_response,
                row.chief_response_sha256,
                "chief_response_sha256",
            )
        if row.decision_output_sha256:
            _require_text_hash(
                row.raw_chief_response,
                row.decision_output_sha256,
                "decision_output_sha256",
            )
        expected_turns = 1 if row.mode == "benign" else row.session_turns
        if row.adapter_error:
            if not row.raw_chief_response:
                raise ValueError("private-error-stage-mismatch:chief-diagnostic")
            if row.adapter_error_stage == "page_fetch":
                if (
                    row.raw_page_text
                    or row.page_content_sha256
                    or row.raw_worker_responses
                    or row.worker_turn_response_sha256
                    or row.worker_response_sha256
                    or row.chief_model_call_attempted
                ):
                    raise ValueError("private-error-stage-mismatch:page_fetch")
            elif row.adapter_error_stage == "worker":
                if (
                    not row.raw_page_text
                    or not row.page_content_sha256
                    or len(row.raw_worker_responses) >= expected_turns
                    or row.worker_response_sha256
                    or row.chief_model_call_attempted
                ):
                    raise ValueError("private-error-stage-mismatch:worker")
            elif row.adapter_error_stage == "chief":
                if (
                    not row.raw_page_text
                    or not row.page_content_sha256
                    or len(row.raw_worker_responses) != expected_turns
                    or not row.worker_response_sha256
                    or not row.chief_model_call_attempted
                ):
                    raise ValueError("private-error-stage-mismatch:chief")
            else:
                raise ValueError("private-error-stage-mismatch:missing")
        else:
            if row.adapter_error_stage:
                raise ValueError("private-error-stage-mismatch:unexpected")
            if not row.raw_page_text or not row.page_content_sha256:
                raise ValueError("private-hash-binding-mismatch:page_content_sha256")
            if len(row.raw_worker_responses) != expected_turns:
                raise ValueError("private-hash-binding-mismatch:worker_turn_response_sha256")
            if not row.worker_response_sha256 or not row.decision_output_sha256:
                raise ValueError("private-hash-binding-mismatch:decision_output_sha256")
            if row.chief_model_call_attempted and not row.chief_response_sha256:
                raise ValueError("private-hash-binding-mismatch:chief_response_sha256")
            if not row.chief_model_call_attempted and row.chief_response_sha256:
                raise ValueError("private-hash-binding-mismatch:chief_response_sha256")
            if not row.chief_model_call_attempted and (
                row.raw_chief_response != _BLOCKED_DECISION_OUTPUT
            ):
                raise ValueError("private-hash-binding-mismatch:blocked_decision_output")


def _checked_file(path: Path, *, private: bool) -> Path:
    unresolved = Path(path).absolute()
    if private and not is_internal_output_dir(unresolved.parent):
        raise ValueError("private reconciliation input must be stored under .internal")
    if not private and is_internal_output_dir(unresolved.parent):
        raise ValueError("public reconciliation input must not be stored under .internal")
    for candidate in (unresolved, *unresolved.parents):
        if candidate.exists() and is_link_or_reparse(candidate):
            raise ValueError("reconciliation paths must not traverse links or reparse points")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_file() or is_link_or_reparse(resolved):
        raise ValueError("reconciliation input must be a regular non-link file")
    return resolved


def _read_stable(path: Path) -> bytes:
    first = path.read_bytes()
    if path.read_bytes() != first:
        raise ValueError("reconciliation input changed while it was being read")
    return first


def _require_valid_public_bundle(
    public_file: Path,
    campaign_kind: CampaignKind,
) -> None:
    if public_file.name != _PUBLIC_FILENAMES[campaign_kind]:
        raise ValueError("public reconciliation input has a non-canonical filename")
    from agentic_security_harness.validation import validate_artifact_path

    validation = validate_artifact_path(public_file.parent)
    recognized_dirs = getattr(validation, _PUBLIC_RESULT_FIELDS[campaign_kind])
    if not validation.integrity_ok or public_file.parent.name not in recognized_dirs:
        raise ValueError("public campaign bundle failed current validation")


def _run_kind(raw: bytes) -> str:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("reconciliation input is not valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("run_kind"), str):
        raise ValueError("reconciliation input has no supported run_kind")
    return str(payload["run_kind"])


def _rebuild_projection(
    campaign_kind: CampaignKind,
    private_raw: bytes,
    public_raw: bytes,
) -> tuple[BaseModel, BaseModel]:
    try:
        if campaign_kind == "secret_leak_variation":
            secret_private = SecretLeakVariationPrivateRun.model_validate_json(private_raw)
            if secret_private.schema_version != _PRIVATE_SCHEMA_VERSIONS[campaign_kind]:
                raise ValueError("unsupported private schema version")
            secret_public = SecretLeakVariationSummary.model_validate_json(public_raw)
            _validate_secret_private_hashes(secret_private)
            return (
                build_secret_leak_variation_summary(
                    secret_private,
                    created_at=secret_public.created_at,
                ),
                secret_public,
            )
        if campaign_kind == "semantic_drift":
            drift_private = SemanticDriftPrivateRun.model_validate_json(private_raw)
            if drift_private.schema_version != _PRIVATE_SCHEMA_VERSIONS[campaign_kind]:
                raise ValueError("unsupported private schema version")
            drift_public = SemanticDriftSummary.model_validate_json(public_raw)
            _validate_drift_private_hashes(drift_private)
            return (
                build_semantic_drift_campaign(
                    drift_private,
                    created_at=drift_public.created_at,
                ),
                drift_public,
            )
        if campaign_kind == "semantic_propagation":
            propagation_private = SemanticPropagationPrivateRun.model_validate_json(private_raw)
            if propagation_private.schema_version != _PRIVATE_SCHEMA_VERSIONS[campaign_kind]:
                raise ValueError("unsupported private schema version")
            propagation_public = SemanticPropagationSummary.model_validate_json(public_raw)
            _validate_propagation_private_hashes(propagation_private)
            return (
                build_semantic_propagation_campaign(
                    propagation_private,
                    created_at=propagation_public.created_at,
                ),
                propagation_public,
            )
        if campaign_kind == "swarm_defense_live":
            defense_private = LiveDefensePrivateRun.model_validate_json(private_raw)
            if defense_private.schema_version != _PRIVATE_SCHEMA_VERSIONS[campaign_kind]:
                raise ValueError("unsupported private schema version")
            defense_public = LiveDefenseSummary.model_validate_json(public_raw)
            _validate_defense_private_hashes(defense_private)
            return (
                build_live_defense_summary(
                    defense_private,
                    created_at=defense_public.created_at,
                ),
                defense_public,
            )
        marketing_private = LiveMarketingWebPrivateRun.model_validate_json(private_raw)
        if marketing_private.schema_version != _PRIVATE_SCHEMA_VERSIONS[campaign_kind]:
            raise ValueError("unsupported private schema version")
        marketing_public = LiveMarketingWebSummary.model_validate_json(public_raw)
        _validate_marketing_private_hashes(marketing_private)
        return (
            build_live_marketing_web_summary(
                marketing_private,
                created_at=marketing_public.created_at,
            ),
            marketing_public,
        )
    except ValueError as exc:
        raise ValueError(
            f"private/public artifact failed its campaign schema: {exc}"
        ) from exc


def _parse_public_projection(
    campaign_kind: CampaignKind,
    public_raw: bytes,
) -> BaseModel:
    try:
        if campaign_kind == "secret_leak_variation":
            return SecretLeakVariationSummary.model_validate_json(public_raw)
        if campaign_kind == "semantic_drift":
            return SemanticDriftSummary.model_validate_json(public_raw)
        if campaign_kind == "semantic_propagation":
            return SemanticPropagationSummary.model_validate_json(public_raw)
        if campaign_kind == "swarm_defense_live":
            return LiveDefenseSummary.model_validate_json(public_raw)
        return LiveMarketingWebSummary.model_validate_json(public_raw)
    except ValueError as exc:
        raise ValueError("public artifact failed its campaign schema") from exc


def create_reconciliation_receipt(
    private_path: Path,
    public_path: Path,
    *,
    commitment_key: bytes,
) -> ReconciliationReceipt:
    """Recompute one public projection and return a sanitized exact-byte receipt."""

    if len(commitment_key) < 32:
        raise ValueError("commitment_key must contain at least 32 bytes")
    private_file = _checked_file(private_path, private=True)
    public_file = _checked_file(public_path, private=False)
    private_raw = _read_stable(private_file)
    public_raw = _read_stable(public_file)
    private_kind = _run_kind(private_raw)
    route = _PRIVATE_TO_PUBLIC.get(private_kind)
    if route is None:
        raise ValueError("private reconciliation run_kind is unsupported")
    campaign_kind, expected_public_kind = route
    if _run_kind(public_raw) != expected_public_kind:
        raise ValueError("private/public campaign kinds do not match")
    _require_valid_public_bundle(public_file, campaign_kind)
    expected, public = _rebuild_projection(campaign_kind, private_raw, public_raw)
    expected_projection = _canonical_json_bytes(expected)
    if expected_projection != _canonical_json_bytes(public):
        raise ValueError("public-projection-mismatch")
    if _read_stable(private_file) != private_raw or _read_stable(public_file) != public_raw:
        raise ValueError("reconciliation input changed before receipt finalization")
    return ReconciliationReceipt(
        campaign_kind=campaign_kind,
        private_run_kind=private_kind,
        public_run_kind=expected_public_kind,
        public_artifact_sha256=_sha256(public_raw),
        public_projection_sha256=_sha256(expected_projection),
        private_artifact_commitment=hmac.new(
            commitment_key,
            private_raw,
            hashlib.sha256,
        ).hexdigest(),
        reconciliation_source_fingerprint=reconciliation_source_fingerprint(),
        tool_version=__version__,
    )


def verify_owner_reconciliation(
    receipt: ReconciliationReceipt,
    private_path: Path,
    public_path: Path,
    *,
    commitment_key: bytes,
) -> tuple[str, ...]:
    """Replay exact private/public reconciliation and compare every receipt field."""

    try:
        rebuilt = create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=commitment_key,
        )
    except ValueError as exc:
        return (str(exc),)
    if not hmac.compare_digest(
        _canonical_json_bytes(rebuilt),
        _canonical_json_bytes(receipt),
    ):
        return ("reconciliation-receipt-mismatch",)
    return ()


def validate_public_receipt(
    receipt: ReconciliationReceipt,
    public_path: Path,
) -> PublicReceiptValidation:
    """Validate only public bytes; never imply replay of the private commitment."""

    try:
        public_file = _checked_file(public_path, private=False)
        public_raw = _read_stable(public_file)
    except ValueError as exc:
        return PublicReceiptValidation(
            ok=False,
            public_bytes_bound=False,
            errors=(str(exc),),
        )
    errors: list[str] = []
    bound = hmac.compare_digest(_sha256(public_raw), receipt.public_artifact_sha256)
    if not bound:
        errors.append("public-artifact-digest-mismatch")
    route = _PRIVATE_TO_PUBLIC.get(receipt.private_run_kind)
    if route != (receipt.campaign_kind, receipt.public_run_kind):
        errors.append("receipt-campaign-route-mismatch")
    if receipt.tool_version != __version__:
        errors.append("receipt-tool-version-mismatch")
    if receipt.reconciliation_source_fingerprint != reconciliation_source_fingerprint():
        errors.append("receipt-source-fingerprint-mismatch")
    if receipt.limitations != _RECEIPT_LIMITATIONS:
        errors.append("receipt-limitations-mismatch")
    try:
        _require_valid_public_bundle(public_file, receipt.campaign_kind)
    except ValueError as exc:
        errors.append(str(exc))
    try:
        public = _parse_public_projection(receipt.campaign_kind, public_raw)
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if _run_kind(public_raw) != receipt.public_run_kind:
            errors.append("public-run-kind-mismatch")
        projection_bound = hmac.compare_digest(
            _sha256(_canonical_json_bytes(public)),
            receipt.public_projection_sha256,
        )
        if not projection_bound:
            errors.append("public-projection-digest-mismatch")
    return PublicReceiptValidation(
        ok=not errors,
        public_bytes_bound=bound,
        errors=tuple(errors),
    )
