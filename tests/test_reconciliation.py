from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import BaseModel

import agentic_security_harness.marketing_web_live_campaign as live_marketing
import agentic_security_harness.swarm_defense_live_campaign as live_defense
import agentic_security_harness.validation as artifact_validation
from agentic_security_harness.marketing_web_injection_campaign import MarketingControlId
from agentic_security_harness.marketing_web_live_campaign import (
    LiveMarketingRunMode,
    LiveMarketingWebPrivateRun,
    LiveMarketingWebSummary,
    build_live_marketing_web_summary,
    write_live_marketing_web_artifacts,
)
from agentic_security_harness.reconciliation import (
    create_reconciliation_receipt,
    validate_public_receipt,
    verify_owner_reconciliation,
)
from agentic_security_harness.secret_leak_campaign import (
    SecretLeakVariationPrivateRun,
    SecretLeakVariationSummary,
    SecretVariationPrivateTranscript,
    build_secret_leak_variation_summary,
    declared_secret_variation_cases,
    write_secret_leak_variation_artifacts,
)
from agentic_security_harness.semantic_drift_campaign import (
    SemanticDriftPrivateRun,
    SemanticDriftPrivateTranscript,
    SemanticDriftSummary,
    build_semantic_drift_campaign,
    declared_semantic_drift_cases,
    write_semantic_drift_artifacts,
)
from agentic_security_harness.semantic_propagation_campaign import (
    SemanticPropagationPrivateRun,
    SemanticPropagationPrivateTranscript,
    SemanticPropagationSummary,
    build_semantic_propagation_campaign,
    declared_semantic_propagation_cases,
    write_semantic_propagation_artifacts,
)
from agentic_security_harness.swarm_defense_contour import (
    build_defense_topologies,
    declared_defense_scenarios,
)
from agentic_security_harness.swarm_defense_live_campaign import (
    LiveDefensePrivateRun,
    LiveDefensePrivateTranscript,
    LiveDefenseSummary,
    build_live_defense_summary,
    write_live_defense_artifacts,
)

_KEY = b"owner-only synthetic reconciliation key" + b"x" * 16


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_marketing_chat(
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: int,
) -> str:
    del base_url, model, timeout_seconds
    if "Prepare the final public marketing analysis" in messages[-1]["content"]:
        return "PUBLIC_ANALYSIS: public facts only.\nPUBLISH_APPROVED: true"
    return (
        "SOURCE_LABEL_PRESERVED: true\n"
        "INTERNAL_STRATEGY_INCLUDED: false\n"
        "PUBLICATION_ALLOWED: true\n"
        "SUMMARY: public facts only."
    )


def _marketing_run() -> LiveMarketingWebPrivateRun:
    scenario = live_marketing.declared_marketing_web_scenarios()[0]
    rows = []
    modes: list[tuple[LiveMarketingRunMode, MarketingControlId | None]] = [
        ("naive", None),
        ("bounded", None),
        ("benign", None),
        *(("ablation", control) for control in scenario.required_controls),
    ]
    for mode, disabled_control in modes:
        page = live_marketing._owned_page_html(scenario, attack=mode != "benign")
        with patch.object(live_marketing, "_fetch_page", return_value=page):
            rows.append(
                live_marketing._run_one_live_chain(
                    scenario=scenario,
                    mode=mode,
                    disabled_control=disabled_control,
                    page_url="http://127.0.0.1/owned.html",
                    secret=live_marketing._new_marketing_secret(),
                    worker_model="synthetic-worker",
                    chief_model="synthetic-chief",
                    base_url="http://127.0.0.1:11434/v1",
                    timeout_seconds=1,
                    session_turns=1,
                    chat_client=_safe_marketing_chat,
                )
            )
    return LiveMarketingWebPrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["synthetic-worker"],
        chief_models=["synthetic-chief"],
        scenario_ids=[scenario.scenario_id],
        endpoint_sha256="f" * 64,
        tool_version=live_marketing.__version__,
        implementation_sha256=live_marketing._implementation_sha256(),
        execution_id="run_" + "2" * 32,
        runtime_mode="local-only",
        transcripts=rows,
    )


def _marketing_error_row(stage: str) -> live_marketing.LiveMarketingWebPrivateTranscript:
    scenario = live_marketing.declared_marketing_web_scenarios()[0]
    page = live_marketing._owned_page_html(scenario, attack=True)

    def staged_chat(
        base_url: str,
        model: str,
        messages: list[dict[str, str]],
        timeout_seconds: int,
    ) -> str:
        del base_url, model, timeout_seconds
        is_chief = "Prepare the final public marketing analysis" in messages[-1][
            "content"
        ]
        if stage == "worker" or (stage == "chief" and is_chief):
            raise OSError(f"synthetic {stage} failure")
        return _safe_marketing_chat("", "", messages, 1)

    fetch = (
        patch.object(
            live_marketing,
            "_fetch_page",
            side_effect=OSError("synthetic page failure"),
        )
        if stage == "page_fetch"
        else patch.object(live_marketing, "_fetch_page", return_value=page)
    )
    with fetch:
        return live_marketing._run_one_live_chain(
            scenario=scenario,
            mode="naive",
            page_url="http://127.0.0.1/owned.html",
            secret=live_marketing._new_marketing_secret(),
            worker_model="synthetic-worker",
            chief_model="synthetic-chief",
            base_url="http://127.0.0.1:11434/v1",
            timeout_seconds=1,
            session_turns=1,
            chat_client=staged_chat,
        )


def _defense_row_with_stage(
    topology: live_defense.DefenseTopology,
    stage: str,
) -> LiveDefensePrivateTranscript:
    def staged_call(**kwargs: object) -> str:
        role = str(kwargs["role"])
        if stage == "worker" and role.startswith("worker-turn"):
            raise OSError("synthetic worker failure")
        if stage == "counter_worker" and role == "counter-worker":
            raise OSError("synthetic counter-worker failure")
        if stage == "chief" and role == "chief":
            raise OSError("synthetic chief failure")
        return "safe synthetic response"

    with patch.object(live_defense, "_call_model", side_effect=staged_call):
        return live_defense._run_one_chain(
            topology=topology,
            pressure="pseudo_code",
            worker_model="synthetic-worker",
            chief_model="synthetic-chief",
            base_url="http://127.0.0.1:11434/v1",
            timeout_seconds=1,
            session_turns=1,
        )


def _campaign_pairs() -> list[tuple[BaseModel, Callable[[], BaseModel]]]:
    secret_rows = [
        SecretVariationPrivateTranscript(
            case_id=case.case_id,
            model="synthetic-model",
            scenario_id=case.scenario_id,
            variation_id=case.variation_id,
            pressure_mode="neutral",
            turns=case.turns,
            response_sha256=_sha("safe response"),
            raw_prompt="synthetic private prompt",
            raw_response="safe response",
            canary_fingerprint="c" * 64,
        )
        for case in declared_secret_variation_cases()
    ]
    secret = SecretLeakVariationPrivateRun(
        created_at="2026-07-15T00:00:00Z",
        models=["synthetic-model"],
        pressure_modes=["neutral"],
        transcripts=secret_rows,
    )
    drift_rows = [
        SemanticDriftPrivateTranscript(
            case_id=case.case_id,
            model="synthetic-model",
            scenario_id=case.scenario_id,
            pressure_mode="gentle_reframe",
            turns=case.turns,
            response_sha256=_sha("safe response"),
            raw_prompt="synthetic private prompt",
            raw_response="safe response",
            canary_fingerprint="d" * 64,
            canonical_state_hash="e" * 64,
        )
        for case in declared_semantic_drift_cases()
    ]
    drift = SemanticDriftPrivateRun(
        created_at="2026-07-15T00:00:00Z",
        models=["synthetic-model"],
        pressure_modes=["gentle_reframe"],
        transcripts=drift_rows,
    )
    propagation_rows = [
        SemanticPropagationPrivateTranscript(
            case_id=case.case_id,
            scenario_id=case.scenario_id,
            pressure_mode="pseudo_code",
            worker_model="synthetic-worker",
            chief_model="synthetic-chief",
            worker_response_sha256=_sha("safe worker response"),
            chief_response_sha256=_sha("safe chief response"),
            raw_worker_prompt="synthetic worker prompt",
            raw_worker_response="safe worker response",
            raw_chief_prompt="synthetic chief prompt",
            raw_chief_response="safe chief response",
            canary_fingerprint="f" * 64,
            canonical_state_hash="a" * 64,
        )
        for case in declared_semantic_propagation_cases()
    ]
    propagation = SemanticPropagationPrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["synthetic-worker"],
        chief_models=["synthetic-chief"],
        pressure_modes=["pseudo_code"],
        transcripts=propagation_rows,
    )
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    worker_response = "safe worker response"
    chief_response = "safe chief response"
    defense_row = LiveDefensePrivateTranscript(
        topology_id=topology.topology_id,
        scenarios=topology.scenarios,
        pressure_mode="pseudo_code",
        worker_model="synthetic-worker",
        chief_model="synthetic-chief",
        raw_worker_prompt="synthetic private prompt",
        raw_worker_turn_prompts=["synthetic private prompt"],
        raw_worker_turn_responses=[worker_response],
        raw_worker_response=worker_response,
        worker_turn_response_sha256=[_sha(worker_response)],
        worker_response_sha256=_sha(worker_response),
        raw_chief_prompt="synthetic chief prompt",
        raw_chief_response=chief_response,
        chief_response_sha256=_sha(chief_response),
        canary_fingerprint="b" * 64,
    )
    decision, blockers = live_defense._verifier_decision(defense_row)
    defense_row = defense_row.model_copy(
        update={
            "verifier_decision": decision,
            "blocked_by": blockers,
            "missing_control_acceptances": live_defense._missing_control_acceptances(
                defense_row, topology
            ),
            "first_failure_step": live_defense._first_failure_step(defense_row),
        }
    )
    defense = LiveDefensePrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["synthetic-worker"],
        chief_models=["synthetic-chief"],
        pressure_modes=["pseudo_code"],
        topology_ids=[topology.topology_id],
        endpoint_sha256="e" * 64,
        tool_version=live_defense.__version__,
        implementation_sha256=live_defense._implementation_sha256(),
        execution_id="run_" + "1" * 32,
        runtime_mode="local-only",
        transcripts=[defense_row],
    )
    marketing = _marketing_run()
    return [
        (secret, lambda: build_secret_leak_variation_summary(secret)),
        (drift, lambda: build_semantic_drift_campaign(drift)),
        (propagation, lambda: build_semantic_propagation_campaign(propagation)),
        (defense, lambda: build_live_defense_summary(defense)),
        (marketing, lambda: build_live_marketing_web_summary(marketing)),
    ]


def _write_pair(
    tmp_path: Path,
    index: int,
    private: BaseModel,
    public: BaseModel,
) -> tuple[Path, Path]:
    private_path = tmp_path / ".internal" / str(index) / "private.json"
    public_dir = tmp_path / "public" / str(index)
    private_path.parent.mkdir(parents=True)
    private_path.write_text(private.model_dump_json(indent=2), encoding="utf-8")
    if isinstance(public, SecretLeakVariationSummary):
        write_secret_leak_variation_artifacts(public_dir, public)
        public_path = public_dir / "secret_leak_variation_summary.json"
    elif isinstance(public, SemanticDriftSummary):
        write_semantic_drift_artifacts(public_dir, public)
        public_path = public_dir / "semantic_drift_summary.json"
    elif isinstance(public, SemanticPropagationSummary):
        write_semantic_propagation_artifacts(public_dir, public)
        public_path = public_dir / "semantic_propagation_summary.json"
    elif isinstance(public, LiveDefenseSummary):
        write_live_defense_artifacts(public_dir, public)
        public_path = public_dir / "swarm_defense_live_summary.json"
    elif isinstance(public, LiveMarketingWebSummary):
        write_live_marketing_web_artifacts(public_dir, public)
        public_path = public_dir / "marketing_web_live_summary.json"
    else:
        raise AssertionError("unsupported synthetic reconciliation fixture")
    return private_path, public_path


def test_owner_reconciliation_matches_all_five_campaign_projections(
    tmp_path: Path,
) -> None:
    for index, (private, public_builder) in enumerate(_campaign_pairs()):
        private_path, public_path = _write_pair(
            tmp_path,
            index,
            private,
            public_builder(),
        )

        receipt = create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )

        assert receipt.decision == "matched"
        assert receipt.origin_authentication == "unsigned_self_declared"
        assert receipt.private_bytes_included is False
        assert receipt.commitment_key_included is False
        assert (
            verify_owner_reconciliation(
                receipt,
                private_path,
                public_path,
                commitment_key=_KEY,
            )
            == ()
        )
        public_validation = validate_public_receipt(receipt, public_path)
        assert public_validation.ok is True
        assert public_validation.public_bytes_bound is True
        assert public_validation.private_reconciliation_verified is False
        assert public_validation.origin_authenticated is False
        assert str(tmp_path) not in receipt.model_dump_json()


def test_reconciliation_rejects_projection_mismatch_without_receipt(
    tmp_path: Path,
) -> None:
    private, public_builder = _campaign_pairs()[0]
    public = public_builder()
    assert isinstance(public, SecretLeakVariationSummary)
    observations = list(public.observations)
    observations[0] = observations[0].model_copy(update={"response_sha256": "0" * 64})
    tampered = public.model_copy(update={"observations": observations})
    private_path, public_path = _write_pair(tmp_path, 0, private, tampered)

    with pytest.raises(ValueError, match="public-projection-mismatch"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_rejects_public_contract_tamper_before_receipt(
    tmp_path: Path,
) -> None:
    private, public_builder = _campaign_pairs()[0]
    private_path, public_path = _write_pair(tmp_path, 0, private, public_builder())
    payload = json.loads(public_path.read_text(encoding="utf-8"))
    payload["claim_boundary"] = "forged promotion"
    public_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="public campaign bundle failed current validation"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_detects_wrong_owner_key_and_public_byte_tamper(
    tmp_path: Path,
) -> None:
    private, public_builder = _campaign_pairs()[1]
    private_path, public_path = _write_pair(tmp_path, 0, private, public_builder())
    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )
    original_public = public_path.read_bytes()

    assert verify_owner_reconciliation(
        receipt,
        private_path,
        public_path,
        commitment_key=b"different owner-only key" + b"y" * 32,
    ) == ("reconciliation-receipt-mismatch",)
    payload = json.loads(public_path.read_text(encoding="utf-8"))
    public_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    validation = validate_public_receipt(receipt, public_path)
    assert validation.ok is False
    assert "public-artifact-digest-mismatch" in validation.errors
    assert "public campaign bundle failed current validation" in validation.errors

    public_path.write_bytes(original_public)
    forged_projection = receipt.model_copy(update={"public_projection_sha256": "0" * 64})
    validation = validate_public_receipt(forged_projection, public_path)
    assert validation.ok is False
    assert validation.public_bytes_bound is True
    assert validation.errors == ("public-projection-digest-mismatch",)


def test_reconciliation_enforces_private_location_and_key_strength(
    tmp_path: Path,
) -> None:
    private, public_builder = _campaign_pairs()[2]
    private_path, public_path = _write_pair(tmp_path, 0, private, public_builder())

    with pytest.raises(ValueError, match="at least 32 bytes"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=b"short",
        )

    public_private_path = tmp_path / "private.json"
    public_private_path.write_bytes(private_path.read_bytes())
    with pytest.raises(ValueError, match="under .internal"):
        create_reconciliation_receipt(
            public_private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_rejects_private_raw_hash_tamper(tmp_path: Path) -> None:
    private, public_builder = _campaign_pairs()[0]
    assert isinstance(private, SecretLeakVariationPrivateRun)
    rows = list(private.transcripts)
    rows[0] = rows[0].model_copy(update={"raw_response": "changed raw bytes"})
    tampered = private.model_copy(update={"transcripts": rows})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        tampered,
        public_builder(),
    )

    with pytest.raises(ValueError, match="private-hash-binding-mismatch"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_rejects_incomplete_private_matrix(tmp_path: Path) -> None:
    private, public_builder = _campaign_pairs()[1]
    assert isinstance(private, SemanticDriftPrivateRun)
    incomplete = private.model_copy(update={"transcripts": private.transcripts[:-1]})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        incomplete,
        public_builder(),
    )

    with pytest.raises(ValueError, match="private-matrix-invalid:semantic_drift"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_rejects_unknown_private_schema(tmp_path: Path) -> None:
    private, public_builder = _campaign_pairs()[2]
    assert isinstance(private, SemanticPropagationPrivateRun)
    future = private.model_copy(update={"schema_version": "future-private.v9"})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        future,
        public_builder(),
    )

    with pytest.raises(ValueError, match="unsupported private schema version"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_rejects_marketing_strategy_fingerprint_tamper(
    tmp_path: Path,
) -> None:
    private, public_builder = _campaign_pairs()[4]
    assert isinstance(private, LiveMarketingWebPrivateRun)
    rows = list(private.transcripts)
    rows[0] = rows[0].model_copy(update={"synthetic_strategy_fingerprint": "0" * 64})
    tampered = private.model_copy(update={"transcripts": rows})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        tampered,
        public_builder(),
    )

    with pytest.raises(ValueError, match="synthetic_strategy_fingerprint"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_public_receipt_rejects_forged_contract_metadata(tmp_path: Path) -> None:
    private, public_builder = _campaign_pairs()[0]
    private_path, public_path = _write_pair(tmp_path, 0, private, public_builder())
    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )

    tool_forgery = receipt.model_copy(update={"tool_version": "forged-version"})
    assert (
        "receipt-tool-version-mismatch" in validate_public_receipt(tool_forgery, public_path).errors
    )
    source_forgery = receipt.model_copy(update={"reconciliation_source_fingerprint": "0" * 64})
    assert (
        "receipt-source-fingerprint-mismatch"
        in validate_public_receipt(source_forgery, public_path).errors
    )
    limitation_forgery = receipt.model_copy(update={"limitations": ("all proven",)})
    assert (
        "receipt-limitations-mismatch"
        in validate_public_receipt(limitation_forgery, public_path).errors
    )


def test_reconciliation_allows_behavioral_mismatch_when_integrity_is_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, public_builder = _campaign_pairs()[0]
    private_path, public_path = _write_pair(tmp_path, 0, private, public_builder())
    actual = artifact_validation.validate_artifact_path(public_path.parent)
    expectation_only = actual.model_copy(
        update={
            "ok": False,
            "integrity_ok": True,
            "expectations_ok": False,
            "expectation_mismatches": ["synthetic adverse outcome"],
        }
    )
    monkeypatch.setattr(
        artifact_validation,
        "validate_artifact_path",
        lambda path: expectation_only,
    )

    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )

    assert receipt.decision == "matched"


@pytest.mark.parametrize("stage", ["page_fetch", "worker", "chief"])
def test_reconciliation_accepts_producer_valid_marketing_partial_error_stages(
    tmp_path: Path,
    stage: str,
) -> None:
    private = _marketing_run()
    replacement = _marketing_error_row(stage)
    rows = [
        replacement
        if (
            row.scenario_id,
            row.mode,
            row.disabled_control,
        )
        == (
            replacement.scenario_id,
            replacement.mode,
            replacement.disabled_control,
        )
        else row
        for row in private.transcripts
    ]
    with_error = private.model_copy(update={"transcripts": rows})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        with_error,
        build_live_marketing_web_summary(with_error),
    )

    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )

    assert receipt.decision == "matched"


@pytest.mark.parametrize("stage", ["worker", "chief"])
def test_reconciliation_accepts_producer_valid_defense_partial_error_stages(
    tmp_path: Path,
    stage: str,
) -> None:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    row = _defense_row_with_stage(topology, stage)
    private = LiveDefensePrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["synthetic-worker"],
        chief_models=["synthetic-chief"],
        pressure_modes=["pseudo_code"],
        topology_ids=[topology.topology_id],
        endpoint_sha256="e" * 64,
        tool_version=live_defense.__version__,
        implementation_sha256=live_defense._implementation_sha256(),
        execution_id="run_" + "3" * 32,
        runtime_mode="local-only",
        transcripts=[row],
    )
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        private,
        build_live_defense_summary(private),
    )

    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )

    assert receipt.decision == "matched"


def test_reconciliation_accepts_producer_valid_counter_worker_error_stage(
    tmp_path: Path,
) -> None:
    topologies = build_defense_topologies(declared_defense_scenarios())[:3]
    assert "consensus_laundering" in topologies[-1].scenarios
    rows = [
        _defense_row_with_stage(
            topology,
            "counter_worker"
            if "consensus_laundering" in topology.scenarios
            else "none",
        )
        for topology in topologies
    ]
    private = LiveDefensePrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["synthetic-worker"],
        chief_models=["synthetic-chief"],
        pressure_modes=["pseudo_code"],
        topology_ids=[item.topology_id for item in topologies],
        endpoint_sha256="e" * 64,
        tool_version=live_defense.__version__,
        implementation_sha256=live_defense._implementation_sha256(),
        execution_id="run_" + "4" * 32,
        runtime_mode="local-only",
        transcripts=rows,
    )
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        private,
        build_live_defense_summary(private),
    )

    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )

    assert receipt.decision == "matched"


def test_reconciliation_binds_empty_completed_response(tmp_path: Path) -> None:
    private, _ = _campaign_pairs()[0]
    assert isinstance(private, SecretLeakVariationPrivateRun)
    rows = list(private.transcripts)
    rows[0] = rows[0].model_copy(
        update={"raw_response": "", "response_sha256": _sha("")}
    )
    completed = private.model_copy(update={"transcripts": rows})
    public = build_secret_leak_variation_summary(completed)
    private_path, public_path = _write_pair(tmp_path, 0, completed, public)

    receipt = create_reconciliation_receipt(
        private_path,
        public_path,
        commitment_key=_KEY,
    )

    assert receipt.decision == "matched"


def test_reconciliation_rejects_orphan_marketing_page_state_after_fetch_error(
    tmp_path: Path,
) -> None:
    valid = _marketing_run()
    error = _marketing_error_row("page_fetch")
    valid_rows = [
        error
        if (row.scenario_id, row.mode, row.disabled_control)
        == (error.scenario_id, error.mode, error.disabled_control)
        else row
        for row in valid.transcripts
    ]
    public_run = valid.model_copy(update={"transcripts": valid_rows})
    orphan = error.model_copy(
        update={
            "raw_page_text": "impossible retained page",
            "page_content_sha256": _sha("impossible retained page"),
        }
    )
    private_rows = [orphan if row is error else row for row in valid_rows]
    private_run = valid.model_copy(update={"transcripts": private_rows})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        private_run,
        build_live_marketing_web_summary(public_run),
    )

    with pytest.raises(ValueError, match="private-error-stage-mismatch:page_fetch"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )


def test_reconciliation_rejects_orphan_defense_final_worker_after_worker_error(
    tmp_path: Path,
) -> None:
    topology = build_defense_topologies(declared_defense_scenarios())[0]
    error = _defense_row_with_stage(topology, "worker")
    public_run = LiveDefensePrivateRun(
        created_at="2026-07-15T00:00:00Z",
        worker_models=["synthetic-worker"],
        chief_models=["synthetic-chief"],
        pressure_modes=["pseudo_code"],
        topology_ids=[topology.topology_id],
        endpoint_sha256="e" * 64,
        tool_version=live_defense.__version__,
        implementation_sha256=live_defense._implementation_sha256(),
        execution_id="run_" + "5" * 32,
        runtime_mode="local-only",
        transcripts=[error],
    )
    orphan = error.model_copy(
        update={
            "raw_worker_response": "impossible final worker",
            "worker_response_sha256": _sha("impossible final worker"),
        }
    )
    private_run = public_run.model_copy(update={"transcripts": [orphan]})
    private_path, public_path = _write_pair(
        tmp_path,
        0,
        private_run,
        build_live_defense_summary(public_run),
    )

    with pytest.raises(ValueError, match="private-error-stage-mismatch:worker"):
        create_reconciliation_receipt(
            private_path,
            public_path,
            commitment_key=_KEY,
        )
