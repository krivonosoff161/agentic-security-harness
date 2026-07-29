"""Explicit causal adjudication for authoritative executable campaign identifiers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .context_consent_campaign import build_context_consent_campaign
from .evidence_campaign import build_evidence_campaign
from .local_swarm_matrix import build_local_swarm_attack_matrix
from .marketing_web_injection_campaign import build_marketing_web_injection_campaign
from .memory_rehydration_campaign import build_memory_rehydration_campaign
from .planner_task_campaign import build_planner_task_campaign
from .rag_context_campaign import build_rag_context_campaign
from .secret_leak_campaign import build_secret_leak_campaign
from .semantic_drift_campaign import build_semantic_drift_campaign
from .semantic_propagation_campaign import build_semantic_propagation_campaign
from .swarm_defense_contour import build_swarm_defense_contour
from .tool_authority_campaign import build_tool_authority_campaign

UnitKind = Literal["case", "scenario", "variation_row", "contour_primitive"]


@dataclass(frozen=True)
class ScenarioAdjudication:
    source_builder: str
    source_id: str
    unit_kind: UnitKind
    primary_family: str
    canonical_alias_key: str
    review_status: Literal["provisional_internal_review"] = "provisional_internal_review"


_EVIDENCE_FAMILIES = {
    "db.attack.label_stripping": "T02",
    "db.benign.same_label_handoff": "T02",
    "db.malformed.missing_envelope": "T02",
    "db.multihop.label_laundering": "T02",
    "db.bypass.provider_metadata_loss": "T02",
    "db.attack.adversarial_summary": "T02",
    "auth.attack.scope_expansion": "T06",
    "auth.benign.read_only_delegate": "T06",
    "auth.bypass.tool_claims_authority": "T07",
    "auth.multihop.authority_laundering": "T06",
    "auth.attack.approval_rephrasing": "T05",
    "auth.benign.same_scope_tool_output": "T07",
    "mem.attack.stale_recall": "T04",
    "mem.benign.fresh_same_scope": "T04",
    "mem.bypass.cross_user_recall": "T04",
    "mem.malformed.envelope_widening": "T04",
    "mem.attack.poison_recall_later": "T04",
    "mem.benign.trusted_policy_lookup": "T04",
    "swarm.attack.tool_injection": "T01",
    "swarm.benign.normal_worker_result": "T20",
    "swarm.borderline.verifier_outage": "T19",
    "swarm.bypass.approval_laundering": "T05",
    "swarm.attack.budget_skip_verifier": "T15",
    "swarm.benign.audit_only_review": "T18",
}

_RAG_FAMILIES = {
    "ragctx.rank.snippet_command": "T01",
    "ragctx.citation.permission_laundering": "T05",
    "ragctx.summary.source_label_loss": "T02",
    "ragctx.planner.subtask_conversion": "T13",
    "ragctx.corroboration.laundering": "T10",
    "ragctx.memory.delayed_activation": "T04",
    "ragctx.handoff.inherited_authority": "T06",
}

_PROPAGATION_FAMILIES = {
    "propagation.var.worker_relabel_to_chief": "T09",
    "propagation.var.pseudocode_summary_poison": "T09",
    "propagation.var.memory_summary_laundering": "T09",
    "propagation.var.multi_worker_consensus_poison": "T10",
}

_CONTOUR_FAMILIES = {
    "semantic_parameter_drift": "T09",
    "propagation_to_chief": "T09",
    "consensus_laundering": "T10",
    "benign_boundary_leak": "T02",
}

_MARKETING_FAMILIES = {
    "web_prompt_injection": "T01",
    "authority_hijack": "T06",
    "source_laundering": "T02",
    "summary_drift": "T09",
    "benign_task_confusion": "T01",
}

_MATRIX_FAMILIES = {
    "base.handoff_label_stripping": "T02",
    "base.authority_expansion": "T06",
    "base.tool_result_injection": "T01",
    "base.approval_laundering": "T05",
    "base.missing_envelope_recovery": "T22",
    "base.malformed_envelope": "T22",
    "base.verifier_outage": "T22",
    "base.memory_stale_recall": "T04",
    "base.cross_user_memory": "T04",
    "base.memory_trust_precedence": "T04",
    "base.memory_poisoned_recall": "T04",
    "base.memory_envelope_widening": "T04",
    "base.tool_output_authority_confusion": "T07",
    "base.multi_hop_label_laundering": "T02",
    "base.multi_hop_authority_laundering": "T06",
    "prompt_only.direct_tool_instruction": "T01",
    "prompt_only.approval_rephrasing": "T05",
    "prompt_only.scope_widening_request": "T06",
    "delayed.memory_after_ttl": "T04",
    "delayed.poison_recall_later": "T04",
    "recovery.missing_envelope_fail_closed": "T22",
    "recovery.malformed_envelope_quarantine": "T22",
    "recovery.verifier_unavailable": "T22",
    "audit.omitted_source_label": "T18",
    "audit.multihop_label_blind_spot": "T18",
    "budget.skip_verifier_for_cost": "T15",
    "budget.multi_hop_depth_pressure": "T15",
    "cross_provider.metadata_drop": "T12",
    "cross_provider.raw_payload_only": "T12",
    "cross_provider.multi_hop_metadata_decay": "T12",
    "contradiction.model_says_approved": "T05",
    "contradiction.memory_claims_policy": "T04",
    "contradiction.tool_claims_capability": "T07",
    "deep.handoff_payload_rewrite_hash_mismatch": "T17",
    "deep.handoff_recipient_switch_by_model": "T17",
    "deep.handoff_expired_replay_after_delay": "T17",
    "deep.handoff_policy_version_decay": "T17",
    "deep.tool_schema_smuggling_as_authority": "T07",
    "deep.tool_summary_drops_tool_label": "T07",
    "deep.memory_similar_key_confusion": "T04",
    "deep.memory_read_before_write": "T04",
    "deep.memory_ttl_removed_on_read": "T04",
    "deep.memory_forwarding_weakened_on_store": "T04",
}


def build_scenario_adjudication() -> tuple[ScenarioAdjudication, ...]:
    """Return one explicit primary-family decision for every authoritative builder unit."""

    rows: list[ScenarioAdjudication] = []

    def add(
        source_builder: str,
        source_id: str,
        unit_kind: UnitKind,
        family: str,
        alias_source: str,
    ) -> None:
        rows.append(
            ScenarioAdjudication(
                source_builder=source_builder,
                source_id=source_id,
                unit_kind=unit_kind,
                primary_family=family,
                canonical_alias_key=f"{family}:{alias_source}",
            )
        )

    for evidence_case in build_evidence_campaign().cases:
        family = _EVIDENCE_FAMILIES[evidence_case.case_id]
        add(
            "evidence_campaign",
            evidence_case.case_id,
            "case",
            family,
            evidence_case.scenario_id or evidence_case.case_id,
        )
    for consent_case in build_context_consent_campaign().cases:
        add(
            "context_consent_campaign",
            consent_case.case_id,
            "case",
            "T05",
            consent_case.scenario_id,
        )
    for secret_scenario in build_secret_leak_campaign().scenarios:
        add(
            "secret_leak_campaign",
            secret_scenario.scenario_id,
            "scenario",
            "T03",
            secret_scenario.scenario_id,
        )
    for drift_case in build_semantic_drift_campaign().cases:
        add(
            "semantic_drift_campaign",
            drift_case.case_id,
            "case",
            "T09",
            drift_case.scenario_id,
        )
    for propagation_case in build_semantic_propagation_campaign().cases:
        add(
            "semantic_propagation_campaign",
            propagation_case.case_id,
            "case",
            _PROPAGATION_FAMILIES[propagation_case.case_id],
            propagation_case.scenario_id,
        )
    for memory_case in build_memory_rehydration_campaign().cases:
        add(
            "memory_rehydration_campaign",
            memory_case.case_id,
            "case",
            "T04",
            memory_case.scenario_id,
        )
    for rag_case in build_rag_context_campaign().cases:
        add(
            "rag_context_campaign",
            rag_case.case_id,
            "case",
            _RAG_FAMILIES[rag_case.case_id],
            rag_case.scenario_id,
        )
    for planner_case in build_planner_task_campaign().cases:
        add(
            "planner_task_campaign",
            planner_case.case_id,
            "case",
            "T13",
            planner_case.scenario_id,
        )
    for contour_scenario in build_swarm_defense_contour().scenarios:
        add(
            "swarm_defense_contour",
            contour_scenario.scenario_id,
            "contour_primitive",
            _CONTOUR_FAMILIES[contour_scenario.scenario_id],
            contour_scenario.scenario_id,
        )
    for tool_case in build_tool_authority_campaign().cases:
        add(
            "tool_authority_campaign",
            tool_case.case_id,
            "case",
            "T07",
            tool_case.scenario_id,
        )
    for matrix_row in build_local_swarm_attack_matrix().rows:
        add(
            "local_swarm_matrix",
            matrix_row.case_id,
            "variation_row",
            _MATRIX_FAMILIES[matrix_row.case_id],
            matrix_row.base_scenario,
        )
    for marketing_scenario in build_marketing_web_injection_campaign().scenarios:
        add(
            "marketing_web_injection_campaign",
            marketing_scenario.scenario_id,
            "scenario",
            _MARKETING_FAMILIES[marketing_scenario.scenario_id],
            marketing_scenario.scenario_id,
        )

    return tuple(rows)
