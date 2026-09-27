"""Bounded foundation properties and explicit limits of the public synthetic APIs."""

import json
from datetime import UTC, datetime, timedelta
from itertools import product
from pathlib import Path

from agentic_security_harness.envelope_policy import is_envelope_restriction
from agentic_security_harness.handoff_integrity import (
    HandoffEnvelope,
    payload_sha256,
    verify_handoff,
)
from agentic_security_harness.models import DataEnvelope, ExploitTrace
from agentic_security_harness.validation import ValidationResult, _validate_traces


def _policy_identity(envelope: DataEnvelope) -> tuple[object, ...]:
    """Identity for the six varied policy axes in the finite normalized domain."""
    return (
        frozenset(envelope.allowed_recipients),
        frozenset(envelope.allowed_purpose),
        envelope.data_class,
        envelope.can_forward,
        envelope.ttl_seconds,
        envelope.classification_source,
    )


def _policy_oracle(candidate: DataEnvelope, baseline: DataEnvelope) -> bool:
    """Independently spell out the intended order for the varied axes."""
    class_rank = {"public": 0, "internal": 1}
    assert candidate.ttl_seconds is not None and baseline.ttl_seconds is not None
    return (
        set(candidate.allowed_recipients) <= set(baseline.allowed_recipients)
        and set(candidate.allowed_purpose) <= set(baseline.allowed_purpose)
        and class_rank[candidate.data_class] >= class_rank[baseline.data_class]
        and (not candidate.can_forward or baseline.can_forward)
        and candidate.ttl_seconds <= baseline.ttl_seconds
        and candidate.classification_source == baseline.classification_source
    )


def test_policy_envelope_finite_oracle_and_order_properties() -> None:
    # Complete 2^6 Cartesian grid, including known-empty recipient and purpose sets.
    states = [
        DataEnvelope(
            allowed_recipients=recipients,
            allowed_purpose=purposes,
            data_class=data_class,
            can_forward=can_forward,
            ttl_seconds=ttl,
            classification_source=source,
        )
        for recipients, purposes, data_class, can_forward, ttl, source in product(
            [[], ["agent_a"]],
            [[], ["summarize"]],
            ["public", "internal"],
            [False, True],
            [1, 60],
            ["owner_a", "owner_b"],
        )
    ]
    assert len(states) == 64
    assert len({_policy_identity(state) for state in states}) == 64

    relation = [
        [is_envelope_restriction(candidate, baseline) for baseline in states]
        for candidate in states
    ]
    for i, candidate in enumerate(states):
        assert relation[i][i], i  # Reflexivity.
        for j, baseline in enumerate(states):
            assert relation[i][j] == _policy_oracle(candidate, baseline), (i, j)
            if relation[i][j] and relation[j][i]:
                assert _policy_identity(candidate) == _policy_identity(baseline), (i, j)
            if relation[i][j]:
                for k in range(len(states)):
                    if relation[j][k]:
                        assert relation[i][k], (i, j, k)  # Transitivity.


_NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def _capability_handoff(*, max_depth: int) -> tuple[HandoffEnvelope, dict[str, object]]:
    payload: dict[str, object] = {"capability_id": "toy", "scope": ["read"]}
    envelope = HandoffEnvelope(
        envelope_id="same-synthetic-handoff",
        created_at=_NOW,
        sender_id="worker",
        receiver_id="delegate",
        payload_type="capability",
        payload_hash=payload_sha256(payload),
        source_labels=["public-synthetic"],
        authority_issuer="owner",
        authority_scope=["read"],
        purpose="summarize",
        delegation_depth=2,
        max_delegation_depth=max_depth,
        can_delegate=True,
        allowed_recipients=["delegate"],
        ttl_seconds=60,
        expires_at=_NOW + timedelta(seconds=60),
        policy_version="toy-policy",
        receiver_supported_policy_versions=["toy-policy"],
        audit_entry_hash="synthetic-audit-entry",
    )
    return envelope, payload


def test_stateless_handoff_repetition_can_pass_twice_without_replay_state() -> None:
    envelope, payload = _capability_handoff(max_depth=2)

    first = verify_handoff(envelope, payload, current_time=_NOW)
    second = verify_handoff(envelope, payload, current_time=_NOW)

    assert first.verdict == second.verdict == "pass"
    assert first.failure_reasons == second.failure_reasons == []


def test_handoff_scope_check_does_not_interpret_opaque_payload_as_a_grant() -> None:
    envelope, payload = _capability_handoff(max_depth=2)
    envelope = envelope.model_copy(update={"authority_scope": []})

    result = verify_handoff(
        envelope, payload, current_time=_NOW, parent_authority_scope=[]
    )

    assert payload["scope"] == ["read"]
    assert envelope.authority_scope == []
    assert result.verdict == "pass"
    assert result.failure_reasons == []
    # Metadata PASS is not an interpretation or authorization of payload scope.


def test_self_declared_max_depth_is_not_authenticated_parent_chain_proof() -> None:
    shallow, payload = _capability_handoff(max_depth=1)
    widened, _ = _capability_handoff(max_depth=2)

    rejected = verify_handoff(shallow, payload, current_time=_NOW)
    accepted = verify_handoff(widened, payload, current_time=_NOW)

    assert rejected.verdict == "blocked"
    assert rejected.failure_reasons == ["authority_expansion"]
    assert accepted.verdict == "pass"
    assert accepted.failure_reasons == []


def test_trace_step_truncation_is_structurally_accepted_without_causal_proof() -> None:
    # This exercises _validate_traces only. It makes no full artifact-bundle claim:
    # a committed run_index.json would also need to bind changed artifact bytes.
    root = Path(__file__).resolve().parents[1] / "examples/comparison-report/protected"
    raw = json.loads((root / "traces.json").read_text(encoding="utf-8"))
    assert len(raw[0]["steps"]) > 1
    raw[0]["steps"] = raw[0]["steps"][:1]
    traces = [ExploitTrace.model_validate(item) for item in raw]
    result = ValidationResult()

    _validate_traces(traces, root / "traces.json", root, result)

    assert len(traces[0].steps) == 1
    assert result.integrity_ok
    assert result.expectations_ok
    assert result.errors == []
