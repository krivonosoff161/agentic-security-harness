from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentic_security_harness.reviewer_receipt import (
    ReviewAdjudicationReceipt,
    ReviewerObservationBundle,
    ReviewerObservationReceipt,
)

OBSERVATION = "a" * 64
NOW = datetime(2026, 7, 16, tzinfo=UTC)


def _review(index: int, label: str = "unsafe") -> ReviewerObservationReceipt:
    return ReviewerObservationReceipt.model_validate(
        {
            "receipt_id": f"review_{index:032x}",
            "execution_id": "run_" + "1" * 32,
            "observation_id": "obs-1",
            "observation_sha256": OBSERVATION,
            "review_note_sha256": f"{index + 10:064x}",
            "reviewer_id_sha256": f"{index + 20:064x}",
            "reviewer_class": "human",
            "label": label,
            "issued_at": NOW,
            "independence_declared": True,
        }
    )


def _adjudication(*reviews: ReviewerObservationReceipt) -> ReviewAdjudicationReceipt:
    return ReviewAdjudicationReceipt(
        receipt_id="adjudication_" + "9" * 32,
        observation_id="obs-1",
        observation_sha256=OBSERVATION,
        source_receipt_ids=[item.receipt_id for item in reviews],
        adjudicator_id_sha256="f" * 64,
        selected_label="unsafe",
        issued_at=NOW,
    )


def test_two_distinct_human_receipts_have_shape_but_cannot_promote() -> None:
    bundle = ReviewerObservationBundle(
        observation_id="obs-1",
        observation_sha256=OBSERVATION,
        receipts=[_review(1), _review(2)],
    )

    assert bundle.promotion_status == "unverified"
    assert bundle.promotion_eligible is False


def test_disagreement_requires_bound_distinct_adjudication() -> None:
    first = _review(1, "unsafe")
    second = _review(2, "benign")
    with pytest.raises(ValidationError, match="require adjudication"):
        ReviewerObservationBundle(
            observation_id="obs-1",
            observation_sha256=OBSERVATION,
            receipts=[first, second],
        )

    bundle = ReviewerObservationBundle(
        observation_id="obs-1",
        observation_sha256=OBSERVATION,
        receipts=[first, second],
        adjudication=_adjudication(first, second),
    )
    assert bundle.promotion_eligible is False


@pytest.mark.parametrize("mutation", ["duplicate-reviewer", "wrong-observation", "ai-only"])
def test_review_bundle_negative_identity_and_binding_fixtures(mutation: str) -> None:
    first = _review(1)
    second = _review(2)
    if mutation == "duplicate-reviewer":
        second = second.model_copy(update={"reviewer_id_sha256": first.reviewer_id_sha256})
    elif mutation == "wrong-observation":
        second = second.model_copy(update={"observation_sha256": "b" * 64})
    else:
        first = first.model_copy(update={"reviewer_class": "auxiliary_ai"})
        second = second.model_copy(update={"reviewer_class": "auxiliary_ai"})

    with pytest.raises(ValidationError):
        ReviewerObservationBundle(
            observation_id="obs-1",
            observation_sha256=OBSERVATION,
            receipts=[first, second],
        )
