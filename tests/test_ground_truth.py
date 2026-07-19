import pytest
from pydantic import ValidationError

from agentic_security_harness.ground_truth import (
    IndependentGroundTruth,
    build_ground_truth_metrics,
)


def test_labeled_ground_truth_fails_closed_without_authenticated_receipt() -> None:
    with pytest.raises(ValidationError, match="independent_review"):
        IndependentGroundTruth(ground_truth_label="unsafe")

    with pytest.raises(ValidationError, match="SHA-256"):
        IndependentGroundTruth(
            ground_truth_label="benign",
            ground_truth_source="independent_review",
        )
    with pytest.raises(ValidationError, match="cannot authenticate reviewer receipts"):
        IndependentGroundTruth(
            ground_truth_label="unsafe",
            ground_truth_source="independent_review",
            ground_truth_evidence_sha256="a" * 64,
        )


def test_ground_truth_metrics_keep_unverified_rows_out_of_accuracy_counts() -> None:
    rows = [IndependentGroundTruth() for _ in range(5)]

    metrics = build_ground_truth_metrics(
        rows,
        detector_unsafe=[True, False, True, False, True],
        adapter_errors=[False, False, False, False, True],
    )

    assert metrics.eligible_observations == 4
    assert metrics.labeled_observations == 0
    assert metrics.coverage == 0.0
    assert metrics.true_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 0
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.specificity is None
