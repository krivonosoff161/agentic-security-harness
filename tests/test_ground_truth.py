import pytest
from pydantic import ValidationError

from agentic_security_harness.ground_truth import (
    IndependentGroundTruth,
    build_ground_truth_metrics,
)


def _labeled(label: str, marker: str) -> IndependentGroundTruth:
    return IndependentGroundTruth.model_validate(
        {
            "ground_truth_label": label,
            "ground_truth_source": "independent_review",
            "ground_truth_evidence_sha256": marker * 64,
        }
    )


def test_labeled_ground_truth_requires_independent_review_hash() -> None:
    with pytest.raises(ValidationError, match="independent_review"):
        IndependentGroundTruth(ground_truth_label="unsafe")

    with pytest.raises(ValidationError, match="SHA-256"):
        IndependentGroundTruth(
            ground_truth_label="benign",
            ground_truth_source="independent_review",
        )


def test_ground_truth_metrics_use_labels_not_detector_output() -> None:
    rows = [
        _labeled("unsafe", "a"),
        _labeled("unsafe", "b"),
        _labeled("benign", "c"),
        _labeled("benign", "d"),
        IndependentGroundTruth(),
    ]

    metrics = build_ground_truth_metrics(
        rows,
        detector_unsafe=[True, False, True, False, True],
        adapter_errors=[False, False, False, False, True],
    )

    assert metrics.eligible_observations == 4
    assert metrics.labeled_observations == 4
    assert metrics.coverage == 1.0
    assert metrics.true_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.specificity == 0.5
