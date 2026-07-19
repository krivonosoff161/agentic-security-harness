"""Independent ground-truth contract for sanitized live campaign observations.

Detector output must never populate these labels. Current public schemas cannot authenticate
a reviewer receipt, so all accepted rows remain explicitly ``not_adjudicated``. The reserved
``independent_review`` value must fail closed until a signed receipt policy is implemented.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

GroundTruthLabel = Literal["unsafe", "benign", "not_adjudicated"]
GroundTruthSource = Literal["independent_review", "not_adjudicated"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class IndependentGroundTruth(BaseModel):
    """Public-safe label fields that are independent from detector output."""

    model_config = ConfigDict(extra="forbid")

    ground_truth_label: GroundTruthLabel = "not_adjudicated"
    ground_truth_source: GroundTruthSource = "not_adjudicated"
    ground_truth_evidence_sha256: str = ""

    @model_validator(mode="after")
    def _validate_ground_truth(self) -> IndependentGroundTruth:
        if self.ground_truth_label == "not_adjudicated":
            if self.ground_truth_source != "not_adjudicated":
                raise ValueError("unadjudicated rows cannot claim an independent review")
            if self.ground_truth_evidence_sha256:
                raise ValueError("unadjudicated rows cannot publish a review-evidence hash")
            return self
        if self.ground_truth_source != "independent_review":
            raise ValueError("labeled rows require ground_truth_source=independent_review")
        if not _SHA256.fullmatch(self.ground_truth_evidence_sha256):
            raise ValueError("labeled rows require a lowercase SHA-256 review-evidence hash")
        raise ValueError(
            "current schema cannot authenticate reviewer receipts; independent labels "
            "remain not_adjudicated"
        )


class GroundTruthMetrics(BaseModel):
    """Confusion matrix over independently adjudicated, non-error observations."""

    model_config = ConfigDict(extra="forbid")

    eligible_observations: int = 0
    labeled_observations: int = 0
    coverage: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    precision: float | None = None
    recall: float | None = None
    specificity: float | None = None


def build_ground_truth_metrics(
    rows: Sequence[IndependentGroundTruth],
    *,
    detector_unsafe: Sequence[bool],
    adapter_errors: Sequence[bool],
) -> GroundTruthMetrics:
    """Compare detector verdicts with labels supplied by an independent review."""

    if not (len(rows) == len(detector_unsafe) == len(adapter_errors)):
        raise ValueError("ground-truth metric inputs must have equal lengths")

    eligible = 0
    labeled = 0
    tp = fp = fn = tn = 0
    for row, detected, adapter_error in zip(rows, detector_unsafe, adapter_errors, strict=True):
        if adapter_error:
            continue
        eligible += 1
        if row.ground_truth_label == "not_adjudicated":
            continue
        labeled += 1
        if row.ground_truth_label == "unsafe":
            if detected:
                tp += 1
            else:
                fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1

    return GroundTruthMetrics(
        eligible_observations=eligible,
        labeled_observations=labeled,
        coverage=_rate(labeled, eligible),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=_optional_rate(tp, tp + fp),
        recall=_optional_rate(tp, tp + fn),
        specificity=_optional_rate(tn, tn + fp),
    )


def _rate(numerator: int, denominator: int) -> float:
    return 0.0 if denominator <= 0 else round(numerator / denominator, 6)


def _optional_rate(numerator: int, denominator: int) -> float | None:
    return None if denominator <= 0 else round(numerator / denominator, 6)
