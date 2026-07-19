"""Unverified reviewer/observation receipt schema.

The schema records what an independent review bundle would need to bind. It does not
authenticate reviewer identities, signatures, or time and therefore cannot promote a
public observation to independently labelled evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ReviewLabel = Literal["unsafe", "benign"]
ReviewerClass = Literal["human", "auxiliary_ai"]


class ReviewerObservationReceipt(BaseModel):
    """One private review decision bound to one exact observation projection."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["reviewer_observation_receipt.v0.1"] = (
        "reviewer_observation_receipt.v0.1"
    )
    receipt_id: str = Field(pattern=r"^review_[0-9a-f]{32}$")
    execution_id: str = Field(pattern=r"^run_[0-9a-f]{32}$")
    observation_id: str = Field(min_length=1, max_length=256)
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_note_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_id_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_class: ReviewerClass
    label: ReviewLabel
    issued_at: datetime
    independence_declared: bool
    authentication_state: Literal["unverified"] = "unverified"
    signature_scheme: Literal["none"] = "none"

    @model_validator(mode="after")
    def _require_declared_independence(self) -> ReviewerObservationReceipt:
        if not self.independence_declared:
            raise ValueError("review receipt must declare detector-independent adjudication")
        return self


class ReviewAdjudicationReceipt(BaseModel):
    """Tie-break decision for disagreeing human review receipts."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["review_adjudication_receipt.v0.1"] = "review_adjudication_receipt.v0.1"
    receipt_id: str = Field(pattern=r"^adjudication_[0-9a-f]{32}$")
    observation_id: str = Field(min_length=1, max_length=256)
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_receipt_ids: list[str] = Field(min_length=2)
    adjudicator_id_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_label: ReviewLabel
    issued_at: datetime
    authentication_state: Literal["unverified"] = "unverified"
    signature_scheme: Literal["none"] = "none"


class ReviewerObservationBundle(BaseModel):
    """Two-reviewer plus adjudication shape that remains ineligible for promotion."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["reviewer_observation_bundle.v0.1"] = "reviewer_observation_bundle.v0.1"
    observation_id: str = Field(min_length=1, max_length=256)
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipts: list[ReviewerObservationReceipt] = Field(min_length=2)
    adjudication: ReviewAdjudicationReceipt | None = None
    promotion_status: Literal["unverified"] = "unverified"

    @model_validator(mode="after")
    def _validate_bundle(self) -> ReviewerObservationBundle:
        receipt_ids = [item.receipt_id for item in self.receipts]
        reviewer_ids = [item.reviewer_id_sha256 for item in self.receipts]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("review receipt ids must be unique")
        if len(reviewer_ids) != len(set(reviewer_ids)):
            raise ValueError("reviewer identities must be distinct")
        if sum(item.reviewer_class == "human" for item in self.receipts) < 2:
            raise ValueError("at least two distinct human review receipts are required")
        if any(
            item.observation_id != self.observation_id
            or item.observation_sha256 != self.observation_sha256
            for item in self.receipts
        ):
            raise ValueError("every receipt must bind the same observation id and digest")

        labels = {item.label for item in self.receipts if item.reviewer_class == "human"}
        if len(labels) > 1 and self.adjudication is None:
            raise ValueError("disagreeing human reviews require adjudication")
        if self.adjudication is not None:
            adjudication = self.adjudication
            if (
                adjudication.observation_id != self.observation_id
                or adjudication.observation_sha256 != self.observation_sha256
            ):
                raise ValueError("adjudication must bind the reviewed observation")
            if set(adjudication.source_receipt_ids) != set(receipt_ids):
                raise ValueError("adjudication must bind every source receipt exactly")
            if adjudication.adjudicator_id_sha256 in set(reviewer_ids):
                raise ValueError("adjudicator identity must be distinct from reviewers")
        return self

    @property
    def promotion_eligible(self) -> bool:
        """Current v0.1 receipts carry no authenticated identity or signature."""
        return False
