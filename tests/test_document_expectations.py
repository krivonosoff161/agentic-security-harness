"""Pure, closed host plan and ordered document-job expectations."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from agentic_security_harness.document_expectations import DocumentRunPlan, ExpectedDocumentJob

CONFIG = "a" * 64
TASK = "b" * 64
INPUT = "c" * 64
RESTRICTIONS = "d" * 64


def _input(job_id: str = "first", **changes: Any) -> ExpectedDocumentJob:
    return ExpectedDocumentJob(
        job_id=job_id, task_sha256=TASK, input_sha256=INPUT,
        **changes,
    )


def _chain() -> DocumentRunPlan:
    return DocumentRunPlan(CONFIG, (
        _input(source_restrictions_sha256=RESTRICTIONS),
        ExpectedDocumentJob("second", TASK, source_job="first"),
    ))


def test_ordered_roundtrip_lookup_and_digest() -> None:
    plan = _chain()
    encoded = json.dumps(plan.record(), sort_keys=True)
    restored = DocumentRunPlan.from_record(json.loads(encoded))
    assert restored == plan and restored.sha256 == plan.sha256
    assert plan.for_job("second").source_job == "first"
    with pytest.raises(ValueError, match="not in host plan"):
        plan.for_job("third")
    assert "source_restrictions_sha256" in encoded
    with pytest.raises(FrozenInstanceError):
        plan.configuration_sha256 = INPUT  # type: ignore[misc]


def test_record_list_mutation_cannot_change_frozen_plan() -> None:
    plan = _chain()
    digest = plan.sha256
    record = plan.record()
    record["jobs"].reverse()
    record["jobs"][0]["source_job"] = "forged"
    assert plan.jobs[0].job_id == "first"
    assert plan.jobs[1].source_job == "first"
    assert plan.sha256 == digest


@pytest.mark.parametrize("job_id", [
    "", "UPPER", "bad.name", "a/b", "a\\b", "a\x00b", "a" * 49,
    "con", "nul", "com1", "lpt9",
])
def test_job_id_uses_workflow_portable_rules(job_id: str) -> None:
    with pytest.raises(ValueError, match="portable document job ID"):
        _input(job_id)


@pytest.mark.parametrize("field,value", [
    ("task_sha256", "A" * 64),
    ("task_sha256", 7),
    ("input_sha256", "bad"),
    ("input_sha256", True),
])
def test_strict_job_digest_types(field: str, value: object) -> None:
    record = _input().record()
    record[field] = value
    with pytest.raises(ValueError):
        ExpectedDocumentJob.from_record(record)


def test_exactly_one_input_or_source_and_no_from_job_override() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        ExpectedDocumentJob("job", TASK)
    with pytest.raises(ValueError, match="exactly one"):
        ExpectedDocumentJob("job", TASK, INPUT, "first")
    with pytest.raises(ValueError, match="inherited"):
        ExpectedDocumentJob("job", TASK, source_job="first",
                            source_restrictions_sha256=RESTRICTIONS)
    with pytest.raises(ValueError, match="restrictions digest"):
        _input(source_restrictions_sha256="bad")


def test_duplicate_forward_self_and_cycle_references_rejected() -> None:
    first = _input()
    from_first = ExpectedDocumentJob("second", TASK, source_job="first")
    with pytest.raises(ValueError, match="duplicate"):
        DocumentRunPlan(CONFIG, (first, first))
    with pytest.raises(ValueError, match="earlier"):
        DocumentRunPlan(CONFIG, (from_first, first))
    with pytest.raises(ValueError, match="earlier"):
        DocumentRunPlan(CONFIG, (ExpectedDocumentJob("self", TASK, source_job="self"),))
    with pytest.raises(ValueError, match="earlier"):
        DocumentRunPlan(CONFIG, (
            ExpectedDocumentJob("first", TASK, source_job="second"),
            ExpectedDocumentJob("second", TASK, source_job="first"),
        ))
    assert DocumentRunPlan(CONFIG, (first, from_first)).jobs[1] == from_first


def test_plan_count_and_exact_types() -> None:
    with pytest.raises(ValueError, match="1..64"):
        DocumentRunPlan(CONFIG, ())
    with pytest.raises(ValueError, match="1..64"):
        DocumentRunPlan(CONFIG, tuple(_input(f"j{n}") for n in range(65)))
    with pytest.raises(ValueError, match="immutable jobs"):
        DocumentRunPlan(CONFIG, [_input()])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="closed expected job"):
        DocumentRunPlan(CONFIG, (_input(), "second"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="configuration digest"):
        DocumentRunPlan("bad", (_input(),))


def test_job_and_plan_closed_record_validation() -> None:
    job_record = _input().record()
    job_record["authority"] = "owner"
    with pytest.raises(ValueError, match="closed"):
        ExpectedDocumentJob.from_record(job_record)
    job_record.pop("authority")
    job_record["schema_version"] = "other"
    with pytest.raises(ValueError, match="version"):
        ExpectedDocumentJob.from_record(job_record)

    plan_record = _chain().record()
    plan_record["authority"] = "owner"
    with pytest.raises(ValueError, match="closed"):
        DocumentRunPlan.from_record(plan_record)
    plan_record.pop("authority")
    plan_record["jobs"] = tuple(plan_record["jobs"])
    with pytest.raises(ValueError, match="bounded job records"):
        DocumentRunPlan.from_record(plan_record)
    invalid_records: tuple[object, ...] = (None, [], "claim", 5)
    for value in invalid_records:
        with pytest.raises(ValueError, match="closed"):
            DocumentRunPlan.from_record(value)


def test_digest_is_sensitive_to_order_and_every_binding() -> None:
    base = _chain()
    alternatives = (
        DocumentRunPlan(INPUT, base.jobs),
        DocumentRunPlan(CONFIG, (_input(source_restrictions_sha256=None), base.jobs[1])),
        DocumentRunPlan(CONFIG, (ExpectedDocumentJob(
            "first", INPUT, input_sha256=INPUT, source_restrictions_sha256=RESTRICTIONS,
        ), base.jobs[1])),
        DocumentRunPlan(CONFIG, (_input(source_restrictions_sha256=RESTRICTIONS),
                                 ExpectedDocumentJob("second", TASK, input_sha256=INPUT))),
    )
    assert all(other.sha256 != base.sha256 for other in alternatives)
    independent = DocumentRunPlan(CONFIG, (_input(), _input("third")))
    reversed_jobs = DocumentRunPlan(CONFIG, tuple(reversed(independent.jobs)))
    assert reversed_jobs.sha256 != independent.sha256
