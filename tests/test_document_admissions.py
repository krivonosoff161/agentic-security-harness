"""Host admission records are finite, create-only and anchored outside job output."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness import document_admissions as admissions
from agentic_security_harness import document_workflow as workflow
from agentic_security_harness.document_dynamic import run_admitted_job
from agentic_security_harness.document_expectations import (
    DocumentRunPlan,
    ExpectedDocumentJob,
    execution_sha256,
)
from agentic_security_harness.document_workflow import DocumentConfig


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _job(job_id: str, *, source_job: str | None = None) -> ExpectedDocumentJob:
    return ExpectedDocumentJob(
        job_id, _sha(job_id.encode()),
        input_sha256=_sha(b"synthetic input") if source_job is None else None,
        source_job=source_job,
        execution_sha256=execution_sha256(requirements_sha256=None),
    )


def _fixture(tmp_path: Path) -> tuple[DocumentConfig, DocumentRunPlan, Path]:
    jobs = tmp_path / "work" / "jobs"
    jobs.mkdir(parents=True)
    config = DocumentConfig(jobs, "local-model:latest", data_class="synthetic")
    return config, DocumentRunPlan(config.sha256, (_job("first"),)), tmp_path / "ledger"


def _mutate(path: Path, **changes: Any) -> None:
    value = json.loads(path.read_bytes())
    value.update(changes)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_append_decide_stop_seal_and_per_job_plan_digests(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(
        config, plan, path, pending_decisions=("initial_branch",),
    )
    assert root.sequence == 0 and root.pending_decisions == ("initial_branch",)
    assert root.plan_sha256_for("first") == plan.sha256
    with pytest.raises(ValueError, match="pending"):
        admissions.seal_admissions(config, path, expected_head_sha256=root.head_sha256)
    assert len(list(path.iterdir())) == 1

    admitted = admissions.resolve_decision(
        config, path, expected_head_sha256=root.head_sha256,
        decision_id="initial_branch", job=_job("second", source_job="first"),
    )
    assert admitted.sequence == 1 and admitted.pending_decisions == ()
    assert admitted.plan_sha256_for("first") == plan.sha256
    assert admitted.plan_sha256_for("second") == admitted.plan.sha256
    assert admitted.plan.sha256 != plan.sha256
    declared = admissions.declare_decision(
        config, path, expected_head_sha256=admitted.head_sha256,
        decision_id="followup", parent_job="second",
    )
    assert declared.pending_decisions == ("followup",)
    stopped = admissions.resolve_decision(
        config, path, expected_head_sha256=declared.head_sha256,
        decision_id="followup", reason="no_further_work",
    )
    sealed = admissions.seal_admissions(config, path, expected_head_sha256=stopped.head_sha256)
    assert sealed.sealed and sealed.sequence == 4
    assert sealed.resolved_decisions == ("initial_branch", "followup")
    assert sealed.decision_parents == (("initial_branch", None), ("followup", "second"))
    assert admissions.load_admissions(
        config, path, expected_head_sha256=sealed.head_sha256,
    ) == sealed
    assert not list(config.jobs_dir.iterdir())
    with pytest.raises(ValueError, match="sealed"):
        admissions.declare_decision(config, path, expected_head_sha256=sealed.head_sha256,
                                    decision_id="late", parent_job="first")


def test_initialization_requires_empty_jobs_and_external_new_directory(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    with pytest.raises(ValueError, match="outside jobs root"):
        admissions.initialize_admissions(config, plan, config.jobs_dir / "ledger")
    (config.jobs_dir / "existing").mkdir()
    with pytest.raises(ValueError, match="precede"):
        admissions.initialize_admissions(config, plan, path)
    (config.jobs_dir / "existing").rmdir()
    root = admissions.initialize_admissions(config, plan, path)
    with pytest.raises(FileExistsError):
        admissions.initialize_admissions(config, plan, path)
    other = DocumentConfig(config.jobs_dir, config.model, data_class="private")
    with pytest.raises(ValueError, match="configuration mismatch"):
        admissions.load_admissions(other, path, expected_head_sha256=root.head_sha256)


def test_declared_parent_must_match_admitted_source_before_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, path = _fixture(tmp_path)
    plan = DocumentRunPlan(config.sha256, (_job("first"), _job("other")))
    root = admissions.initialize_admissions(config, plan, path)
    declared = admissions.declare_decision(
        config, path, expected_head_sha256=root.head_sha256,
        decision_id="route", parent_job="first",
    )
    before = {entry.name: entry.read_bytes() for entry in path.iterdir()}
    calls: list[bool] = []

    def unexpected_generation(*args: object, **kwargs: object) -> None:
        calls.append(True)
        raise AssertionError("unadmitted job reached generator")

    monkeypatch.setattr(workflow, "_generate", unexpected_generation)
    for wrong in (_job("wrong_file"), _job("wrong_parent", source_job="other")):
        with pytest.raises(ValueError, match="decision parent"):
            admissions.resolve_decision(
                config, path, expected_head_sha256=declared.head_sha256,
                decision_id="route", job=wrong,
            )
        with pytest.raises(ValueError, match="not admitted"):
            run_admitted_job(
                config, path, declared.head_sha256, None, wrong.job_id, wrong.job_id,
                source_job=wrong.source_job, execute=True,
            )
    assert {entry.name: entry.read_bytes() for entry in path.iterdir()} == before
    assert not calls and not list(config.jobs_dir.iterdir())
    accepted = admissions.resolve_decision(
        config, path, expected_head_sha256=declared.head_sha256,
        decision_id="route", job=_job("right", source_job="first"),
    )
    assert accepted.plan.for_job("right").source_job == "first"


def test_initial_root_decision_has_no_parent_source_constraint(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(config, plan, path,
                                             pending_decisions=("root_choice",))
    admitted = admissions.resolve_decision(
        config, path, expected_head_sha256=root.head_sha256,
        decision_id="root_choice", job=_job("independent_file"),
    )
    assert admitted.plan.for_job("independent_file").source_job is None


def test_root_requires_bound_jobs_and_bounded_unique_decisions(tmp_path: Path) -> None:
    config, _, path = _fixture(tmp_path)
    legacy = DocumentRunPlan(config.sha256, (
        ExpectedDocumentJob("first", _sha(b"task"), input_sha256=_sha(b"source")),
    ))
    with pytest.raises(ValueError, match="fully execution-bound"):
        admissions.initialize_admissions(config, legacy, path)
    assert not path.exists()
    bound = DocumentRunPlan(config.sha256, (_job("first"),))
    with pytest.raises(ValueError, match="duplicate initial"):
        admissions.initialize_admissions(config, bound, path,
                                         pending_decisions=("branch", "branch"))
    with pytest.raises(ValueError, match="bounded initial"):
        admissions.initialize_admissions(
            config, bound, path,
            pending_decisions=tuple(f"d{index}" for index in range(129)),
        )
    assert not path.exists()


def test_duplicate_stale_and_invalid_job_or_decision_never_append(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(config, plan, path,
                                             pending_decisions=("branch",))
    with pytest.raises(ValueError, match="already used"):
        admissions.declare_decision(config, path, expected_head_sha256=root.head_sha256,
                                    decision_id="branch", parent_job="first")
    with pytest.raises(ValueError, match="not in host plan"):
        admissions.declare_decision(config, path, expected_head_sha256=root.head_sha256,
                                    decision_id="new", parent_job="missing")
    with pytest.raises(ValueError, match="fully execution-bound"):
        admissions.resolve_decision(config, path, expected_head_sha256=root.head_sha256,
                                    decision_id="branch", job=ExpectedDocumentJob(
                                        "second", _sha(b"task"), source_job="first",
                                    ))
    with pytest.raises(ValueError, match="already admitted"):
        admissions.resolve_decision(config, path, expected_head_sha256=root.head_sha256,
                                    decision_id="branch", job=_job("first"))
    with pytest.raises(ValueError, match="bounded no-job"):
        admissions.resolve_decision(config, path, expected_head_sha256=root.head_sha256,
                                    decision_id="branch", reason="raw text not a token")
    assert len(list(path.iterdir())) == 1
    admitted = admissions.resolve_decision(
        config, path, expected_head_sha256=root.head_sha256,
        decision_id="branch", job=_job("second", source_job="first"),
    )
    with pytest.raises(ValueError, match="head differs"):
        admissions.declare_decision(config, path, expected_head_sha256=root.head_sha256,
                                    decision_id="late", parent_job="second")
    with pytest.raises(ValueError, match="not pending"):
        admissions.resolve_decision(config, path, expected_head_sha256=admitted.head_sha256,
                                    decision_id="branch", reason="done")
    assert len(list(path.iterdir())) == 2


@pytest.mark.parametrize("damage", [
    "changed", "partial", "missing", "extra", "wrong_sequence", "bool_sequence",
    "extra_field", "wrong_previous", "wrong_kind_type", "changed_root",
])
def test_changed_partial_or_extra_history_refuses_without_repair(
    tmp_path: Path, damage: str,
) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(config, plan, path,
                                             pending_decisions=("branch",))
    head = admissions.resolve_decision(config, path, expected_head_sha256=root.head_sha256,
                                       decision_id="branch", reason="not_needed")
    record = path / "000001.json"
    if damage == "changed":
        _mutate(record, reason="other_reason")
    elif damage == "partial":
        record.write_bytes(b"{")
    elif damage == "missing":
        record.unlink()
    elif damage == "extra":
        (path / "unrecognized.json").write_text("{}", encoding="utf-8")
    elif damage == "wrong_sequence":
        _mutate(record, sequence=2)
    elif damage == "bool_sequence":
        _mutate(record, sequence=True)
    elif damage == "extra_field":
        _mutate(record, unexpected=True)
    elif damage == "wrong_kind_type":
        _mutate(record, kind=["resolve_stop"])
    elif damage == "changed_root":
        _mutate(path / "000000.json", pending_decisions=[])
    else:
        _mutate(record, previous_sha256="0" * 64)
    before = {p.name: p.read_bytes() for p in path.iterdir()}
    with pytest.raises(ValueError):
        admissions.load_admissions(config, path, expected_head_sha256=head.head_sha256)
    assert before == {p.name: p.read_bytes() for p in path.iterdir()}


def test_reordered_records_refuse(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(config, plan, path,
                                             pending_decisions=("branch",))
    stopped = admissions.resolve_decision(config, path, expected_head_sha256=root.head_sha256,
                                          decision_id="branch", reason="not_needed")
    sealed = admissions.seal_admissions(config, path, expected_head_sha256=stopped.head_sha256)
    first, second = path / "000001.json", path / "000002.json"
    first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
    first.write_bytes(second_bytes)
    second.write_bytes(first_bytes)
    with pytest.raises(ValueError, match="closed admission record"):
        admissions.load_admissions(config, path, expected_head_sha256=sealed.head_sha256)


def test_inventory_change_during_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(config, plan, path)
    original = admissions._read_file

    def add_extra_after_root(target: Path, limit: int) -> bytes:
        raw = original(target, limit)
        if target.name == "000000.json":
            (path / "extra.json").write_text("{}", encoding="utf-8")
        return raw

    monkeypatch.setattr(admissions, "_read_file", add_extra_after_root)
    with pytest.raises(ValueError, match="contiguous|directory changed"):
        admissions.load_admissions(config, path, expected_head_sha256=root.head_sha256)


def test_same_next_slot_concurrency_has_one_winner_and_no_replay(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    root = admissions.initialize_admissions(config, plan, path,
                                             pending_decisions=("branch",))

    def attempt() -> admissions.AdmissionSnapshot | Exception:
        try:
            return admissions.resolve_decision(
                config, path, expected_head_sha256=root.head_sha256,
                decision_id="branch", reason="not_needed",
            )
        except (OSError, ValueError) as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    successes = [row for row in results if isinstance(row, admissions.AdmissionSnapshot)]
    failures = [row for row in results if isinstance(row, Exception)]
    assert len(successes) == 1 and len(failures) == 1
    assert len(list(path.iterdir())) == 2
    assert admissions.load_admissions(
        config, path, expected_head_sha256=successes[0].head_sha256,
    ) == successes[0]


def test_coordinated_history_and_anchor_replacement_needs_external_witness(
    tmp_path: Path,
) -> None:
    """A valid shorter alternative history passes only with its matching head."""
    config, plan, old_path = _fixture(tmp_path)
    old_root = admissions.initialize_admissions(config, plan, old_path)
    old = admissions.seal_admissions(config, old_path,
                                     expected_head_sha256=old_root.head_sha256)
    current_path = tmp_path / "current-ledger"
    current_root = admissions.initialize_admissions(
        config, plan, current_path, pending_decisions=("route",),
    )
    resolved = admissions.resolve_decision(
        config, current_path, expected_head_sha256=current_root.head_sha256,
        decision_id="route", reason="host_declared_stop",
    )
    current = admissions.seal_admissions(config, current_path,
                                         expected_head_sha256=resolved.head_sha256)
    assert current.head_sha256 != old.head_sha256 and current.sequence > old.sequence
    # Synthetic tampering is confined to this temporary test ledger. The
    # original host-retained head detects it; replacing that head too does not.
    for entry in current_path.iterdir():
        entry.unlink()
    for entry in old_path.iterdir():
        (current_path / entry.name).write_bytes(entry.read_bytes())
    with pytest.raises(ValueError, match="head differs"):
        admissions.load_admissions(
            config, current_path, expected_head_sha256=current.head_sha256,
        )
    replaced = admissions.load_admissions(
        config, current_path, expected_head_sha256=old.head_sha256,
    )
    assert replaced.sealed and replaced.pending_decisions == ()
    assert replaced.sequence == old.sequence
    # This verifies the declared-history scope, not independent host intent.


def test_undeclared_source_is_outside_admission_scope(tmp_path: Path) -> None:
    config, plan, path = _fixture(tmp_path)
    declared = tmp_path / "declared.txt"
    declared.write_bytes(b"synthetic input")
    root = admissions.initialize_admissions(config, plan, path)
    before = {entry.name: entry.read_bytes() for entry in path.iterdir()}
    preview = run_admitted_job(
        config, path, root.head_sha256, declared, "first", "first", execute=False,
    )
    assert preview["state"] == "preview"
    omitted = tmp_path / "omitted.txt"
    omitted.write_bytes(b"second independent host source")
    assert {entry.name: entry.read_bytes() for entry in path.iterdir()} == before
    assert admissions.load_admissions(
        config, path, expected_head_sha256=root.head_sha256,
    ).head_sha256 == root.head_sha256
    assert run_admitted_job(
        config, path, root.head_sha256, declared, "first", "first", execute=False,
    )["state"] == "preview"
    # An omitted file not submitted to the host plan cannot be inferred from
    # a correct ledger. Completeness is relative to declared host inputs.
