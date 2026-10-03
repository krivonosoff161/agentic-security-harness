"""Injected storage errors are not a reproduction of any specific filesystem."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agentic_security_harness import ancestry_store as storage
from agentic_security_harness import cli
from agentic_security_harness import controlled_file_workflow as workflow
from agentic_security_harness._fixture_files import INITIAL_PROTECTED, INITIAL_REPORT
from agentic_security_harness.controlled_file_verifier import verify_controlled_file_workflow


def _io_error() -> sqlite3.OperationalError:
    error = sqlite3.OperationalError("disk I/O error: PRIVATE_PATH_SENTINEL")
    error.sqlite_errorcode = sqlite3.SQLITE_IOERR
    return error


def _fail_commit(monkeypatch: pytest.MonkeyPatch, *, after_commit: bool) -> None:
    original_connect = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self) -> None:
            if after_commit:
                super().commit()
            raise _io_error()

    def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs["factory"] = FailedCommit
        return original_connect(*args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(storage.sqlite3, "connect", connect)


@pytest.mark.parametrize("after_commit", [False, True])
def test_failed_commit_preserves_partial_state_and_blocks_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_commit: bool,
) -> None:
    out = tmp_path / "failed"
    with monkeypatch.context() as patch:
        _fail_commit(patch, after_commit=after_commit)
        patch.setattr(workflow, "_model_proposal", lambda *a: pytest.fail("model reached"))
        patch.setattr(workflow, "_apply", lambda *a, **kw: pytest.fail("effect path reached"))
        with pytest.raises(storage.StorageError) as raised:
            workflow.run_controlled_file_workflow(out, model="fixed-local")
    error = raised.value
    assert error.stage == "commit_database"
    assert error.sqlite_errorcode == sqlite3.SQLITE_IOERR
    assert "PRIVATE_PATH_SENTINEL" not in str(error)
    assert not (out / "result.json").exists()
    assert not list(out.rglob("*-intent.json"))
    area = out / "case-01"
    assert (area / "files/report.txt").read_bytes() == INITIAL_REPORT
    assert (area / "files/protected.txt").read_bytes() == INITIAL_PROTECTED
    assert (area / "witness.json").read_bytes() == b""
    with sqlite3.connect(area / "ancestry.sqlite") as conn:
        assert conn.execute("SELECT COUNT(*) FROM records").fetchone()[0] == int(after_commit)
    assert verify_controlled_file_workflow(out)["integrity_ok"] is False
    before = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    with pytest.raises((ValueError, FileExistsError)):
        workflow.run_controlled_file_workflow(out)
    assert before == {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}


def test_failed_witness_does_not_become_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object) -> None:
        raise OSError(28, "PRIVATE_PATH_SENTINEL")

    monkeypatch.setattr(storage.AncestryStore, "_write_witness", fail)
    with pytest.raises(storage.StorageError) as raised:
        workflow.run_controlled_file_workflow(tmp_path / "failed")
    assert raised.value.stage == "write_witness"
    assert raised.value.os_errno == 28
    assert verify_controlled_file_workflow(tmp_path / "failed")["integrity_ok"] is False


def test_cli_storage_failure_is_typed_content_free_and_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _fail_commit(monkeypatch, after_commit=False)
    assert cli.main(["controlled-file-workflow", "--out", str(tmp_path / "failed")]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["reason"] == "ancestry_storage_unavailable"
    assert report["stage"] == "commit_database"
    assert report["partial_evidence"] == "preserved_no_resume_no_overwrite"
    assert report["sqlite_errorcode"] == sqlite3.SQLITE_IOERR
    assert "PRIVATE_PATH_SENTINEL" not in captured.out + captured.err
    assert str(tmp_path) not in captured.out + captured.err


@pytest.mark.parametrize("source_assets", [False, True])
def test_doctor_cli_selects_explicit_source_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    source_assets: bool,
) -> None:
    monkeypatch.chdir(tmp_path)
    args = ["doctor", "--json", "--reports-root", str(tmp_path / "reports")]
    if source_assets:
        args.append("--source-assets")
    status = cli.main(args)
    report = json.loads(capsys.readouterr().out)
    names = {check["name"] for check in report["checks"]}
    assert ("examples_dir" in names) is source_assets
    assert ("fake_server" in names) is source_assets
    assert status == int(source_assets)
