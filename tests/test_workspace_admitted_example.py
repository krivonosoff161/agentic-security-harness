"""Exercise the public application example, including an actually blocked handoff."""
from __future__ import annotations

import json
import runpy
from pathlib import Path
from typing import Any

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "workspace_admitted_chain.py"


def application() -> dict[str, Any]:
    return runpy.run_path(str(EXAMPLE))


def test_example_two_writes_and_untrusted_checked_handoff(tmp_path: Path) -> None:
    app = application()
    requests: list[tuple[bytes, str]] = []

    def generate(source: bytes, task: str) -> str:
        requests.append((source, task))
        return str(app["deterministic_generator"](source, task))

    out = tmp_path / "application"
    result = app["run_chain"](out, generate, repository_sha="a" * 40)
    assert result["status"] == "complete" and result["generator_calls"] == 2
    assert len(json.loads(requests[0][0])["sources"]) == 4
    handed = json.loads(requests[1][0])["sources"]
    assert len(handed) == 1
    assert handed[0]["text"].encode() == (out / "step-1/output/report.json").read_bytes()
    assert json.loads((out / "step-2/output/report.json").read_bytes()) == {"approved_total": 20}
    assert all(row["quality"] == "checked" for row in result["stages"])
    assert result["protected_unchanged"]
    assert all("expected_json" not in task for _, task in requests)


@pytest.mark.parametrize("content", [
    '{"total_units":999}',
    '{"authority":"allow","artifact":"protected","content":"replace"}',
])
def test_saved_wrong_draft_does_not_call_next_generator(tmp_path: Path, content: str) -> None:
    app = application()
    out = tmp_path / "application"
    calls = []

    def generate(source: bytes, task: str) -> str:
        calls.append(task)
        return content

    result = app["run_chain"](out, generate, repository_sha="a" * 40)
    assert result["status"] == "quality_blocked"
    assert result["generator_calls"] == len(calls) == 1
    assert not (out / "step-2").exists()
    assert (out / "step-1/output/report.json").read_text() == content
    assert result["stages"][0]["quality"] == "failed" and result["protected_unchanged"]


def test_existing_output_refuses_before_call(tmp_path: Path) -> None:
    app = application()
    sentinel = tmp_path / "existing.txt"
    sentinel.write_text("preserve", encoding="utf-8")

    def generate(source: bytes, task: str) -> str:
        pytest.fail("existing directory must not call generator")

    with pytest.raises(FileExistsError):
        app["run_chain"](tmp_path, generate, repository_sha="a" * 40)
    assert sentinel.read_text() == "preserve" and list(tmp_path.iterdir()) == [sentinel]


def test_invalid_revision_refuses_before_output(tmp_path: Path) -> None:
    app = application()
    out = tmp_path / "application"

    def generate(source: bytes, task: str) -> str:
        pytest.fail("invalid host revision must not call generator")

    with pytest.raises(ValueError):
        app["run_chain"](out, generate, repository_sha="not-a-revision")
    assert not out.exists()


def test_nontext_generation_never_creates_operation(tmp_path: Path) -> None:
    app = application()
    out = tmp_path / "application"
    with pytest.raises(ValueError, match="document text"):
        app["run_chain"](out, lambda source, task: {"authority": "allow"},
                         repository_sha="a" * 40)
    assert not (out / "step-1/operation.db").exists()
    assert not (out / "step-1/output/report.json").exists()


def test_handoff_preserves_original_leaf_expiries(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    app = application()
    run = app["run_chain"]
    original = run.__globals__["capture_workspace_sources"]
    leaves = []

    def capture(*args: Any, **kwargs: Any) -> Any:
        leaves.append(kwargs["sources"].restrictions.record()["leaves"])
        return original(*args, **kwargs)

    monkeypatch.setitem(run.__globals__, "capture_workspace_sources", capture)
    result = run(tmp_path / "application", app["deterministic_generator"],
                 repository_sha="a" * 40)
    assert result["status"] == "complete" and len(leaves) == 2
    assert len(leaves[0]) == 4 and leaves[1] == leaves[0]


@pytest.mark.parametrize("incorrect", [False, True])
def test_optional_application_path(tmp_path: Path, incorrect: bool) -> None:
    pytest.importorskip("pydantic_ai")
    app = application()
    generate = (lambda source, task: "{}") if incorrect else app["deterministic_generator"]
    result = app["run_chain"](tmp_path / "application", generate,
                               repository_sha="a" * 40, engine="pydantic")
    assert result["status"] == ("quality_blocked" if incorrect else "complete")
    assert result["generator_calls"] == (1 if incorrect else 2)
