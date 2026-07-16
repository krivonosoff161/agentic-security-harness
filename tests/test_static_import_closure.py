from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

import agentic_security_harness.static_import_closure as closure_module
from agentic_security_harness.static_import_closure import static_import_closure


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_static_import_closure_follows_batch_modules_and_local_imports(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "bat" / "entry.bat", "call bat\\worker.bat\n")
    _write(
        tmp_path / "bat" / "worker.bat",
        "python -m scripts.worker\n",
    )
    _write(
        tmp_path / "scripts" / "worker.py",
        "from src.pipeline import run\n",
    )
    _write(tmp_path / "src" / "pipeline.py", "def run():\n    return 1\n")

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is True
    assert report["batch_file_count"] == 2
    assert report["python_file_count"] == 2
    assert report["module_names"] == ["scripts.worker", "src.pipeline"]
    assert report["blockers"] == []
    assert report["raw_contents_included"] is False
    assert report["absolute_paths_included"] is False
    assert str(tmp_path) not in str(report)
    file_hashes = cast(dict[str, str], report["file_hashes"])
    closure_sha256 = cast(str, report["closure_sha256"])
    assert all(value.startswith("sha256:") for value in file_hashes.values())
    assert closure_sha256.startswith("sha256:")
    assert report["schema_version"] == "0.2"
    assert len(cast(str, report["analyzer_source_fingerprint"])) == 64
    assert cast(str, report["tool_version"])


def test_static_import_closure_fails_closed_on_dynamic_import(tmp_path: Path) -> None:
    _write(tmp_path / "bat" / "entry.bat", "python -m scripts.worker\n")
    _write(
        tmp_path / "scripts" / "worker.py",
        "from importlib import import_module\nimport_module('src.dynamic')\n",
    )
    _write(tmp_path / "src" / "dynamic.py", "VALUE = 1\n")

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is False
    assert report["dynamic_import_site_count"] == 1
    assert "dynamic-import-present" in cast(list[str], report["blockers"])


def test_static_import_closure_blocks_missing_and_escaping_entrypoints(
    tmp_path: Path,
) -> None:
    missing = static_import_closure(tmp_path, entrypoint="bat/missing.bat")
    escaped = static_import_closure(tmp_path, entrypoint="../outside.bat")

    assert missing["complete"] is False
    assert escaped["complete"] is False
    assert "entrypoint-or-batch-missing" in cast(list[str], missing["blockers"])
    assert "entrypoint-or-batch-missing" in cast(list[str], escaped["blockers"])


def test_static_import_closure_fails_closed_on_missing_local_import(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "bat" / "entry.bat", "python -m scripts.worker\n")
    _write(tmp_path / "scripts" / "worker.py", "import src.missing\n")
    (tmp_path / "src").mkdir()

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is False
    assert report["unresolved_local_import_count"] == 1
    assert "unresolved-local-import" in cast(list[str], report["blockers"])


def test_static_import_closure_blocks_source_change_during_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write(tmp_path / "bat" / "entry.bat", "python -m scripts.worker\n")
    module_path = tmp_path / "scripts" / "worker.py"
    _write(module_path, "VALUE = 1\n")
    original = Path.read_bytes
    changed = False

    def read_then_change(path: Path) -> bytes:
        nonlocal changed
        raw = original(path)
        if path == module_path and not changed:
            changed = True
            path.write_text("VALUE = 2\n", encoding="utf-8")
        return raw

    monkeypatch.setattr(Path, "read_bytes", read_then_change)

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is False
    assert "source-changed-during-closure" in cast(list[str], report["blockers"])


def test_static_import_closure_classifies_authority_sinks_and_phases(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "bat" / "entry.bat", "python -m scripts.worker\n")
    _write(
        tmp_path / "scripts" / "worker.py",
        "import src.journal\nimport src.provider\n",
    )
    _write(
        tmp_path / "src" / "journal.py",
        "from dotenv import load_dotenv\nload_dotenv()\n",
    )
    _write(
        tmp_path / "src" / "provider.py",
        "import requests\n"
        "def send():\n"
        "    requests.post('https://example.invalid/chat/completions')\n",
    )

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is True
    assert report["security_clear"] is False
    assert report["environment_provider_order"] == "co-reachable-order-not-proven"
    categories = cast(list[str], report["sink_categories"])
    assert "environment_load" in categories
    assert "provider_or_network" in categories
    inventory = cast(list[dict[str, object]], report["sink_inventory"])
    assert any(
        item["category"] == "environment_load" and item["phase"] == "import-time"
        for item in inventory
    )
    assert any(
        item["category"] == "provider_or_network" and item["phase"] == "call-time"
        for item in inventory
    )
    paths = cast(list[dict[str, object]], report["authority_paths"])
    assert any(
        item["sink_module"] == "src.provider"
        and item["module_path"]
        == ["scripts.worker", "src.provider"]
        for item in paths
    )


def test_static_import_closure_classifies_process_and_dynamic_code_execution(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "bat" / "entry.bat", "python -m scripts.worker\n")
    _write(
        tmp_path / "scripts" / "worker.py",
        "import subprocess as sp\n"
        "from os import system as shell\n"
        "def run(command):\n"
        "    sp.run(command)\n"
        "    shell(command)\n"
        "    exec(command)\n",
    )

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is True
    assert report["security_clear"] is False
    categories = cast(list[str], report["sink_categories"])
    assert "process_execution" in categories
    assert "dynamic_code_execution" in categories
    blockers = cast(list[str], report["security_blockers"])
    assert "process_execution" in blockers
    assert "dynamic_code_execution" in blockers


def test_static_import_closure_follows_literal_dynamic_target_but_stays_incomplete(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "bat" / "entry.bat", "python -m scripts.worker\n")
    _write(
        tmp_path / "scripts" / "worker.py",
        "from importlib import import_module\nimport_module('src.dynamic')\n",
    )
    _write(tmp_path / "src" / "dynamic.py", "VALUE = 1\n")

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is False
    assert report["dynamic_literal_import_site_count"] == 1
    assert "src.dynamic" in cast(list[str], report["module_names"])
    assert "dynamic-import-present" in cast(list[str], report["blockers"])


def test_static_import_closure_rejects_reparse_path_component(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    entry = tmp_path / "bat" / "entry.bat"
    _write(entry, "python -m scripts.worker\n")
    _write(tmp_path / "scripts" / "worker.py", "VALUE = 1\n")
    monkeypatch.setattr(
        closure_module,
        "is_link_or_reparse",
        lambda path: Path(path) == entry,
    )

    report = static_import_closure(tmp_path, entrypoint="bat/entry.bat")

    assert report["complete"] is False
    assert "entrypoint-or-batch-missing" in cast(list[str], report["blockers"])
