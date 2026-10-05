"""Source-mode check of the installed acceptance runner's deterministic fixture."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


def test_scripted_native_acceptance_from_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[1]
    script = root / "tools" / "check_document_workflow.py"
    spec = importlib.util.spec_from_file_location("check_document_workflow", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    existing = os.environ.get("PYTHONPATH", "")
    source_path = str(root / "src") + (os.pathsep + existing if existing else "")
    monkeypatch.setenv("PYTHONPATH", source_path)
    result = module.check(tmp_path / "fresh", _source_test=True)
    assert result["passed"] is True
    assert result["model_measurement"] is False
    assert result["metadata_gets"] == 1
    assert result["generation_posts"] == 4
    assert result["protected_unchanged"] is True
    assert result["checks"] == 13
    saved = json.loads((tmp_path / "fresh" / "acceptance.json").read_text(encoding="utf-8"))
    assert saved == result
    assert "PUBLIC_SOURCE_SENTINEL" not in json.dumps(saved)
    assert "PUBLIC_DOCUMENT_SENTINEL" not in json.dumps(saved)
