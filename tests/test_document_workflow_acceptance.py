"""Source-mode check of the installed acceptance runner's deterministic fixture."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


@pytest.mark.parametrize("engine", ["native", "pydantic-ai"])
def test_scripted_acceptance_from_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: str,
) -> None:
    if engine == "pydantic-ai":
        pytest.importorskip("pydantic_ai")
    root = Path(__file__).resolve().parents[1]
    script = root / "tools" / "check_document_workflow.py"
    spec = importlib.util.spec_from_file_location("check_document_workflow", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    existing = os.environ.get("PYTHONPATH", "")
    source_path = str(root / "src") + (os.pathsep + existing if existing else "")
    monkeypatch.setenv("PYTHONPATH", source_path)
    result = module.check(tmp_path / "fresh", engine=engine, _source_test=True)
    assert result["passed"] is True
    assert result["engine"] == engine
    assert result["model_measurement"] is False
    assert result["metadata_gets"] == 1
    assert result["generation_posts"] == 14
    assert result["protected_unchanged"] is True
    assert result["checks"] == 47
    names = {item["case"] for item in result["rows"]}
    assert {"supervised_preview", "supervised_dynamic_first", "pending_coverage",
            "dynamic_second", "unsealed_coverage", "sealed_coverage"} <= names
    saved = json.loads((tmp_path / "fresh" / "acceptance.json").read_text(encoding="utf-8"))
    assert saved == result
    assert "PUBLIC_SOURCE_SENTINEL" not in json.dumps(saved)
    assert "PUBLIC_DOCUMENT_SENTINEL" not in json.dumps(saved)
