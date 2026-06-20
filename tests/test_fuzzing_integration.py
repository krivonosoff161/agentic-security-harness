"""Fuzzing integration smoke tests."""

from __future__ import annotations

import re
from pathlib import Path

from fuzz.artifact_validation_fuzzer import fuzz_one_input as fuzz_artifact_validation
from fuzz.external_decision_fuzzer import fuzz_one_input as fuzz_external_decision

ROOT = Path(__file__).resolve().parent.parent
SHA_RE = re.compile(r"@[0-9a-f]{40}(?:\s+#\s+v[0-9][^\n]*)?$")


def test_fuzz_targets_are_callable_without_atheris() -> None:
    samples = [
        b"",
        b"\xff\x00not json",
        b'{"decision":"allow","would_preserve_boundary":false,"reason":"x"}',
        b"```json\n{\"decision\":\"block\",\"would_preserve_boundary\":true}\n```",
    ]
    for sample in samples:
        fuzz_external_decision(sample)
        fuzz_artifact_validation(sample)


def test_clusterfuzzlite_workflow_uses_pinned_actions() -> None:
    text = (ROOT / ".github" / "workflows" / "clusterfuzzlite.yml").read_text(
        encoding="utf-8"
    )
    assert "google/clusterfuzzlite/actions/build_fuzzers@" in text
    assert "google/clusterfuzzlite/actions/run_fuzzers@" in text
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses: "):
            assert SHA_RE.search(stripped), stripped


def test_clusterfuzzlite_dockerfile_pins_base_image() -> None:
    text = (ROOT / ".clusterfuzzlite" / "Dockerfile").read_text(encoding="utf-8")
    assert "gcr.io/oss-fuzz-base/base-builder-python@sha256:" in text
    assert "base-builder-python:latest" not in text
    build_script = (ROOT / ".clusterfuzzlite" / "build.sh").read_text(encoding="utf-8")
    assert "pip install --require-hashes -r requirements/runtime.txt" in build_script

