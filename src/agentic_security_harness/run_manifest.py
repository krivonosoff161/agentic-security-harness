"""Run manifest: a small machine-readable index written into each run directory.

`run_index.json` gives every run a stable id and records what was run (kind, target,
model, scenario, variants, repeats), the outcome counts, and the artifact paths
relative to the run directory. It is the unit `ash list-runs` reads to show run history.

Deterministic by design except for the optional `created_at` timestamp, which is
informational and never rebuilt or compared by validation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.safe_io import write_text_artifact
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS

_RUN_KINDS = frozenset({"run", "compare", "matrix", "external", "local_swarm"})


class RunManifest(BaseModel):
    """Machine-readable index for one run directory."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["run_manifest"]
    run_id: str
    run_kind: str
    created_at: str = ""
    tool_version: str = ""
    target: str = ""
    model: str = ""
    scenario: str = ""
    variants: list[str] = Field(default_factory=list)
    repeats: int = 1
    outcomes: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    artifacts: list[str] = Field(default_factory=list)


def make_run_id(
    run_kind: str,
    target: str,
    model: str,
    scenario: str,
    variants: list[str],
    repeats: int,
) -> str:
    """Deterministic short id for a run configuration (stable across reruns)."""
    raw = "|".join(
        [
            run_kind,
            target,
            model,
            scenario,
            ",".join(variants),
            str(repeats),
        ]
    )
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"run_{digest[:10]}"


def build_manifest(
    run_kind: str,
    out_dir: Path,
    *,
    target: str = "",
    model: str = "",
    scenario: str = "",
    variants: list[str] | None = None,
    repeats: int = 1,
    outcomes: dict[str, int] | None = None,
    metadata: dict[str, str | int | float | bool | None] | None = None,
    artifacts: list[str] | None = None,
    tool_version: str = "",
    created_at: str = "",
) -> RunManifest:
    """Build a RunManifest. ``created_at`` is optional and informational."""
    if run_kind not in _RUN_KINDS:
        raise ValueError(f"unknown run_kind '{run_kind}'")
    variants = variants or []
    return RunManifest(
        run_id=make_run_id(run_kind, target, model, scenario, variants, repeats),
        run_kind=run_kind,
        created_at=created_at,
        tool_version=tool_version,
        target=target,
        model=model,
        scenario=scenario,
        variants=variants,
        repeats=repeats,
        outcomes=outcomes or {},
        metadata=metadata or {},
        artifacts=sorted(artifacts or []),
    )


def write_run_manifest(out_dir: Path, manifest: RunManifest) -> Path:
    """Write ``run_index.json`` into ``out_dir`` (LF newlines). Returns the path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "run_index.json"
    write_text_artifact(path, json.dumps(manifest.model_dump(mode="json"), indent=2) + "\n")
    return path


def load_run_manifests(root: Path) -> list[tuple[Path, RunManifest]]:
    """Find and parse every ``run_index.json`` under ``root`` (sorted by path).

    Unreadable or malformed manifests are skipped so a single bad directory does not
    break a listing.
    """
    if not root.exists() or not root.is_dir():
        return []
    found: list[tuple[Path, RunManifest]] = []
    for path in sorted(root.rglob("run_index.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            found.append((path, RunManifest.model_validate(raw)))
        except (OSError, ValueError):
            continue
    return found
