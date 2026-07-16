"""Run manifest: a small machine-readable index written into each run directory.

`run_index.json` gives every execution a unique id, a stable configuration fingerprint,
and records what was run (kind, target,
model, scenario, variants, repeats), the outcome counts, and the artifact paths
relative to the run directory. It is the unit `ash list-runs` reads to show run history.

Configuration identity is deterministic; execution identity is intentionally unique.
The optional `created_at` timestamp is informational.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentic_security_harness.safe_io import (
    is_link_or_reparse,
    is_staging_path,
    write_text_artifact,
)
from agentic_security_harness.schema_versions import SCHEMA_VERSIONS
from agentic_security_harness.source_identity import component_fingerprint

_EXPECTATION_VALIDATOR_COMPONENTS = (
    "corpus.py",
    "patterns.py",
    "run_manifest.py",
    "schema_versions.py",
    "validation.py",
)

_RUN_KINDS = frozenset(
    {
        "run",
        "compare",
        "matrix",
        "external",
        "run_diff",
        "evidence_quality",
        "run_stats",
        "showcase",
        "local_swarm",
        "evidence_campaign",
        "secret_leak_campaign",
        "secret_leak_variations",
        "semantic_drift_campaign",
        "semantic_propagation_campaign",
        "swarm_defense_contour",
        "swarm_defense_live_campaign",
        "marketing_web_injection_campaign",
        "marketing_web_live_campaign",
        "swarm_resilience_campaign",
        "context_consent_campaign",
        "tool_authority_campaign",
        "rag_context_campaign",
        "planner_task_campaign",
        "memory_rehydration_campaign",
    }
)


class RunManifest(BaseModel):
    """Machine-readable index for one run directory."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSIONS["run_manifest"]
    run_id: str
    execution_id: str = ""
    config_fingerprint: str = ""
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
    artifact_sha256: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class ValidatedRunRecord:
    """One stable manifest snapshot plus independently recomputed validation status."""

    path: Path
    manifest: RunManifest
    manifest_sha256: str
    expectations_ok: bool
    expectation_mismatch_count: int
    validator_source_fingerprint: str


def expectation_validator_fingerprint() -> str:
    """Bind expectation observations to the exact local validator source bytes."""

    return component_fingerprint(_EXPECTATION_VALIDATOR_COMPONENTS)


def _resolve_manifest_artifact(out_dir: Path, artifact: str) -> Path:
    """Resolve one manifest artifact without allowing directory escape."""

    if not artifact.strip():
        raise ValueError("artifact path is empty")
    relative = Path(artifact)
    if relative.is_absolute():
        raise ValueError(f"artifact path must be relative: {artifact}")
    root = out_dir.resolve()
    unresolved = root
    for part in relative.parts:
        unresolved /= part
        if is_link_or_reparse(unresolved):
            raise ValueError(f"artifact path must not traverse a link or reparse point: {artifact}")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"artifact path escapes the run directory: {artifact}") from exc
    if candidate == root / "run_index.json":
        raise ValueError("run_index.json cannot hash itself")
    return candidate


def _artifact_sha256(path: Path) -> str:
    """Hash the exact persisted artifact bytes."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_artifact_hashes(out_dir: Path, artifacts: list[str]) -> dict[str, str]:
    """Build a deterministic content-integrity map for manifest artifacts."""

    if len(artifacts) != len(set(artifacts)):
        raise ValueError("manifest artifact paths must be unique")
    hashes: dict[str, str] = {}
    for artifact in sorted(artifacts):
        path = _resolve_manifest_artifact(out_dir, artifact)
        if not path.is_file():
            raise ValueError(f"manifest artifact is not a file: {artifact}")
        hashes[artifact] = _artifact_sha256(path)
    return hashes


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


def make_config_fingerprint(
    run_kind: str,
    target: str,
    model: str,
    scenario: str,
    variants: list[str],
    repeats: int,
) -> str:
    """Deterministic identity for comparable run configuration."""

    legacy = make_run_id(run_kind, target, model, scenario, variants, repeats)
    return f"cfg_{legacy.removeprefix('run_')}"


def make_execution_id() -> str:
    """Return an opaque unique identity for one execution attempt."""

    return f"run_{uuid.uuid4().hex}"


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
    execution_id: str = "",
) -> RunManifest:
    """Build a manifest with separate execution and configuration identities."""
    if run_kind not in _RUN_KINDS:
        raise ValueError(f"unknown run_kind '{run_kind}'")
    variants = variants or []
    resolved_execution_id = execution_id or make_execution_id()
    return RunManifest(
        run_id=resolved_execution_id,
        execution_id=resolved_execution_id,
        config_fingerprint=make_config_fingerprint(
            run_kind,
            target,
            model,
            scenario,
            variants,
            repeats,
        ),
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
    persisted = manifest
    if manifest.schema_version == SCHEMA_VERSIONS["run_manifest"]:
        persisted = manifest.model_copy(
            update={
                "artifact_sha256": _manifest_artifact_hashes(
                    out_dir,
                    manifest.artifacts,
                )
            }
        )
    write_text_artifact(
        path,
        json.dumps(persisted.model_dump(mode="json"), indent=2) + "\n",
    )
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
        if is_staging_path(path):
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            found.append((path, RunManifest.model_validate(raw)))
        except (OSError, ValueError):
            continue
    return found


def load_validated_run_records(root: Path) -> list[ValidatedRunRecord]:
    """Return stable, current, root-bound records with integrity-valid contracts.

    Behavioral expectation mismatches are adverse evidence, not corrupt evidence, and
    remain discoverable. Callers that present a run should expose its independently
    recomputed expectation status instead of silently dropping it.
    """

    from agentic_security_harness.validation import validate_artifact_path

    validated: list[ValidatedRunRecord] = []
    validator_fingerprint = expectation_validator_fingerprint()
    for path, manifest in load_run_manifests(root):
        try:
            manifest_snapshot = path.read_bytes()
            snapshot_manifest = RunManifest.model_validate_json(manifest_snapshot)
        except (OSError, ValueError):
            continue
        if snapshot_manifest != manifest:
            # The manifest changed after discovery; do not return a generation whose
            # parsed metadata and integrity check came from different snapshots.
            continue
        if snapshot_manifest.schema_version != SCHEMA_VERSIONS["run_manifest"]:
            continue
        result = validate_artifact_path(path.parent)
        recognized_root = any(
            path.parent.name in values
            for field, values in result.model_dump(mode="python").items()
            if field.endswith("_dirs")
        )
        root_manifest = path.parent / "run_index.json"
        try:
            snapshot_unchanged = root_manifest.read_bytes() == manifest_snapshot
        except OSError:
            snapshot_unchanged = False
        if result.integrity_ok and recognized_root and snapshot_unchanged:
            if root_manifest.is_file() and not is_link_or_reparse(root_manifest):
                validated.append(
                    ValidatedRunRecord(
                        path=path,
                        manifest=snapshot_manifest,
                        manifest_sha256=hashlib.sha256(manifest_snapshot).hexdigest(),
                        expectations_ok=result.expectations_ok,
                        expectation_mismatch_count=len(result.expectation_mismatches),
                        validator_source_fingerprint=validator_fingerprint,
                    )
                )
    return validated


def load_validated_run_manifests(root: Path) -> list[tuple[Path, RunManifest]]:
    """Compatibility projection of :func:`load_validated_run_records`."""

    return [(record.path, record.manifest) for record in load_validated_run_records(root)]
