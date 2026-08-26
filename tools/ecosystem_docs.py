"""Validate and generate the public Agentic Security ecosystem documentation.

The ``*.yaml`` contracts intentionally use canonical JSON syntax. JSON is a strict
subset of YAML 1.2, which keeps the files readable by YAML tooling while allowing the
offline validator to reject duplicate keys and avoid a second parser dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT = Path(__file__).resolve().parents[1]
ECOSYSTEM = ROOT / "ecosystem"
SCHEMAS = ECOSYSTEM / "schemas"
EXTENSION_CANDIDATE_HARNESS_APIS = frozenset(
    {"1", "1 (candidate; future package boundary >=1.3,<2)"}
)
EXTENSION_CANDIDATE_PYTHON = ">=3.11,<3.14"

Role = Literal[
    "canonical",
    "component-owned",
    "component-front-door",
    "generated",
    "generated-current-snapshot",
    "generated-ecosystem-view",
    "current-snapshot",
    "research",
    "historical",
    "superseded",
]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PackageSpec(ClosedModel):
    name: str | None
    version: str | None
    install: str | None
    entry_points: list[str]


class Ownership(ClosedModel):
    modules: list[str]
    checks: list[str]
    collectors: list[str]
    adapters: list[str]
    contracts: list[str]


class ContractRef(ClosedModel):
    id: str
    version: str
    direction: Literal["provides", "consumes"]
    required: bool


class DocumentRef(ClosedModel):
    path: str
    role: Role


class PlatformSupport(ClosedModel):
    supported: list[Literal["linux", "windows", "macos", "web"]]
    tested: list[Literal["linux", "windows", "macos", "web"]]

    @model_validator(mode="after")
    def tested_is_supported(self) -> PlatformSupport:
        if not set(self.tested) <= set(self.supported):
            raise ValueError("tested platforms must be a subset of supported platforms")
        return self


class CompatibilitySpec(ClosedModel):
    harness_api: str
    python: str
    platforms: PlatformSupport


class ComponentManifest(ClosedModel):
    schema_version: Literal["AgenticSecurityEcosystemComponent.v1"]
    component_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str
    repository: str | None
    visibility: Literal["public", "private"]
    kind: Literal[
        "core",
        "check_extension",
        "declarative_pack",
        "support_adapter",
        "research_upstream",
        "profile_projection",
    ]
    summary: str
    package: PackageSpec
    owns: Ownership
    consumes: list[str]
    contracts: list[ContractRef]
    docs: list[DocumentRef]
    compatibility: CompatibilitySpec
    integration_status: Literal[
        "standalone",
        "contract_only",
        "extension_candidate",
        "installable_extension",
        "suite_verified",
    ]
    evidence_refs: list[str]
    claims: list[str]
    non_claims: list[str]
    authority: Literal["none"]

    @model_validator(mode="after")
    def semantic_contract(self) -> ComponentManifest:
        _require_unique("contract ids", [item.id for item in self.contracts])
        _require_unique("document paths", [item.path for item in self.docs])
        for value in [*self.evidence_refs, *(item.path for item in self.docs)]:
            _require_relative_public_path(value)
        if self.visibility == "public" and not (
            self.repository and self.repository.startswith("https://github.com/")
        ):
            raise ValueError("public components require a public GitHub repository URL")
        if self.visibility == "private" and self.repository is not None:
            raise ValueError("private repository locations must not enter the public manifest")
        if not self.non_claims:
            raise ValueError("each component must state at least one non-claim")
        if self.integration_status == "extension_candidate":
            if self.visibility != "public":
                raise ValueError("extension candidates must be public")
            if self.kind != "check_extension":
                raise ValueError("extension candidates must use kind check_extension")
            if self.compatibility.harness_api not in EXTENSION_CANDIDATE_HARNESS_APIS:
                raise ValueError("extension candidates require an exact Harness API")
            if not self.compatibility.platforms.tested:
                raise ValueError("extension candidates require a tested platform")
            if not self.evidence_refs:
                raise ValueError("extension candidates require public evidence")
        return self


class Phase(ClosedModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    title: str
    status: Literal["planned", "active", "blocked", "complete"]
    depends_on: list[str]
    deliverables: list[str]


class DocumentationContract(ClosedModel):
    roles: list[
        Literal[
            "canonical",
            "component-owned",
            "generated",
            "current-snapshot",
            "research",
            "historical",
            "superseded",
        ]
    ]
    generated_outputs: list[str]


class EcosystemRoadmap(ClosedModel):
    schema_version: Literal["AgenticSecurityEcosystemRoadmap.v1"]
    roadmap_id: Literal["agentic-security-ecosystem"]
    version: str
    canonical_repository: Literal[
        "https://github.com/krivonosoff161/agentic-security-harness"
    ]
    authority: Literal["none"]
    components: list[str]
    phases: list[Phase]
    documentation: DocumentationContract
    non_claims: list[str]

    @model_validator(mode="after")
    def semantic_contract(self) -> EcosystemRoadmap:
        _require_unique("component ids", self.components)
        _require_unique("phase ids", [phase.id for phase in self.phases])
        ids = {phase.id for phase in self.phases}
        state = {phase.id: phase.status for phase in self.phases}
        graph = {phase.id: phase.depends_on for phase in self.phases}
        for phase in self.phases:
            _require_unique(f"dependencies for {phase.id}", phase.depends_on)
            missing = set(phase.depends_on) - ids
            if missing:
                raise ValueError(f"phase {phase.id} has missing dependencies: {sorted(missing)}")
            if phase.id in phase.depends_on:
                raise ValueError(f"phase {phase.id} depends on itself")
            if phase.status == "complete" and any(
                state[dependency] != "complete" for dependency in phase.depends_on
            ):
                raise ValueError(f"complete phase {phase.id} has incomplete dependencies")
        _require_dag(graph)
        for path in self.documentation.generated_outputs:
            _require_relative_public_path(path)
        return self


class CompatibilityRow(ClosedModel):
    component_id: str
    integration_status: Literal[
        "standalone",
        "contract_only",
        "extension_candidate",
        "installable_extension",
        "suite_verified",
    ]
    harness_api: str
    python: str
    extension_python: str | None = None
    supported_platforms: list[Literal["linux", "windows", "macos", "web"]]
    tested_platforms: list[Literal["linux", "windows", "macos", "web"]]
    evidence: list[str]

    @model_validator(mode="after")
    def semantic_contract(self) -> CompatibilityRow:
        if not set(self.tested_platforms) <= set(self.supported_platforms):
            raise ValueError("tested platforms must be a subset of supported platforms")
        if self.integration_status == "extension_candidate":
            if self.extension_python != EXTENSION_CANDIDATE_PYTHON:
                raise ValueError("extension candidates require the exact extension Python range")
            if self.harness_api not in EXTENSION_CANDIDATE_HARNESS_APIS:
                raise ValueError("extension candidates require an exact Harness API")
            if not self.tested_platforms:
                raise ValueError("extension candidates require a tested platform")
            if not self.evidence:
                raise ValueError("extension candidates require public evidence")
        elif self.extension_python is not None:
            raise ValueError("extension Python range is only for extension candidates")
        for path in self.evidence:
            _require_relative_public_path(path)
        return self


class EcosystemCompatibility(ClosedModel):
    schema_version: Literal["AgenticSecurityEcosystemCompatibility.v1"]
    core_component: Literal["agentic-security-harness"]
    core_version: str
    harness_api: str
    rows: list[CompatibilityRow]


class ComponentLockEntry(ClosedModel):
    component_id: str
    visibility: Literal["public", "private"]
    repository: str | None
    source_ref: str | None
    source_commit: str | None
    source_tree: str | None
    manifest_sha256: str
    verification: Literal["exact_public_git", "sanitized_projection"]
    projection_path: str | None

    @model_validator(mode="after")
    def semantic_contract(self) -> ComponentLockEntry:
        if not re.fullmatch(r"[0-9a-f]{64}", self.manifest_sha256):
            raise ValueError("manifest_sha256 must be lowercase SHA-256")
        if self.verification == "exact_public_git":
            if self.visibility != "public" or not (
                self.repository
                and self.repository.startswith("https://github.com/")
                and self.source_ref
                and self.source_commit
                and self.source_tree
            ):
                raise ValueError("exact public Git entries require repository/ref/commit/tree")
            if not re.fullmatch(r"[0-9a-f]{40}", self.source_commit):
                raise ValueError("source_commit must be a full Git SHA-1")
            if not re.fullmatch(r"[0-9a-f]{40}", self.source_tree):
                raise ValueError("source_tree must be a full Git SHA-1")
            if self.projection_path is not None:
                raise ValueError("exact public Git entries cannot use a projection path")
        else:
            if self.visibility != "private" or any(
                value is not None
                for value in (
                    self.repository,
                    self.source_ref,
                    self.source_commit,
                    self.source_tree,
                )
            ):
                raise ValueError("sanitized projection must not expose private Git identity")
            if self.projection_path is None:
                raise ValueError("sanitized projection requires a public projection path")
            _require_relative_public_path(self.projection_path)
        return self


class ComponentsLock(ClosedModel):
    schema_version: Literal["AgenticSecurityEcosystemComponentsLock.v1"]
    digest_algorithm: Literal["sha256-canonical-json-v1"]
    roadmap_sha256: str
    authority: Literal["none"]
    entries: list[ComponentLockEntry]

    @model_validator(mode="after")
    def semantic_contract(self) -> ComponentsLock:
        if not re.fullmatch(r"[0-9a-f]{64}", self.roadmap_sha256):
            raise ValueError("roadmap_sha256 must be lowercase SHA-256")
        _require_unique("lock component ids", [entry.component_id for entry in self.entries])
        return self


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "component-manifest.v1.schema.json": ComponentManifest,
    "components-lock.v1.schema.json": ComponentsLock,
    "ecosystem-roadmap.v1.schema.json": EcosystemRoadmap,
    "compatibility.v1.schema.json": EcosystemCompatibility,
}


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_contract(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)


def load_contract_bytes(content: bytes) -> object:
    return json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicates)


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require_unique(label: str, values: Iterable[str]) -> None:
    ordered = list(values)
    if len(ordered) != len(set(ordered)):
        raise ValueError(f"{label} must be unique")


def _require_relative_public_path(value: str) -> None:
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe or non-portable path: {value}")


def _require_dag(graph: dict[str, list[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError(f"phase dependency cycle includes {node}")
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def validate_all() -> tuple[ComponentManifest, EcosystemRoadmap, EcosystemCompatibility]:
    component = ComponentManifest.model_validate(load_contract(ROOT / "component.yaml"))
    roadmap = EcosystemRoadmap.model_validate(load_contract(ECOSYSTEM / "roadmap.yaml"))
    compatibility = EcosystemCompatibility.model_validate(
        load_contract(ECOSYSTEM / "compatibility.json")
    )
    rows = [row.component_id for row in compatibility.rows]
    _require_unique("compatibility component ids", rows)
    if rows != roadmap.components:
        raise ValueError("compatibility rows must exactly follow roadmap component order")
    if component.component_id != compatibility.core_component:
        raise ValueError("local component must be the compatibility core")
    if component.package.version != compatibility.core_version:
        raise ValueError("core package and compatibility versions differ")
    return component, roadmap, compatibility


def validate_component_set(
    roots: list[Path],
) -> list[ComponentManifest]:
    """Validate exact source-owned manifests against the central roadmap and matrix."""
    _, roadmap, compatibility = validate_all()
    manifests = [
        ComponentManifest.model_validate(load_contract(root / "component.yaml"))
        for root in roots
    ]
    ids = [manifest.component_id for manifest in manifests]
    _require_unique("source component ids", ids)
    if ids != roadmap.components:
        raise ValueError("source component manifests must exactly follow roadmap component order")

    rows = {row.component_id: row for row in compatibility.rows}
    owned: dict[tuple[str, str], str] = {}
    for manifest in manifests:
        row = rows[manifest.component_id]
        validate_component_compatibility(manifest, row)
        for category in ("modules", "checks", "collectors", "contracts"):
            for item in getattr(manifest.owns, category):
                key = (category, item)
                previous = owned.get(key)
                if previous is not None:
                    raise ValueError(
                        f"{category} ownership collision for {item}: "
                        f"{previous} and {manifest.component_id}"
                    )
                owned[key] = manifest.component_id
    return manifests


def validate_component_compatibility(
    manifest: ComponentManifest, row: CompatibilityRow
) -> None:
    """Fail closed when a source manifest drifts from its central compatibility row."""

    if manifest.integration_status != row.integration_status:
        raise ValueError(f"integration status drift for {manifest.component_id}")
    if manifest.compatibility.harness_api != row.harness_api:
        raise ValueError(f"Harness API drift for {manifest.component_id}")
    if manifest.compatibility.python != row.python:
        raise ValueError(f"Python compatibility drift for {manifest.component_id}")
    if manifest.compatibility.platforms.supported != row.supported_platforms:
        raise ValueError(f"supported platform drift for {manifest.component_id}")
    if manifest.compatibility.platforms.tested != row.tested_platforms:
        raise ValueError(f"tested platform drift for {manifest.component_id}")


def validate_component_lock(roots: list[Path]) -> ComponentsLock:
    """Verify public source commits and the bounded private projection against the lock."""
    _, roadmap, _ = validate_all()
    lock = ComponentsLock.model_validate(load_contract(ECOSYSTEM / "components.lock.json"))
    if lock.roadmap_sha256 != sha256(load_contract(ECOSYSTEM / "roadmap.yaml")):
        raise ValueError("roadmap digest drift in component lock")
    if [entry.component_id for entry in lock.entries] != roadmap.components:
        raise ValueError("lock entries must exactly follow roadmap component order")

    public_roots: dict[str, Path] = {}
    for root in roots:
        manifest = ComponentManifest.model_validate(load_contract(root / "component.yaml"))
        if manifest.component_id in public_roots:
            raise ValueError(f"duplicate component root for {manifest.component_id}")
        public_roots[manifest.component_id] = root

    for entry in lock.entries:
        if entry.verification == "sanitized_projection":
            assert entry.projection_path is not None
            projection = ComponentManifest.model_validate(
                load_contract(ROOT / entry.projection_path)
            )
            if projection.component_id != entry.component_id:
                raise ValueError("sanitized projection component id drift")
            if sha256(projection.model_dump(mode="json")) != entry.manifest_sha256:
                raise ValueError("sanitized projection digest drift")
            continue

        source_root = public_roots.get(entry.component_id)
        if source_root is None:
            raise ValueError(f"missing exact public root for {entry.component_id}")
        assert entry.source_commit is not None and entry.source_tree is not None
        tree = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(source_root),
                "rev-parse",
                f"{entry.source_commit}^{{tree}}",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if tree != entry.source_tree:
            raise ValueError(f"source tree drift for {entry.component_id}")
        content = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(source_root),
                "show",
                f"{entry.source_commit}:component.yaml",
            ],
            check=True,
            capture_output=True,
        ).stdout
        manifest = ComponentManifest.model_validate(load_contract_bytes(content))
        if manifest.component_id != entry.component_id:
            raise ValueError(f"source manifest id drift for {entry.component_id}")
        if sha256(manifest.model_dump(mode="json")) != entry.manifest_sha256:
            raise ValueError(f"source manifest digest drift for {entry.component_id}")
    expected_public = {
        entry.component_id
        for entry in lock.entries
        if entry.verification == "exact_public_git"
    }
    if set(public_roots) != expected_public:
        raise ValueError("component roots must exactly match public lock entries")
    return lock


def generated_schemas() -> dict[str, bytes]:
    return {
        name: canonical_bytes(model.model_json_schema())
        for name, model in SCHEMA_MODELS.items()
    }


def _classify_document(path: str, policy: dict[str, object]) -> dict[str, object]:
    exact = policy["exact"]
    assert isinstance(exact, dict)
    if path in exact:
        value = exact[path]
        assert isinstance(value, dict)
        return dict(value)
    prefixes = policy["prefixes"]
    assert isinstance(prefixes, list)
    for entry in prefixes:
        assert isinstance(entry, dict)
        prefix = entry["prefix"]
        assert isinstance(prefix, str)
        if path.startswith(prefix):
            return {"role": entry["role"], "disposition": entry["disposition"], "replacement": None}
    markers = policy["research_markers"]
    assert isinstance(markers, list)
    if any(str(marker) in path.lower() for marker in markers):
        return {"role": "research", "disposition": "keep", "replacement": None}
    default = policy["default"]
    assert isinstance(default, dict)
    return {"role": default["role"], "disposition": default["disposition"], "replacement": None}


def build_document_registry() -> dict[str, object]:
    policy = load_contract(ECOSYSTEM / "document-policy.json")
    assert isinstance(policy, dict)
    candidates = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "GOVERNANCE.md"]
    candidates.extend(
        path
        for path in (ROOT / "docs").rglob("*")
        if path.is_file() and path.suffix.lower() in {".md", ".json", ".yaml", ".yml"}
    )
    documents = {file_path.relative_to(ROOT).as_posix() for file_path in candidates}
    entries: list[dict[str, object]] = []
    for relative in sorted(documents):
        classification = _classify_document(relative, policy)
        entries.append(
            {
                "path": relative,
                "role": classification["role"],
                "disposition": classification["disposition"],
                "replacement": classification.get("replacement"),
                "owner": "agentic-security-harness",
            }
        )
    return {
        "schema_version": "AgenticSecurityDocumentRegistry.v1",
        "generated_from": "ecosystem/document-policy.json",
        "entries": entries,
    }


def _render_roadmap(roadmap: EcosystemRoadmap) -> str:
    lines = [
        "# Agentic Security ecosystem roadmap",
        "",
        "> Generated from `ecosystem/roadmap.yaml`; edit the machine contract, not this file.",
        "> Roadmap entries grant no operational authority.",
        "",
        f"Version: `{roadmap.version}`  ",
        f"Authority: `{roadmap.authority}`",
        "",
        "## Ordered phases",
        "",
        "| Phase | Status | Depends on | Deliverables |",
        "|---|---|---|---|",
    ]
    for phase in roadmap.phases:
        depends = ", ".join(f"`{item}`" for item in phase.depends_on) or "none"
        deliverables = "; ".join(phase.deliverables)
        lines.append(f"| `{phase.id}` | **{phase.status}** | {depends} | {deliverables} |")
    lines.extend(["", "## Explicit non-claims", ""])
    lines.extend(f"- {claim}" for claim in roadmap.non_claims)
    return "\n".join(lines) + "\n"


def _render_components(compatibility: EcosystemCompatibility) -> str:
    lines = [
        "# Ecosystem components",
        "",
        "> Generated from `ecosystem/compatibility.json` and the ordered component list.",
        "",
        "| Component | Integration | Harness API | Source package Python | "
        "Extension Python | Supported | Tested |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in compatibility.rows:
        supported = ", ".join(row.supported_platforms) or "none"
        tested = ", ".join(row.tested_platforms) or "not yet recorded"
        lines.append(
            f"| `{row.component_id}` | `{row.integration_status}` | "
            f"`{row.harness_api}` | `{row.python}` | "
            f"`{row.extension_python or 'not applicable'}` | {supported} | {tested} |"
        )
    lines.extend(
        [
            "",
            "`contract_only` and `standalone` are honest current states. They do not mean",
            "the component is already installable through the Harness Extension API.",
            "`extension_candidate` identifies an exact review-only source extension tested",
            "by Harness; it is not a released dependency and grants no execution authority.",
            "For that state, source-package Python preserves the base package declaration",
            "and extension Python records the separately tested nested runtime range.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_document_map(registry: dict[str, object]) -> str:
    entries = registry["entries"]
    assert isinstance(entries, list)
    counts: dict[str, int] = {}
    for entry in entries:
        assert isinstance(entry, dict)
        role = str(entry["role"])
        counts[role] = counts.get(role, 0) + 1
    lines = [
        "# Documentation map",
        "",
        "> Generated from `ecosystem/document-policy.json` and the current documentation tree.",
        "",
        f"The registry classifies **{len(entries)}** current documentation artifacts.",
        "",
        "| Role | Files |",
        "|---|---:|",
    ]
    lines.extend(f"| `{role}` | {count} |" for role, count in sorted(counts.items()))
    lines.extend(
        [
            "",
            "The complete per-file crosswalk is `ecosystem/document-registry.json`.",
            "Historical and research records are preserved; superseded pages redirect "
            "rather than disappear.",
        ]
    )
    return "\n".join(lines) + "\n"


def generated_outputs() -> dict[Path, bytes]:
    _, roadmap, compatibility = validate_all()
    registry = build_document_registry()
    outputs: dict[Path, bytes] = {
        ECOSYSTEM / "document-registry.json": canonical_bytes(registry),
        ROOT / "docs" / "ecosystem-roadmap.md": _render_roadmap(roadmap).encode(),
        ROOT / "docs" / "ecosystem-components.md": _render_components(compatibility).encode(),
        ROOT / "docs" / "documentation-map.md": _render_document_map(registry).encode(),
    }
    outputs.update({SCHEMAS / name: content for name, content in generated_schemas().items()})
    return outputs


def write_generated() -> None:
    for path, content in generated_outputs().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def check_generated() -> None:
    mismatches: list[str] = []
    for path, expected in generated_outputs().items():
        if not path.is_file() or path.read_bytes() != expected:
            mismatches.append(path.relative_to(ROOT).as_posix())
    if mismatches:
        raise ValueError(f"generated ecosystem files are stale: {', '.join(mismatches)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("check", "generate", "check-components", "check-lock")
    )
    parser.add_argument(
        "--component-root",
        action="append",
        default=[],
        type=Path,
        help="source repository root; repeat in roadmap order",
    )
    args = parser.parse_args()
    if args.mode == "generate":
        write_generated()
    elif args.mode == "check-components":
        if not args.component_root:
            parser.error("check-components requires --component-root")
        validate_component_set(args.component_root)
    elif args.mode == "check-lock":
        if not args.component_root:
            parser.error("check-lock requires --component-root")
        validate_component_lock(args.component_root)
    else:
        validate_all()
        check_generated()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
