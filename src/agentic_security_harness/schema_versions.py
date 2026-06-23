"""Single source of truth for benchmark artifact schema versions.

Every versioned JSON artifact declares a ``schema_version``. This module centralizes the
current version and the set of versions this build of the tool can read, so the models
and the validator cannot drift. See ``docs/artifact-schemas.md`` for the compatibility
policy and what counts as a breaking change.

No imports from other package modules - keep this a leaf so models can import it.
"""

from __future__ import annotations

# Current schema_version written by this build, keyed by artifact kind.
SCHEMA_VERSIONS: dict[str, str] = {
    "trace": "0.1",            # one item in traces.json
    "scorecard": "0.1",       # scorecard.json
    "remediation": "0.1",     # remediation.json
    "matrix": "0.2",          # matrix.json
    "run_config": "0.1",      # run_config.json (external)
    "external_summary": "0.1",  # external_summary.json
    "run_manifest": "0.1",    # run_index.json
    "run_diff": "0.2",        # run_diff.json (0.2: explicit decisive/non-decisive labels)
    "evidence_quality": "0.2",  # evidence_quality.json (derived external/local/swarm analysis)
    "local_swarm": "0.1",     # local_swarm_summary.json (bounded local swarm research)
    "local_swarm_matrix": "0.1",  # local_swarm_attack_matrix.json
    "evidence_campaign": "0.2",  # evidence_campaign_summary.json (0.2: control ablation)
}

# Current implemented defensive corpus revision. Artifact schema versions describe file
# shape; corpus version describes benchmark content and pattern semantics.
CORPUS_VERSION = "0.13.0"

# Versions this build can READ for each artifact kind (forward/back compatibility).
# Today each kind reads exactly its current version; widen these sets when a
# backwards-compatible revision is added.
KNOWN_SCHEMA_VERSIONS: dict[str, frozenset[str]] = {
    kind: frozenset({version}) for kind, version in SCHEMA_VERSIONS.items()
}
KNOWN_SCHEMA_VERSIONS["run_diff"] = frozenset({"0.1", SCHEMA_VERSIONS["run_diff"]})
KNOWN_SCHEMA_VERSIONS["evidence_quality"] = frozenset({
    "0.1",
    SCHEMA_VERSIONS["evidence_quality"],
})


def schema_version(kind: str) -> str:
    """Return the current schema_version string for an artifact kind."""
    return SCHEMA_VERSIONS[kind]


def is_known(kind: str, version: str) -> bool:
    """True if this build can read ``version`` of ``kind``."""
    return version in KNOWN_SCHEMA_VERSIONS.get(kind, frozenset())


def check_schema_version(
    kind: str, version: str | None, *, required: bool = True
) -> str | None:
    """Validate one artifact's declared schema_version.

    Returns an error message, or ``None`` when acceptable. ``version`` is ``None`` when the
    field is absent. A future/unknown version yields a clear, actionable error rather than
    a confusing downstream parse failure.
    """
    if version is None or version == "":
        if required:
            supported = ", ".join(sorted(KNOWN_SCHEMA_VERSIONS.get(kind, frozenset())))
            return f"missing schema_version for {kind} artifact (supported: {supported})"
        return None
    if not is_known(kind, version):
        supported = ", ".join(sorted(KNOWN_SCHEMA_VERSIONS.get(kind, frozenset())))
        return (
            f"unknown/future schema_version '{version}' for {kind} artifact; "
            f"this build supports: {supported or '(none)'}. Upgrade the tool to read it."
        )
    return None
