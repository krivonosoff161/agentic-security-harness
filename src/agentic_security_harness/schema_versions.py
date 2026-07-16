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
    "run_config": "0.2",      # 0.2: pre-request execution identity
    "external_summary": "0.2",  # 0.2: execution-bound external bundle
    "run_manifest": "0.3",    # 0.3: listed artifact content hashes
    "run_diff": "0.3",        # 0.3: validated source commitments + output manifest
    "evidence_quality": "0.3",  # 0.3: input validation/authenticity scope per run
    "run_stats": "0.2",       # 0.2: independently recomputed expectation status
    "showcase": "0.2",        # 0.2: independently recomputed expectation status
    "local_swarm": "0.1",     # local_swarm_summary.json (bounded local swarm research)
    "local_swarm_matrix": "0.2",  # local_swarm_attack_matrix.json
    "evidence_campaign": "0.2",  # evidence_campaign_summary.json (0.2: control ablation)
    "secret_leak_campaign": "0.1",  # secret_leak_campaign_summary.json
    "secret_leak_variations": "0.1",  # secret_leak_variation_summary.json
    "semantic_drift_campaign": "0.2",  # 0.2: independent-label contract
    "semantic_propagation_campaign": "0.3",  # 0.3: independent-label contract
    "swarm_defense_contour": "0.2",  # 0.2: executable-specification evidence class
    "swarm_defense_live_campaign": "0.5",  # 0.5: staged adapter-error contract
    "marketing_web_injection_campaign": "0.1",  # marketing_web_injection_summary.json
    "marketing_web_live_campaign": "0.3",  # 0.3: staged adapter-error contract
    "swarm_resilience_campaign": "0.1",  # swarm_resilience_summary.json
    "context_consent_campaign": "0.2",  # 0.2: executable-specification evidence class
    "tool_authority_campaign": "0.2",  # 0.2: executable-specification evidence class
    "rag_context_campaign": "0.2",  # 0.2: executable-specification evidence class
    "planner_task_campaign": "0.2",  # 0.2: executable-specification evidence class
    "memory_rehydration_campaign": "0.2",  # 0.2: executable-specification evidence class
    "evidence_status_registry": "0.1",  # public evidence classification inventory
    "private_public_reconciliation": "0.1",  # unsigned owner-side byte receipt
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
KNOWN_SCHEMA_VERSIONS["run_diff"] = frozenset({
    "0.1",
    "0.2",
    SCHEMA_VERSIONS["run_diff"],
})
KNOWN_SCHEMA_VERSIONS["evidence_quality"] = frozenset({
    "0.1",
    "0.2",
    SCHEMA_VERSIONS["evidence_quality"],
})
KNOWN_SCHEMA_VERSIONS["run_manifest"] = frozenset({
    "0.1",
    "0.2",
    SCHEMA_VERSIONS["run_manifest"],
})
KNOWN_SCHEMA_VERSIONS["run_config"] = frozenset({
    "0.1",
    SCHEMA_VERSIONS["run_config"],
})
KNOWN_SCHEMA_VERSIONS["external_summary"] = frozenset({
    "0.1",
    SCHEMA_VERSIONS["external_summary"],
})
KNOWN_SCHEMA_VERSIONS["run_stats"] = frozenset({
    "0.1",
    SCHEMA_VERSIONS["run_stats"],
})
KNOWN_SCHEMA_VERSIONS["showcase"] = frozenset({
    "0.1",
    SCHEMA_VERSIONS["showcase"],
})
KNOWN_SCHEMA_VERSIONS["semantic_propagation_campaign"] = frozenset({
    "0.1",
    "0.2",
    SCHEMA_VERSIONS["semantic_propagation_campaign"],
})
KNOWN_SCHEMA_VERSIONS["semantic_drift_campaign"] = frozenset({
    "0.1",
    SCHEMA_VERSIONS["semantic_drift_campaign"],
})
KNOWN_SCHEMA_VERSIONS["swarm_defense_live_campaign"] = frozenset({
    "0.1",
    "0.2",
    "0.3",
    "0.4",
    SCHEMA_VERSIONS["swarm_defense_live_campaign"],
})
KNOWN_SCHEMA_VERSIONS["marketing_web_live_campaign"] = frozenset({
    "0.1",
    "0.2",
    SCHEMA_VERSIONS["marketing_web_live_campaign"],
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
