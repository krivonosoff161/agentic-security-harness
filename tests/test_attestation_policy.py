"""Independent negative fixtures for the release-attestation policy."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentic_security_harness.attestation_policy import (
    GITHUB_WORKFLOW_BUILD_TYPE,
    IN_TOTO_STATEMENT_V1,
    SLSA_PROVENANCE_V1,
    main,
    validate_verification_results,
)

REPOSITORY = "krivonosoff161/agentic-security-harness"
WORKFLOW = ".github/workflows/release.yml"
REF = "refs/tags/v0.14.0"
SOURCE_DIGEST = "a" * 40
SUBJECT_DIGEST = "b" * 64


def _verified_entry() -> dict[str, object]:
    repo_url = f"https://github.com/{REPOSITORY}"
    return {
        "attestation": {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
        "verificationResult": {
            "verifiedTimestamps": [{"type": "transparency-log"}],
            "signature": {"certificate": {"issuer": "https://token.actions.githubusercontent.com"}},
            "statement": {
                "_type": IN_TOTO_STATEMENT_V1,
                "subject": [{"name": "package.whl", "digest": {"sha256": SUBJECT_DIGEST}}],
                "predicateType": SLSA_PROVENANCE_V1,
                "predicate": {
                    "buildDefinition": {
                        "buildType": GITHUB_WORKFLOW_BUILD_TYPE,
                        "externalParameters": {
                            "workflow": {
                                "repository": repo_url,
                                "path": WORKFLOW,
                                "ref": REF,
                            }
                        },
                        "internalParameters": {
                            "github": {
                                "event_name": "push",
                                "runner_environment": "github-hosted",
                            }
                        },
                        "resolvedDependencies": [
                            {
                                "uri": f"git+{repo_url}@{REF}",
                                "digest": {"gitCommit": SOURCE_DIGEST},
                            }
                        ],
                    },
                    "runDetails": {
                        "builder": {"id": f"{repo_url}/{WORKFLOW}@{REF}"},
                        "metadata": {"invocationId": "https://github.com/run/1"},
                    },
                },
            },
        },
    }


def _issues(payload: object) -> list[str]:
    return validate_verification_results(
        payload,
        repository=REPOSITORY,
        workflow_path=WORKFLOW,
        source_ref=REF,
        source_digest=SOURCE_DIGEST,
        subject_sha256=SUBJECT_DIGEST,
    )


def test_exact_release_attestation_policy_accepts() -> None:
    assert _issues([_verified_entry()]) == []


@pytest.mark.parametrize(
    ("path", "bad_value", "expected"),
    [
        (("verificationResult", "verifiedTimestamps"), [], "timestamp"),
        (
            ("verificationResult", "statement", "_type"),
            "https://example.test/statement",
            "statement type",
        ),
        (
            ("verificationResult", "statement", "predicateType"),
            "https://example.test/v1",
            "predicate",
        ),
        (
            ("verificationResult", "statement", "subject", 0, "digest", "sha256"),
            "0" * 64,
            "subject",
        ),
        (
            ("verificationResult", "statement", "predicate", "buildDefinition", "buildType"),
            "bad",
            "build type",
        ),
        (
            (
                "verificationResult",
                "statement",
                "predicate",
                "buildDefinition",
                "externalParameters",
                "workflow",
                "repository",
            ),
            "https://github.com/other/repo",
            "workflow",
        ),
        (
            (
                "verificationResult",
                "statement",
                "predicate",
                "buildDefinition",
                "externalParameters",
                "workflow",
                "path",
            ),
            ".github/workflows/other.yml",
            "workflow",
        ),
        (
            (
                "verificationResult",
                "statement",
                "predicate",
                "buildDefinition",
                "externalParameters",
                "workflow",
                "ref",
            ),
            "refs/heads/main",
            "workflow",
        ),
        (
            (
                "verificationResult",
                "statement",
                "predicate",
                "buildDefinition",
                "internalParameters",
                "github",
                "event_name",
            ),
            "workflow_dispatch",
            "push event",
        ),
        (
            (
                "verificationResult",
                "statement",
                "predicate",
                "buildDefinition",
                "internalParameters",
                "github",
                "runner_environment",
            ),
            "self-hosted",
            "GitHub-hosted",
        ),
        (
            (
                "verificationResult",
                "statement",
                "predicate",
                "buildDefinition",
                "resolvedDependencies",
                0,
                "digest",
                "gitCommit",
            ),
            "c" * 40,
            "source ref/digest",
        ),
        (
            ("verificationResult", "statement", "predicate", "runDetails", "builder", "id"),
            "https://example.test/builder",
            "builder identity",
        ),
    ],
)
def test_release_attestation_policy_negative_fixtures(
    path: tuple[str | int, ...], bad_value: object, expected: str
) -> None:
    payload: object = copy.deepcopy(_verified_entry())
    cursor: object = payload
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = bad_value  # type: ignore[index]

    assert any(expected in issue for issue in _issues([payload]))


def test_one_exact_attestation_is_sufficient_among_verified_candidates() -> None:
    wrong = copy.deepcopy(_verified_entry())
    wrong["verificationResult"]["statement"]["predicate"]["runDetails"]["builder"]["id"] = "bad"  # type: ignore[index]
    assert _issues([wrong, _verified_entry()]) == []


def test_release_attestation_policy_rejects_unexpected_external_parameters() -> None:
    entry: Any = _verified_entry()
    entry["verificationResult"]["statement"]["predicate"]["buildDefinition"][
        "externalParameters"
    ]["workflowInputs"] = {"unreviewed": "value"}

    assert any("external parameters" in issue for issue in _issues([entry]))


def test_release_attestation_policy_rejects_unexpected_workflow_parameters() -> None:
    entry: Any = _verified_entry()
    entry["verificationResult"]["statement"]["predicate"]["buildDefinition"][
        "externalParameters"
    ]["workflow"]["actor"] = "unreviewed"

    assert any("workflow" in issue for issue in _issues([entry]))


def test_cli_hashes_exact_artifact_bytes(tmp_path: Path) -> None:
    artifact = tmp_path / "package.whl"
    artifact.write_bytes(b"release-bytes")
    entry = _verified_entry()
    entry["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = hashlib.sha256(  # type: ignore[index]
        artifact.read_bytes()
    ).hexdigest()
    verified = tmp_path / "verified.json"
    verified.write_text(json.dumps([entry]), encoding="utf-8")

    assert (
        main(
            [
                "--artifact",
                str(artifact),
                "--verification-json",
                str(verified),
                "--repository",
                REPOSITORY,
                "--workflow-path",
                WORKFLOW,
                "--source-ref",
                REF,
                "--source-digest",
                SOURCE_DIGEST,
            ]
        )
        == 0
    )
