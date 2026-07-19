"""Fail-closed policy checks for GitHub artifact-attestation verification output.

Cryptographic verification remains the responsibility of ``gh attestation verify``.
This module checks the authenticated result against the release policy that the CLI's
generic signature verification cannot infer for this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
GITHUB_WORKFLOW_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: object) -> Sequence[object] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _entry_issues(
    entry: object,
    *,
    repository: str,
    workflow_path: str,
    source_ref: str,
    source_digest: str,
    subject_sha256: str,
) -> list[str]:
    issues: list[str] = []
    row = _mapping(entry)
    if row is None:
        return ["verification entry is not an object"]

    result = _mapping(row.get("verificationResult"))
    if result is None:
        return ["verificationResult is missing"]
    timestamps = _sequence(result.get("verifiedTimestamps"))
    if not timestamps:
        issues.append("verified transparency/timestamp evidence is missing")

    statement = _mapping(result.get("statement"))
    if statement is None:
        return [*issues, "verified statement is missing"]
    if statement.get("_type") != IN_TOTO_STATEMENT_V1:
        issues.append("statement type is not in-toto Statement v1")
    if statement.get("predicateType") != SLSA_PROVENANCE_V1:
        issues.append("predicate type is not SLSA provenance v1")

    subjects = _sequence(statement.get("subject"))
    subject_match = False
    if subjects is not None:
        for subject in subjects:
            subject_row = _mapping(subject)
            digest = _mapping(subject_row.get("digest")) if subject_row else None
            if digest and str(digest.get("sha256", "")).lower() == subject_sha256:
                subject_match = True
                break
    if not subject_match:
        issues.append("attested subject digest does not match the artifact")

    predicate = _mapping(statement.get("predicate"))
    build_definition = _mapping(predicate.get("buildDefinition")) if predicate else None
    run_details = _mapping(predicate.get("runDetails")) if predicate else None
    if build_definition is None or run_details is None:
        return [*issues, "SLSA buildDefinition or runDetails is missing"]
    if build_definition.get("buildType") != GITHUB_WORKFLOW_BUILD_TYPE:
        issues.append("unexpected SLSA build type")

    repo_url = f"https://github.com/{repository}"
    external_parameters = _mapping(build_definition.get("externalParameters"))
    if external_parameters is None or set(external_parameters) != {"workflow"}:
        issues.append("unexpected SLSA external parameters")
    workflow = _mapping(external_parameters.get("workflow")) if external_parameters else None
    expected_workflow = {
        "repository": repo_url,
        "path": workflow_path,
        "ref": source_ref,
    }
    if (
        workflow is None
        or set(workflow) != set(expected_workflow)
        or any(workflow.get(key) != value for key, value in expected_workflow.items())
    ):
        issues.append("workflow repository/path/ref does not match release policy")

    internal_parameters = _mapping(build_definition.get("internalParameters"))
    github_parameters = _mapping(internal_parameters.get("github")) if internal_parameters else None
    if github_parameters is None or github_parameters.get("event_name") != "push":
        issues.append("attestation was not produced by a push event")
    if github_parameters is None or github_parameters.get("runner_environment") != "github-hosted":
        issues.append("attestation was not produced on a GitHub-hosted runner")

    expected_uri = f"git+{repo_url}@{source_ref}"
    dependency_match = False
    dependencies = _sequence(build_definition.get("resolvedDependencies"))
    if dependencies is not None:
        for dependency in dependencies:
            dependency_row = _mapping(dependency)
            digest = _mapping(dependency_row.get("digest")) if dependency_row else None
            if (
                dependency_row
                and dependency_row.get("uri") == expected_uri
                and digest
                and digest.get("gitCommit") == source_digest
            ):
                dependency_match = True
                break
    if not dependency_match:
        issues.append("resolved source ref/digest does not match the release source")

    builder = _mapping(run_details.get("builder"))
    expected_builder = f"{repo_url}/{workflow_path}@{source_ref}"
    if builder is None or builder.get("id") != expected_builder:
        issues.append("builder identity does not match the release workflow")
    return issues


def validate_verification_results(
    payload: object,
    *,
    repository: str,
    workflow_path: str,
    source_ref: str,
    source_digest: str,
    subject_sha256: str,
) -> list[str]:
    """Return policy failures; one fully matching verified attestation is sufficient."""
    rows = _sequence(payload)
    if not rows:
        return ["verification output contains no attestations"]
    failures = [
        _entry_issues(
            entry,
            repository=repository,
            workflow_path=workflow_path,
            source_ref=source_ref,
            source_digest=source_digest,
            subject_sha256=subject_sha256,
        )
        for entry in rows
    ]
    if any(not issues for issues in failures):
        return []
    return [
        f"attestation[{index}]: {issue}"
        for index, issues in enumerate(failures)
        for issue in issues
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="enforce the ASH release-attestation policy")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--verification-json", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-digest", required=True)
    args = parser.parse_args(argv)

    try:
        payload = json.loads(args.verification_json.read_text(encoding="utf-8"))
        issues = validate_verification_results(
            payload,
            repository=args.repository,
            workflow_path=args.workflow_path,
            source_ref=args.source_ref,
            source_digest=args.source_digest,
            subject_sha256=_sha256(args.artifact),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"release attestation policy error: {type(exc).__name__}")
        return 2
    if issues:
        for issue in issues:
            print(f"release attestation policy failure: {issue}")
        return 1
    print(f"release attestation policy accepted: {args.artifact.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
