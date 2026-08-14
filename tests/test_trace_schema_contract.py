"""Regression contract for the frozen public trace schema v1."""

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_security_harness.models import ExploitTrace
from agentic_security_harness.trace_schema import (
    TRACE_SCHEMA_LEGACY_VERSIONS,
    TRACE_SCHEMA_V1,
    migrate_trace_payload_to_v1,
    parse_trace_payload,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "trace-schema"
SCHEMA_PATH = ROOT / "schemas" / "trace.schema.json"


def _load(name: str) -> dict[str, object]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_current_and_legacy_fixtures_parse_to_the_same_semantics() -> None:
    legacy = parse_trace_payload(_load("trace-v0.1.json"))
    current = parse_trace_payload(_load("trace-v1.0.json"))
    assert TRACE_SCHEMA_V1 == "1.0"
    assert TRACE_SCHEMA_LEGACY_VERSIONS == frozenset({"0.1"})
    assert legacy.model_dump(exclude={"schema_version"}) == current.model_dump(
        exclude={"schema_version"}
    )


def test_migration_changes_only_the_version_and_is_idempotent() -> None:
    legacy = _load("trace-v0.1.json")
    expected = _load("trace-v1.0.json")
    migrated = migrate_trace_payload_to_v1(legacy)
    assert migrated == expected
    assert migrate_trace_payload_to_v1(migrated) == expected


@pytest.mark.parametrize(
    ("location", "extra_key"),
    [
        ((), "unexpected"),
        (("target",), "unexpected_target"),
        (("steps", 0), "unexpected_step"),
    ],
)
def test_unknown_typed_fields_fail_closed(
    location: tuple[str | int, ...], extra_key: str
) -> None:
    payload = copy.deepcopy(_load("trace-v1.0.json"))
    target: object = payload
    for part in location:
        if isinstance(part, int):
            assert isinstance(target, list)
            target = target[part]
        else:
            assert isinstance(target, dict)
            target = target[part]
    assert isinstance(target, dict)
    target[extra_key] = "rejected"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_trace_payload(payload)


def test_reproducibility_is_the_explicit_extension_map() -> None:
    payload = _load("trace-v1.0.json")
    reproducibility = payload["reproducibility"]
    assert isinstance(reproducibility, dict)
    reproducibility["consumer_extension"] = {"version": 1, "enabled": True}
    assert parse_trace_payload(payload).reproducibility["consumer_extension"] == {
        "version": 1,
        "enabled": True,
    }


@pytest.mark.parametrize(
    ("path", "coerced_value"),
    [
        (("steps", 0, "index"), "0"),
        (("target", "type"), 7),
        (("data_envelope", "can_store"), "false"),
    ],
)
def test_json_schema_types_are_not_coerced(
    path: tuple[str | int, ...], coerced_value: object
) -> None:
    payload = _load("trace-v1.0.json")
    if path[0] == "data_envelope":
        payload["data_envelope"] = {"data_class": "public", "can_store": True}
    target: object = payload
    for part in path[:-1]:
        if isinstance(part, int):
            assert isinstance(target, list)
            target = target[part]
        else:
            assert isinstance(target, dict)
            target = target[part]
    assert isinstance(target, dict)
    key = path[-1]
    assert isinstance(key, str)
    target[key] = coerced_value
    with pytest.raises(ValidationError):
        parse_trace_payload(payload)


@pytest.mark.parametrize("nested_field", ["findings", "data_envelope"])
def test_unknown_finding_and_envelope_fields_fail_closed(nested_field: str) -> None:
    payload = _load("trace-v1.0.json")
    if nested_field == "findings":
        payload["findings"] = [
            {
                "code": "fixture",
                "severity": "low",
                "message": "synthetic fixture finding",
                "unexpected_finding": "rejected",
            }
        ]
    else:
        payload["data_envelope"] = {
            "data_class": "public",
            "unexpected_envelope": "rejected",
        }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_trace_payload(payload)


@pytest.mark.parametrize("version", [None, "", "2.0", "9.9"])
def test_missing_or_future_versions_fail_before_structural_parsing(
    version: str | None,
) -> None:
    payload = _load("trace-v1.0.json")
    if version is None:
        del payload["schema_version"]
    else:
        payload["schema_version"] = version
    with pytest.raises(ValueError, match="schema_version"):
        parse_trace_payload(payload)


def test_public_json_schema_is_closed_and_matches_model_fields() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"] == {"const": TRACE_SCHEMA_V1}
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == set(ExploitTrace.model_fields)
    for definition in ("target", "trace_step", "finding", "data_envelope"):
        assert schema["$defs"][definition]["additionalProperties"] is False
    assert schema["properties"]["reproducibility"]["additionalProperties"] is True
