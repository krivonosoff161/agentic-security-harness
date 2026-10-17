"""Exact-action request and Ed25519 decision verification.

Only a trusted host constructs requests and supplies enrolled public keys. This
module deliberately has no signer or private-key API.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQUEST_DOMAIN = "ash-action-authority-request-v1"
DECISION_DOMAIN = "ash-action-authority-decision-v1"
_MAX_INT = 2**53
_MAX_FILE_ID = 2**128 - 1
_MAX_CANONICAL_BYTES = 16384
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_REQUEST_FIELDS = frozenset(
    {
        "domain",
        "binding",
        "epoch",
        "challenge",
        "expires_at",
        "key_id",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "app_id",
        "task_id",
        "operation_id",
        "initiator",
        "action",
        "artifact",
        "policy_sha256",
        "source_admission_sha256",
        "root_path",
        "root_device",
        "root_inode",
        "filename",
        "payload_sha256",
        "payload_length",
        "dependencies",
        "operator_key_fingerprint",
    }
)
_DECISION_FIELDS = frozenset(
    {
        "domain",
        "request_digest",
        "epoch",
        "challenge",
        "key_id",
        "expires_at",
        "decision",
        "issued_at",
    }
)
_BINDING_STRING_LIMITS = {
    "app_id": 128,
    "task_id": 128,
    "operation_id": 128,
    "initiator": 128,
    "artifact": 128,
    "root_path": 4096,
    "filename": 255,
}


class ProtocolError(ValueError):
    """Invalid, unbound, expired, or unauthenticated protocol input."""


def _integer(value: object, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or not (
        0 < value <= _MAX_INT if positive else 0 <= value <= _MAX_INT
    ):
        raise ProtocolError(f"{name}_invalid")
    return value


def _string(value: object, name: str, limit: int) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= limit
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)
    ):
        raise ProtocolError(f"{name}_invalid")
    return value


def _file_id(value: object, name: str) -> str:
    if (
        type(value) is not str
        or len(value) > 39
        or _DECIMAL.fullmatch(value) is None
        or int(value) > _MAX_FILE_ID
    ):
        raise ProtocolError(f"{name}_invalid")
    return value


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ProtocolError(f"{name}_invalid")
    return value


def _fields(value: object, expected: frozenset[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ProtocolError(f"{name}_fields_invalid")
    return value


def _canonical_value(value: object, depth: int) -> None:
    if depth > 6:
        raise ProtocolError("canonical_depth_invalid")
    if value is None:
        return
    if type(value) is str:
        _string(value, "canonical_string", 4096)
        return
    if type(value) is int:
        _integer(value, "canonical_integer")
        return
    if type(value) is dict and len(value) <= 64:
        for key, item in value.items():
            _string(key, "canonical_key", 128)
            _canonical_value(item, depth + 1)
        return
    raise ProtocolError("canonical_type_invalid")


def canonical(value: object) -> bytes:
    """Encode a bounded, deterministic JSON subset; reject floats and booleans."""
    _canonical_value(value, 0)
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("canonical_encoding_invalid") from exc
    if len(raw) > _MAX_CANONICAL_BYTES:
        raise ProtocolError("canonical_size_invalid")
    return raw


def _binding(value: object) -> dict[str, Any]:
    binding = _fields(value, _BINDING_FIELDS, "binding")
    for name, limit in _BINDING_STRING_LIMITS.items():
        _string(binding[name], name, limit)
    if type(binding["action"]) is not str or binding["action"] != "write_text":
        raise ProtocolError("action_invalid")
    for name in ("policy_sha256", "payload_sha256", "operator_key_fingerprint"):
        _digest(binding[name], name)
    admission = binding["source_admission_sha256"]
    if admission is not None:
        _digest(admission, "source_admission_sha256")
    for name in ("root_device", "root_inode"):
        _file_id(binding[name], name)
    if _integer(binding["payload_length"], "payload_length", positive=True) > 65536:
        raise ProtocolError("payload_length_invalid")
    dependencies = binding["dependencies"]
    if type(dependencies) is not dict or len(dependencies) > 32:
        raise ProtocolError("dependencies_invalid")
    for name, digest in dependencies.items():
        _string(name, "dependency_name", 128)
        _digest(digest, "dependency_digest")
    canonical(binding)
    return binding


def _request(value: object) -> dict[str, Any]:
    request = _fields(value, _REQUEST_FIELDS, "request")
    if request["domain"] != REQUEST_DOMAIN:
        raise ProtocolError("request_domain_invalid")
    _binding(request["binding"])
    _integer(request["epoch"], "epoch")
    _digest(request["challenge"], "challenge")
    _integer(request["expires_at"], "expires_at", positive=True)
    _string(request["key_id"], "key_id", 128)
    canonical(request)
    return request


def build_request(
    binding: dict[str, Any],
    *,
    epoch: int,
    challenge: str,
    expires_at: int,
    key_id: str,
) -> dict[str, Any]:
    """Build an immutable-by-convention host request with an exact closed schema."""
    checked = _binding(binding)
    request = {
        "domain": REQUEST_DOMAIN,
        "binding": {**checked, "dependencies": dict(checked["dependencies"])},
        "epoch": epoch,
        "challenge": challenge,
        "expires_at": expires_at,
        "key_id": key_id,
    }
    _request(request)
    return request


def request_digest(request: dict[str, Any]) -> str:
    """Digest the entire validated request, including its signing domain."""
    return hashlib.sha256(canonical(_request(request))).hexdigest()


def decision_message(
    request: dict[str, Any],
    *,
    decision: Literal["approve", "revoke"],
    issued_at: int,
) -> dict[str, Any]:
    """Construct the exact bytes an external operator signer must sign."""
    checked = _request(request)
    if decision not in ("approve", "revoke") or type(decision) is not str:
        raise ProtocolError("decision_invalid")
    _integer(issued_at, "issued_at")
    if issued_at >= checked["expires_at"]:
        raise ProtocolError("decision_expired")
    message = {
        "domain": DECISION_DOMAIN,
        "request_digest": request_digest(checked),
        "epoch": checked["epoch"],
        "challenge": checked["challenge"],
        "key_id": checked["key_id"],
        "expires_at": checked["expires_at"],
        "decision": decision,
        "issued_at": issued_at,
    }
    canonical(message)
    return message


def verify_decision(
    request: dict[str, Any],
    message: dict[str, Any],
    signature: bytes,
    public_key: bytes,
    *,
    now: int,
) -> dict[str, Any]:
    """Verify one operator decision; freshness and single use remain engine duties."""
    checked = _request(request)
    _integer(now, "now")
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ProtocolError("public_key_invalid")
    if hashlib.sha256(public_key).hexdigest() != checked["binding"]["operator_key_fingerprint"]:
        raise ProtocolError("operator_key_mismatch")
    if type(signature) is not bytes or len(signature) != 64:
        raise ProtocolError("signature_invalid")
    signed = _fields(message, _DECISION_FIELDS, "decision")
    if signed["domain"] != DECISION_DOMAIN:
        raise ProtocolError("decision_domain_invalid")
    if signed["decision"] not in ("approve", "revoke") or type(signed["decision"]) is not str:
        raise ProtocolError("decision_invalid")
    issued_at = _integer(signed["issued_at"], "issued_at")
    if issued_at > now or now >= checked["expires_at"]:
        raise ProtocolError("decision_time_invalid")
    for name, expected in (
        ("request_digest", request_digest(checked)),
        ("epoch", checked["epoch"]),
        ("challenge", checked["challenge"]),
        ("key_id", checked["key_id"]),
        ("expires_at", checked["expires_at"]),
    ):
        if type(signed[name]) is not type(expected) or signed[name] != expected:
            raise ProtocolError(f"decision_{name}_mismatch")
    if issued_at >= checked["expires_at"]:
        raise ProtocolError("decision_time_invalid")
    raw = canonical(signed)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, raw)
    except (InvalidSignature, ValueError) as exc:
        raise ProtocolError("signature_verification_failed") from exc
    return dict(signed)
