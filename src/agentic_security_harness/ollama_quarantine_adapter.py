"""Opt-in native Ollama proposal adapter; literal loopback, pure decisions, no dispatch.

The application owns profile and request identity. The model supplies only a proposal;
neither JSON normalization nor successful transport grants authority. No service is
started, no environment/credentials are read, and raw content is never in an outcome.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import re
import socket
import time
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.quarantine_connector import ProviderAdapterProfileRegistryV1
from agentic_security_harness.quarantine_gateway_composition import (
    QuarantineGatewayCompositionV1,
    compose_quarantine_gateway_v1,
)
from agentic_security_harness.runtime_gateway import (
    SAFE_TOKEN_PATTERN,
    SHA256_PATTERN,
    GatewayPolicyV1,
)

MAX_RESPONSE_BYTES = 65_536
MAX_PROPOSAL_BYTES = 16_384
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\Z")
_METRICS = frozenset(
    {
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_cached_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    }
)
_OUTER_FIELDS = _METRICS | {
    "model",
    "response",
    "done",
    "done_reason",
    "created_at",
    "context",
    "thinking",
}
AdapterReason = Literal[
    "evaluated",
    "transport_unavailable",
    "transport_timeout",
    "http_rejected",
    "response_too_large",
    "outer_json_invalid",
    "outer_contract_invalid",
    "model_mismatch",
    "generation_incomplete",
    "proposal_json_invalid",
    "proposal_shape_invalid",
]


class OllamaQuarantineConfigV1(BaseModel):
    """One fixed local HTTP surface; no URL, proxy, auth or retry configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: int = Field(default=11434, ge=1, le=65535)
    timeout_seconds: float = Field(default=90.0, ge=0.1, le=120.0)
    max_response_bytes: int = Field(default=MAX_RESPONSE_BYTES, ge=1024, le=MAX_RESPONSE_BYTES)


class OllamaQuarantineOutcomeV1(BaseModel):
    """Content-free observation; local hashes are not authenticated custody."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal["AgenticSecurityHarnessOllamaQuarantineOutcome.v1"] = (
        "AgenticSecurityHarnessOllamaQuarantineOutcome.v1"
    )
    reason_code: AdapterReason
    model_sha256: str = Field(pattern=SHA256_PATTERN)
    transport_attempts: int = Field(default=0, ge=0, le=1)
    http_status: int | None = Field(default=None, ge=100, le=599)
    request_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    response_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    proposal_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    input_tokens: int | None = Field(default=None, ge=0, le=2**63 - 1)
    output_tokens: int | None = Field(default=None, ge=0, le=2**63 - 1)
    composition: QuarantineGatewayCompositionV1 | None = None
    operational_authority: Literal["none"] = "none"
    dispatch_performed: Literal[False] = False

    @model_validator(mode="after")
    def _coherent(self) -> OllamaQuarantineOutcomeV1:
        if (self.reason_code == "evaluated") != (self.composition is not None):
            raise ValueError("evaluation and composition must agree")
        if self.composition is not None and (
            self.composition.dispatch_performed or self.composition.operational_authority != "none"
        ):
            raise ValueError("adapter outcome cannot carry action authority")
        return self


def ollama_proposal_schema_v1(*, no_request: bool = False) -> dict[str, Any]:
    """A requested data shape, not a policy allowlist or autonomous routing decision.

    Capability and argument values are deliberately not fixed by the schema. The
    separate no-request shape makes a declared non-action observation distinguishable.
    """

    if type(no_request) is not bool:
        raise ValueError("no_request must be a bool")
    if no_request:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["no_request"],
            "properties": {"no_request": {"type": "boolean", "const": True}},
        }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["capability_id", "arguments"],
        "properties": {"capability_id": {"type": "string"}, "arguments": {"type": "object"}},
    }


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> Any:
    raise ValueError("nonfinite JSON number")


def _json(raw: bytes, limit: int) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("JSON byte limit")
    # Bound nesting before allocating recursive containers. json.loads validates syntax.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 12:
                raise ValueError("JSON depth limit")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    _json_values(value)
    return value


def _json_values(value: Any) -> None:
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("JSON object limit")
        for key, item in value.items():
            key.encode("utf-8")  # reject escaped lone surrogates
            _json_values(item)
    elif isinstance(value, list):
        if len(value) > 16384:
            raise ValueError("JSON array limit")
        for item in value:
            _json_values(item)
    elif isinstance(value, str):
        value.encode("utf-8")
    elif type(value) is float and not math.isfinite(value):
        raise ValueError("nonfinite JSON number")
    elif type(value) is int and abs(value) > 2**63 - 1:
        raise ValueError("JSON integer limit")


def _validate_caller(
    registry: ProviderAdapterProfileRegistryV1,
    policy: GatewayPolicyV1,
    profile_id: str,
    profile_version: str,
    request_id: str,
    model_id: str,
) -> None:
    if (
        type(registry) is not ProviderAdapterProfileRegistryV1
        or type(policy) is not GatewayPolicyV1
    ):
        raise ValueError("exact registry and Gateway policy types required")
    # Reject model_construct/copy bypasses before any transport.
    ProviderAdapterProfileRegistryV1.model_validate(registry.model_dump(mode="python"))
    GatewayPolicyV1.model_validate(policy.model_dump(mode="python"))
    if type(model_id) is not str or _MODEL_ID.fullmatch(model_id) is None:
        raise ValueError("invalid model identity")
    if type(request_id) is not str or re.fullmatch(SAFE_TOKEN_PATTERN, request_id) is None:
        raise ValueError("invalid application request identity")
    profile = registry.select_exact(profile_id, profile_version)
    if profile is None or profile.context_mode != "forbidden":
        raise ValueError("an explicit registered stateless profile is required")


def evaluate_ollama_generate_response_v1(
    response: bytes,
    *,
    model_id: str,
    request_id: str,
    registry: ProviderAdapterProfileRegistryV1,
    selected_profile_id: str,
    selected_profile_version: str,
    gateway_policy: GatewayPolicyV1,
    require_no_request: bool = False,
) -> OllamaQuarantineOutcomeV1:
    """Pure native-response normalization followed by the unchanged admission/decision.

    Accept JSON whitespace/key-order variation, not repairs, missing fields, markdown,
    invented requests, provider autodetection or authority-bearing envelope overrides.
    """

    _validate_caller(
        registry,
        gateway_policy,
        selected_profile_id,
        selected_profile_version,
        request_id,
        model_id,
    )
    if type(require_no_request) is not bool:
        raise ValueError("require_no_request must be a bool")
    identity: dict[str, Any] = {"model_sha256": _sha(model_id.encode())}
    if type(response) is not bytes or len(response) > MAX_RESPONSE_BYTES:
        return OllamaQuarantineOutcomeV1(**identity, reason_code="response_too_large")
    identity["response_sha256"] = _sha(response)
    try:
        body = _json(response, MAX_RESPONSE_BYTES)
    except (ValueError, UnicodeError, RecursionError):
        return OllamaQuarantineOutcomeV1(**identity, reason_code="outer_json_invalid")
    required = {"model", "response", "done", "done_reason"}
    if not required <= body.keys() or body.keys() - _OUTER_FIELDS:
        return OllamaQuarantineOutcomeV1(**identity, reason_code="outer_contract_invalid")
    if body["model"] != model_id:
        return OllamaQuarantineOutcomeV1(**identity, reason_code="model_mismatch")
    if body["done"] is not True or body["done_reason"] != "stop":
        return OllamaQuarantineOutcomeV1(**identity, reason_code="generation_incomplete")
    if (
        type(body["response"]) is not str
        or body.get("thinking", "") != ""
        or ("created_at" in body and type(body["created_at"]) is not str)
        or any(type(body[k]) is not int or body[k] < 0 for k in _METRICS & body.keys())
    ):
        return OllamaQuarantineOutcomeV1(**identity, reason_code="outer_contract_invalid")
    context = body.get("context", [])
    if type(context) is not list or any(type(x) is not int or x < 0 for x in context):
        return OllamaQuarantineOutcomeV1(**identity, reason_code="outer_contract_invalid")
    # Ollama's returned continuation token ids are explicitly unused in this stateless
    # protocol. They are never sent back as context or interpreted as instructions.
    try:
        proposal = _json(body["response"].encode("utf-8"), MAX_PROPOSAL_BYTES)
    except (ValueError, UnicodeError, RecursionError):
        return OllamaQuarantineOutcomeV1(**identity, reason_code="proposal_json_invalid")
    if set(proposal) == {"no_request"} and proposal["no_request"] is True:
        representation: dict[str, Any] = {"kind": "no_request"}
    elif (
        set(proposal) == {"capability_id", "arguments"}
        and type(proposal["capability_id"]) is str
        and type(proposal["arguments"]) is dict
    ):
        representation = {"kind": "capability_request", "request_id": request_id, **proposal}
    else:
        return OllamaQuarantineOutcomeV1(**identity, reason_code="proposal_shape_invalid")
    if require_no_request and representation["kind"] != "no_request":
        return OllamaQuarantineOutcomeV1(**identity, reason_code="proposal_shape_invalid")
    payload = _canonical(
        {
            "schema_version": "AgenticSecurityHarnessModelEnvelope.v1",
            "profile_id": selected_profile_id,
            "profile_version": selected_profile_version,
            "representation": representation,
        }
    )
    composition = compose_quarantine_gateway_v1(
        registry,
        selected_profile_id=selected_profile_id,
        selected_profile_version=selected_profile_version,
        payload=payload,
        gateway_policy=gateway_policy,
    )
    return OllamaQuarantineOutcomeV1(
        **identity,
        reason_code="evaluated",
        proposal_sha256=_sha(_canonical(proposal)),
        input_tokens=body.get("prompt_eval_count"),
        output_tokens=body.get("eval_count"),
        composition=composition,
    )


class _WireLimit(OSError):
    pass


class _DeadlineSocket(socket.socket):
    """HTTP's buffered reader still uses recv_into: enforce an absolute deadline there."""

    def __init__(self, timeout: float, limit: int) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.deadline = time.monotonic() + timeout
        self.remaining_bytes = limit
        self._remaining_time()

    def _remaining_time(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("local transport deadline")
        self.settimeout(remaining)

    def sendall(self, data: Any, flags: int = 0) -> None:
        self._remaining_time()
        super().sendall(data, flags)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self._remaining_time()
        if self.remaining_bytes <= 0:
            raise _WireLimit("local response wire limit")
        count = super().recv_into(buffer, min(nbytes or len(buffer), self.remaining_bytes), flags)
        self.remaining_bytes -= count
        return count


def _post(
    config: OllamaQuarantineConfigV1, request: bytes
) -> tuple[bytes | None, int | None, AdapterReason]:
    connection = http.client.HTTPConnection(config.host, config.port)
    sock: _DeadlineSocket | None = None
    status: int | None = None
    try:
        sock = _DeadlineSocket(config.timeout_seconds, config.max_response_bytes + 16384)
        connection.sock = sock
        sock.connect((config.host, config.port))  # literal IPv4; no DNS/proxy/redirect
        connection.request(
            "POST",
            "/api/generate",
            request,
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status = response.status
        headers = response.getheaders()
        content_types = [v.lower() for k, v in headers if k.lower() == "content-type"]
        lengths = [v for k, v in headers if k.lower() == "content-length"]
        transfers = [v.lower() for k, v in headers if k.lower() == "transfer-encoding"]
        if (
            status != 200
            or content_types not in (["application/json"], ["application/json; charset=utf-8"])
            or any(k.lower() == "content-encoding" for k, _ in headers)
            or sum(len(k) + len(v) + 4 for k, v in headers) > 16384
            or len(lengths) > 1
            or transfers not in ([], ["chunked"])
            or (lengths and transfers)
            or (lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()))
        ):
            return None, status, "http_rejected"
        if lengths and int(lengths[0]) > config.max_response_bytes:
            return None, status, "response_too_large"
        body = response.read(config.max_response_bytes + 1)
        if len(body) > config.max_response_bytes:
            return None, status, "response_too_large"
        if lengths and len(body) != int(lengths[0]):
            return None, status, "http_rejected"
        return body, status, "evaluated"
    except TimeoutError:
        return None, status, "transport_timeout"
    except _WireLimit:
        return None, status, "response_too_large"
    except (OSError, http.client.HTTPException, ValueError):
        return None, status, "transport_unavailable"
    finally:
        connection.close()
        if sock is not None:
            sock.close()


def invoke_ollama_quarantine_v1(
    config: OllamaQuarantineConfigV1,
    *,
    model_id: str,
    prompt: str,
    request_id: str,
    registry: ProviderAdapterProfileRegistryV1,
    selected_profile_id: str,
    selected_profile_version: str,
    gateway_policy: GatewayPolicyV1,
    no_request: bool = False,
) -> OllamaQuarantineOutcomeV1:
    """One operator-requested local generation, followed only by a pure decision.

    The application explicitly asks for a proposal or no-request data shape; this is
    not evidence of autonomous tool choice. Capability/argument values remain model
    supplied and must pass the unchanged Connector and Gateway. No retries or dispatch.
    """

    if type(config) is not OllamaQuarantineConfigV1:
        raise ValueError("exact Ollama config type required")
    config = OllamaQuarantineConfigV1.model_validate(config.model_dump(mode="python"))
    _validate_caller(
        registry,
        gateway_policy,
        selected_profile_id,
        selected_profile_version,
        request_id,
        model_id,
    )
    if type(prompt) is not str or not 0 < len(prompt.encode("utf-8")) <= 8192:
        raise ValueError("bounded nonempty public input required")
    schema = ollama_proposal_schema_v1(no_request=no_request)
    request = _canonical(
        {
            "model": model_id,
            "prompt": prompt,
            "format": schema,
            "stream": False,
            "options": {"temperature": 0, "seed": 42, "num_predict": 256, "num_ctx": 2048},
            "keep_alive": "1m",
        }
    )
    body, status, reason = _post(config, request)
    if body is None:
        return OllamaQuarantineOutcomeV1(
            reason_code=reason,
            model_sha256=_sha(model_id.encode()),
            transport_attempts=1,
            http_status=status,
            request_sha256=_sha(request),
        )
    result = evaluate_ollama_generate_response_v1(
        body,
        model_id=model_id,
        request_id=request_id,
        registry=registry,
        selected_profile_id=selected_profile_id,
        selected_profile_version=selected_profile_version,
        gateway_policy=gateway_policy,
        require_no_request=no_request,
    )
    return OllamaQuarantineOutcomeV1.model_validate(
        {
            **result.model_dump(mode="python"),
            "transport_attempts": 1,
            "http_status": status,
            "request_sha256": _sha(request),
        }
    )
