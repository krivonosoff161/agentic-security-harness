"""Provider-neutral offline Security Intelligence contracts and review extension.

The module reviews operator-supplied public-source metadata snapshots.  It never fetches
URLs, invokes a model, imports provider SDKs, stores source bodies, or grants operational
authority.  Deterministic processing remains distinct from the external, unreviewed
provenance of the underlying publication claims.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentic_security_harness.extension_sdk import (
    EXTENSION_MANIFEST_V1,
    ExtensionContractRefV1,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
)
from agentic_security_harness.portfolio_contract import (
    SHA256_PATTERN,
    encode_portfolio_observation_v1,
)

SECURITY_INTELLIGENCE_SOURCE_REGISTRY_V1: Final = (
    "harness-security-intelligence-source-registry-v1.0"
)
SECURITY_INTELLIGENCE_EVIDENCE_V1: Final = (
    "harness-security-intelligence-evidence-v1.0"
)
SECURITY_INTELLIGENCE_BUNDLE_V1: Final = (
    "harness-security-intelligence-bundle-v1.0"
)
SECURITY_INTELLIGENCE_SYNTHESIS_PROFILE_V1: Final = (
    "harness-security-intelligence-synthesis-profile-v1.0"
)
MAX_SECURITY_INTELLIGENCE_SOURCES: Final = 64
MAX_SECURITY_INTELLIGENCE_ITEMS: Final = 512
_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_PUBLIC_HOST_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

SecuritySourceKind = Literal[
    "standards_body",
    "government_advisory",
    "upstream_project",
    "vendor_advisory",
    "incident_owner_statement",
    "peer_reviewed_primary_research",
    "secondary_discovery",
]
SecurityTopic = Literal[
    "agentic_ai",
    "llm_security",
    "mcp",
    "prompt_injection",
    "runtime_boundary",
    "software_supply_chain",
    "standards",
    "vulnerability_advisory",
]
SecurityClaimClass = Literal[
    "observed_publication",
    "source_assertion",
    "calculation",
    "inference",
    "hypothesis",
    "model_proposal",
]
SecurityCollectionState = Literal[
    "collected",
    "no_update",
    "unavailable",
    "malformed",
    "out_of_window",
]


class SecurityIntelligenceContractError(ValueError):
    """Raised when offline security-intelligence metadata violates V1."""


class SecurityIntelligenceSourceV1(BaseModel):
    """One public source identity; this is metadata, not a network instruction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_kind: SecuritySourceKind
    canonical_https_origin: str = Field(min_length=9, max_length=512)
    topics: tuple[SecurityTopic, ...] = Field(min_length=1, max_length=16)
    collection_mode: Literal["offline_snapshot_only"]
    metadata_policy: Literal["public_metadata_and_digests_only"]
    credentials_required: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_source(self) -> SecurityIntelligenceSourceV1:
        _require_public_https_origin(self.canonical_https_origin)
        if self.topics != tuple(sorted(self.topics)):
            raise ValueError("source topics must be canonical sorted tokens")
        if len(self.topics) != len(set(self.topics)):
            raise ValueError("source topics must be unique")
        return self


class SecurityIntelligenceSourceRegistryV1(BaseModel):
    """Content-bound allowlist for offline public-source metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-security-intelligence-source-registry-v1.0"]
    registry_id: str = Field(pattern=SHA256_PATTERN)
    sources: tuple[SecurityIntelligenceSourceV1, ...] = Field(
        min_length=1, max_length=MAX_SECURITY_INTELLIGENCE_SOURCES
    )
    source_policy: Literal[
        "public_primary_sources_preferred_secondary_discovery_not_evidence"
    ]
    network_mode: Literal["off"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_registry(self) -> SecurityIntelligenceSourceRegistryV1:
        source_ids = tuple(item.source_id for item in self.sources)
        if source_ids != tuple(sorted(source_ids)):
            raise ValueError("security source registry must be sorted by source_id")
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("security source ids must be unique")
        if self.registry_id != _model_identity(
            "agentic-security-harness/security-intelligence-source-registry/v1.0",
            self,
            "registry_id",
        ):
            raise ValueError("registry_id does not bind the source registry")
        return self


class SecurityIntelligenceEvidenceV1(BaseModel):
    """Digest-only public-source observation bound to one canonical event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-security-intelligence-evidence-v1.0"]
    item_id: str = Field(pattern=SHA256_PATTERN)
    event_id: str = Field(pattern=SHA256_PATTERN)
    source_observation_sha256: str = Field(pattern=SHA256_PATTERN)
    registry_sha256: str = Field(pattern=SHA256_PATTERN)
    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    locator_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    content_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    published_at: datetime | None
    observed_at: datetime
    window_start: datetime
    window_end: datetime
    claim_class: SecurityClaimClass | None
    claim_group_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    summary_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    collection_state: SecurityCollectionState
    raw_content_retained: Literal[False]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_evidence(self) -> SecurityIntelligenceEvidenceV1:
        times = (self.observed_at, self.window_start, self.window_end)
        if any(item.tzinfo is None or item.utcoffset() != UTC.utcoffset(item) for item in times):
            raise ValueError("security-intelligence times must be canonical UTC")
        if self.window_start >= self.window_end:
            raise ValueError("security-intelligence window must be non-empty")
        if self.window_end - self.window_start != timedelta(days=7):
            raise ValueError("security-intelligence V1 requires an exact seven-day window")
        if self.published_at is not None and (
            self.published_at.tzinfo is None
            or self.published_at.utcoffset() != UTC.utcoffset(self.published_at)
        ):
            raise ValueError("published_at must be canonical UTC")
        detail_fields = (
            self.locator_sha256,
            self.content_sha256,
            self.published_at,
            self.claim_class,
            self.claim_group_sha256,
            self.summary_sha256,
        )
        if self.collection_state == "collected":
            if any(item is None for item in detail_fields):
                raise ValueError("collected evidence requires every digest and claim field")
            published_at = self.published_at
            if published_at is None:
                raise ValueError("collected evidence requires published_at")
            if not self.window_start <= published_at < self.window_end:
                raise ValueError("collected publication is outside the declared window")
            if published_at > self.observed_at:
                raise ValueError("publication cannot be observed before it is published")
        elif any(item is not None for item in detail_fields):
            raise ValueError("non-collected states cannot retain publication detail fields")
        if self.observed_at != self.window_end:
            raise ValueError("offline weekly evidence must be observed at window_end")
        if self.item_id != _model_identity(
            "agentic-security-harness/security-intelligence-evidence/v1.0",
            self,
            "item_id",
        ):
            raise ValueError("item_id does not bind security-intelligence evidence")
        return self


class SecurityIntelligenceBundleV1(BaseModel):
    """Closed ordered batch for one declared weekly review window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-security-intelligence-bundle-v1.0"]
    bundle_id: str = Field(pattern=SHA256_PATTERN)
    registry_sha256: str = Field(pattern=SHA256_PATTERN)
    window_start: datetime
    window_end: datetime
    items: tuple[SecurityIntelligenceEvidenceV1, ...] = Field(
        min_length=1, max_length=MAX_SECURITY_INTELLIGENCE_ITEMS
    )
    collection_status: Literal["complete_for_declared_sources", "partial", "failed"]
    missing_source_ids: tuple[str, ...] = Field(max_length=MAX_SECURITY_INTELLIGENCE_SOURCES)
    raw_content_retained: Literal[False]
    source_authenticity: Literal["external_unreviewed"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_bundle(self) -> SecurityIntelligenceBundleV1:
        if (
            self.window_start.tzinfo is None
            or self.window_end.tzinfo is None
            or self.window_start.utcoffset() != UTC.utcoffset(self.window_start)
            or self.window_end.utcoffset() != UTC.utcoffset(self.window_end)
            or self.window_start >= self.window_end
        ):
            raise ValueError("bundle window must be non-empty canonical UTC")
        if self.window_end - self.window_start != timedelta(days=7):
            raise ValueError("security-intelligence V1 requires an exact seven-day window")
        item_ids = tuple(item.item_id for item in self.items)
        event_ids = tuple(item.event_id for item in self.items)
        if len(item_ids) != len(set(item_ids)) or len(event_ids) != len(set(event_ids)):
            raise ValueError("bundle item and event ids must be unique")
        collected = tuple(
            item for item in self.items if item.collection_state == "collected"
        )
        locators = tuple(item.locator_sha256 for item in collected)
        source_contents = tuple(
            (item.source_id, item.content_sha256) for item in collected
        )
        if len(locators) != len(set(locators)):
            raise ValueError("collected source locators cannot be replayed")
        if len(source_contents) != len(set(source_contents)):
            raise ValueError("collected source content cannot be replayed per source")
        by_source: dict[str, list[SecurityIntelligenceEvidenceV1]] = {}
        for item in self.items:
            by_source.setdefault(item.source_id, []).append(item)
        if any(
            len(source_items) > 1
            and any(item.collection_state != "collected" for item in source_items)
            for source_items in by_source.values()
        ):
            raise ValueError(
                "non-collected source state cannot coexist with another source item"
            )
        ordered = tuple(
            sorted(self.items, key=lambda item: (item.source_id, item.observed_at, item.item_id))
        )
        if self.items != ordered:
            raise ValueError("bundle items must use canonical source/time/id ordering")
        if any(
            item.registry_sha256 != self.registry_sha256
            or item.window_start != self.window_start
            or item.window_end != self.window_end
            for item in self.items
        ):
            raise ValueError("bundle item registry or window drift")
        if self.missing_source_ids != tuple(sorted(self.missing_source_ids)):
            raise ValueError("missing source ids must be canonical sorted tokens")
        if len(self.missing_source_ids) != len(set(self.missing_source_ids)):
            raise ValueError("missing source ids must be unique")
        if self.collection_status == "complete_for_declared_sources" and self.missing_source_ids:
            raise ValueError("complete collection cannot declare missing sources")
        if self.collection_status == "failed" and any(
            item.collection_state == "collected" for item in self.items
        ):
            raise ValueError("failed collection cannot contain collected evidence")
        if self.bundle_id != _model_identity(
            "agentic-security-harness/security-intelligence-bundle/v1.0",
            self,
            "bundle_id",
        ):
            raise ValueError("bundle_id does not bind security-intelligence items")
        return self


class SecurityIntelligenceSynthesisProfileV1(BaseModel):
    """Provider-neutral shape for optional synthesis outside the core extension."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["harness-security-intelligence-synthesis-profile-v1.0"]
    profile_id: str = Field(pattern=SHA256_PATTERN)
    language: Literal["en", "ru"]
    sections: tuple[
        Literal[
            "verified_facts",
            "inferences",
            "hypotheses",
            "coverage_gaps",
            "safe_follow_up_tasks",
        ],
        ...,
    ]
    max_follow_up_tasks: Literal[5]
    model_interface: Literal["provider_neutral_optional"]
    model_execution: Literal["outside_core_not_invoked"]
    output_retention: Literal["statement_digests_only_in_core"]
    independence: Literal["not_claimed"]
    operational_authority: Literal["none"]

    @model_validator(mode="after")
    def _validate_profile(self) -> SecurityIntelligenceSynthesisProfileV1:
        expected = (
            "verified_facts",
            "inferences",
            "hypotheses",
            "coverage_gaps",
            "safe_follow_up_tasks",
        )
        if self.sections != expected:
            raise ValueError("synthesis sections must use the exact V1 order")
        if self.profile_id != _model_identity(
            "agentic-security-harness/security-intelligence-synthesis-profile/v1.0",
            self,
            "profile_id",
        ):
            raise ValueError("profile_id does not bind the synthesis profile")
        return self


class SecurityIntelligenceReviewExtensionV1:
    """Explicit deterministic reviewer over an already normalized offline batch."""

    def __init__(
        self,
        *,
        registry: SecurityIntelligenceSourceRegistryV1,
        bundle: SecurityIntelligenceBundleV1,
        profile: SecurityIntelligenceSynthesisProfileV1,
    ) -> None:
        self.registry = SecurityIntelligenceSourceRegistryV1.model_validate(
            registry.model_dump(mode="python")
        )
        self.bundle = SecurityIntelligenceBundleV1.model_validate(
            bundle.model_dump(mode="python")
        )
        self.profile = SecurityIntelligenceSynthesisProfileV1.model_validate(
            profile.model_dump(mode="python")
        )
        _require_bundle_registry(self.registry, self.bundle)
        self._items = {item.event_id: item for item in self.bundle.items}
        self.manifest = ExtensionManifestV1(
            schema_version=EXTENSION_MANIFEST_V1,
            extension_id="security-intelligence.offline-review-v1",
            extension_version="1.0.0",
            component_id="agentic-security-harness",
            implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            configuration_sha256=_configuration_sha256(
                self.registry, self.bundle, self.profile
            ),
            harness_api="1",
            kind="check_extension",
            capabilities=(
                "observation.read",
                "finding.emit",
                "intelligence.review",
            ),
            consumes=(
                ExtensionContractRefV1(
                    contract_id="portfolio-observation", version="1.0", required=True
                ),
                ExtensionContractRefV1(
                    contract_id="security-intelligence-evidence",
                    version="1.0",
                    required=True,
                ),
            ),
            produces=(
                ExtensionContractRefV1(
                    contract_id="extension-finding", version="1.0", required=True
                ),
            ),
            deterministic=True,
            evidence_provenance="external_unreviewed",
            network_mode="off",
            raw_data_policy="digests_only",
            execution_model="in_process_operator_approved_not_sandboxed",
            operational_authority="none",
        )

    def evaluate(
        self, envelope: ExtensionObservationEnvelopeV1
    ) -> tuple[ExtensionFindingV1, ...]:
        if self.manifest.configuration_sha256 != _configuration_sha256(
            self.registry, self.bundle, self.profile
        ):
            raise SecurityIntelligenceContractError("security-intelligence configuration drift")
        if {event.event_id for event in envelope.events} != set(self._items):
            raise SecurityIntelligenceContractError(
                "security-intelligence evidence must exactly cover the input events"
            )
        source_kinds = {item.source_id: item.source_kind for item in self.registry.sources}
        findings: list[ExtensionFindingV1] = []
        for event in envelope.events:
            item = self._items[event.event_id]
            observation_sha256 = hashlib.sha256(
                encode_portfolio_observation_v1(event)
            ).hexdigest()
            if item.source_observation_sha256 != observation_sha256:
                raise SecurityIntelligenceContractError(
                    "security-intelligence evidence does not bind the canonical observation"
                )
            if (
                event.source_surface != "document"
                or event.activity != "security_intelligence.publication_observed"
                or event.authority_envelope_ref is not None
                or event.telemetry_state != "unattested"
                or item.observed_at != event.occurred_at
                or (
                    item.collection_state == "collected"
                    and item.content_sha256 != event.data_envelope_ref
                )
            ):
                raise SecurityIntelligenceContractError(
                    "security-intelligence evidence and observation semantics differ"
                )
            outcome: Literal["finding", "inconclusive"] = "inconclusive"
            severity: Literal["none", "low"] = "none"
            reason_code = _collection_reason(item.collection_state)
            if item.collection_state == "collected":
                if item.claim_class == "model_proposal":
                    reason_code = "intelligence.model_proposal_unverified"
                elif source_kinds[item.source_id] == "secondary_discovery":
                    reason_code = "intelligence.secondary_source_discovery"
                elif item.claim_class in ("observed_publication", "source_assertion"):
                    outcome = "finding"
                    severity = "low"
                    reason_code = "intelligence.review_candidate"
                elif item.claim_class in ("calculation", "inference", "hypothesis"):
                    reason_code = {
                        "calculation": "intelligence.calculation_unreviewed",
                        "inference": "intelligence.inference_unreviewed",
                        "hypothesis": "intelligence.hypothesis_unreviewed",
                    }[item.claim_class]
                else:
                    raise SecurityIntelligenceContractError(
                        "collected security-intelligence claim class is invalid"
                    )
            findings.append(
                ExtensionFindingV1(
                    check_id=f"security-intelligence.review.{item.item_id}",
                    outcome=outcome,
                    severity=severity,
                    reason_code=reason_code,
                    evidence_event_ids=(event.event_id,),
                )
            )
        return tuple(findings)


def build_security_intelligence_source_registry_v1(
    sources: tuple[SecurityIntelligenceSourceV1, ...],
) -> SecurityIntelligenceSourceRegistryV1:
    provisional = SecurityIntelligenceSourceRegistryV1.model_construct(
        schema_version=SECURITY_INTELLIGENCE_SOURCE_REGISTRY_V1,
        registry_id="0" * 64,
        sources=sources,
        source_policy=(
            "public_primary_sources_preferred_secondary_discovery_not_evidence"
        ),
        network_mode="off",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["registry_id"] = _model_identity(
        "agentic-security-harness/security-intelligence-source-registry/v1.0",
        provisional,
        "registry_id",
    )
    return SecurityIntelligenceSourceRegistryV1.model_validate(payload)


def default_security_intelligence_source_registry_v1(
) -> SecurityIntelligenceSourceRegistryV1:
    """Return the bounded public-primary-source registry for the V1 offline fixture.

    Origins are identities only.  This function performs no DNS or network access and
    does not claim exhaustive ecosystem coverage or current source availability.
    """

    rows: tuple[tuple[str, SecuritySourceKind, str, tuple[SecurityTopic, ...]], ...] = (
        ("cisa-advisories", "government_advisory", "https://cisa.gov", (
            "software_supply_chain",
            "vulnerability_advisory",
        )),
        ("github-security", "upstream_project", "https://github.com", (
            "software_supply_chain",
            "vulnerability_advisory",
        )),
        ("mitre-atlas", "standards_body", "https://mitre.org", (
            "agentic_ai",
            "llm_security",
            "standards",
        )),
        ("nist-ai", "government_advisory", "https://nist.gov", (
            "agentic_ai",
            "llm_security",
            "standards",
        )),
        ("openai-security", "vendor_advisory", "https://openai.com", (
            "agentic_ai",
            "llm_security",
            "prompt_injection",
        )),
        ("owasp-genai", "standards_body", "https://owasp.org", (
            "agentic_ai",
            "llm_security",
            "mcp",
            "prompt_injection",
            "runtime_boundary",
            "standards",
        )),
    )
    return build_security_intelligence_source_registry_v1(
        tuple(
            SecurityIntelligenceSourceV1(
                source_id=source_id,
                source_kind=source_kind,
                canonical_https_origin=origin,
                topics=topics,
                collection_mode="offline_snapshot_only",
                metadata_policy="public_metadata_and_digests_only",
                credentials_required=False,
                operational_authority="none",
            )
            for source_id, source_kind, origin, topics in rows
        )
    )


def build_security_intelligence_evidence_v1(
    **values: Any,
) -> SecurityIntelligenceEvidenceV1:
    provisional = SecurityIntelligenceEvidenceV1.model_construct(
        schema_version=SECURITY_INTELLIGENCE_EVIDENCE_V1,
        item_id="0" * 64,
        raw_content_retained=False,
        operational_authority="none",
        **values,
    )
    payload = provisional.model_dump(mode="python")
    payload["item_id"] = _model_identity(
        "agentic-security-harness/security-intelligence-evidence/v1.0",
        provisional,
        "item_id",
    )
    return SecurityIntelligenceEvidenceV1.model_validate(payload)


def build_security_intelligence_bundle_v1(
    *,
    registry: SecurityIntelligenceSourceRegistryV1,
    window_start: datetime,
    window_end: datetime,
    items: tuple[SecurityIntelligenceEvidenceV1, ...],
    collection_status: Literal["complete_for_declared_sources", "partial", "failed"],
    missing_source_ids: tuple[str, ...] = (),
) -> SecurityIntelligenceBundleV1:
    provisional = SecurityIntelligenceBundleV1.model_construct(
        schema_version=SECURITY_INTELLIGENCE_BUNDLE_V1,
        bundle_id="0" * 64,
        registry_sha256=security_intelligence_source_registry_sha256(registry),
        window_start=window_start,
        window_end=window_end,
        items=items,
        collection_status=collection_status,
        missing_source_ids=missing_source_ids,
        raw_content_retained=False,
        source_authenticity="external_unreviewed",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["bundle_id"] = _model_identity(
        "agentic-security-harness/security-intelligence-bundle/v1.0",
        provisional,
        "bundle_id",
    )
    bundle = SecurityIntelligenceBundleV1.model_validate(payload)
    _require_bundle_registry(registry, bundle)
    return bundle


def build_security_intelligence_synthesis_profile_v1(
    *, language: Literal["en", "ru"] = "ru"
) -> SecurityIntelligenceSynthesisProfileV1:
    provisional = SecurityIntelligenceSynthesisProfileV1.model_construct(
        schema_version=SECURITY_INTELLIGENCE_SYNTHESIS_PROFILE_V1,
        profile_id="0" * 64,
        language=language,
        sections=(
            "verified_facts",
            "inferences",
            "hypotheses",
            "coverage_gaps",
            "safe_follow_up_tasks",
        ),
        max_follow_up_tasks=5,
        model_interface="provider_neutral_optional",
        model_execution="outside_core_not_invoked",
        output_retention="statement_digests_only_in_core",
        independence="not_claimed",
        operational_authority="none",
    )
    payload = provisional.model_dump(mode="python")
    payload["profile_id"] = _model_identity(
        "agentic-security-harness/security-intelligence-synthesis-profile/v1.0",
        provisional,
        "profile_id",
    )
    return SecurityIntelligenceSynthesisProfileV1.model_validate(payload)


def encode_security_intelligence_contract_v1(model: BaseModel) -> bytes:
    return _canonical_bytes(model.model_dump(mode="json"))


def security_intelligence_source_registry_sha256(
    registry: SecurityIntelligenceSourceRegistryV1,
) -> str:
    return hashlib.sha256(encode_security_intelligence_contract_v1(registry)).hexdigest()


def security_intelligence_v1_json_schemas() -> dict[str, dict[str, Any]]:
    models: dict[str, type[BaseModel]] = {
        "security-intelligence-source-registry.v1.schema.json": (
            SecurityIntelligenceSourceRegistryV1
        ),
        "security-intelligence-evidence.v1.schema.json": SecurityIntelligenceEvidenceV1,
        "security-intelligence-bundle.v1.schema.json": SecurityIntelligenceBundleV1,
        "security-intelligence-synthesis-profile.v1.schema.json": (
            SecurityIntelligenceSynthesisProfileV1
        ),
    }
    return {name: model.model_json_schema() for name, model in models.items()}


def _require_bundle_registry(
    registry: SecurityIntelligenceSourceRegistryV1,
    bundle: SecurityIntelligenceBundleV1,
) -> None:
    if bundle.registry_sha256 != security_intelligence_source_registry_sha256(registry):
        raise SecurityIntelligenceContractError("bundle source registry digest drift")
    source_ids = {item.source_id for item in registry.sources}
    observed = {item.source_id for item in bundle.items}
    missing = set(bundle.missing_source_ids)
    if observed & missing:
        raise SecurityIntelligenceContractError(
            "a security source cannot be both observed and missing"
        )
    if observed | missing != source_ids:
        raise SecurityIntelligenceContractError(
            "bundle coverage must exactly account for the source registry"
        )


def _require_public_https_origin(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("security source must be one canonical public HTTPS origin")
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".local"):
        raise ValueError("local security sources are outside the public registry")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not _PUBLIC_HOST_PATTERN.fullmatch(host):
            raise ValueError("security source host is not canonical public DNS") from None
    else:
        if not address.is_global:
            raise ValueError("non-public IP sources are outside the registry")
        raise ValueError("literal IP origins are not canonical source identities")
    if value != f"https://{host}":
        raise ValueError("security source origin must be lowercase and path-free")


def _configuration_sha256(
    registry: SecurityIntelligenceSourceRegistryV1,
    bundle: SecurityIntelligenceBundleV1,
    profile: SecurityIntelligenceSynthesisProfileV1,
) -> str:
    return _domain_object_digest(
        "agentic-security-harness/security-intelligence-configuration/v1.0",
        {
            "registry": registry.model_dump(mode="json"),
            "bundle": bundle.model_dump(mode="json"),
            "profile": profile.model_dump(mode="json"),
        },
    )


def _collection_reason(state: SecurityCollectionState) -> str:
    return {
        "collected": "intelligence.review_candidate",
        "no_update": "intelligence.no_update_observed",
        "unavailable": "intelligence.source_unavailable",
        "malformed": "intelligence.source_malformed",
        "out_of_window": "intelligence.out_of_window",
    }[state]


def _model_identity(domain: str, model: BaseModel, identity_field: str) -> str:
    payload = model.model_dump(mode="json")
    payload.pop(identity_field, None)
    return _domain_object_digest(domain, payload)


def _domain_object_digest(domain: str, payload: object) -> str:
    return hashlib.sha256(domain.encode("utf-8") + b"\0" + _canonical_bytes(payload)).hexdigest()


def _canonical_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
