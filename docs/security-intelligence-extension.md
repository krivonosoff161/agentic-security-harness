# Security Intelligence extension V1

Status: published in the `v1.3.0` Harness core. It remains an offline review contract and
does not fetch sources, invoke a model, publish a companion, or grant operational authority.

The Security Intelligence slice turns the ecosystem roadmap's weekly threat-watch item
into an executable **offline review contract**. It accepts normalized metadata snapshots
that an operator or a future acquisition layer produced from public sources. The Harness
does not fetch those sources, invoke a model, or retain article bodies.

## What is implemented

- a content-bound registry of declared public source origins;
- digest-only evidence records bound to complete canonical observation bytes;
- one ordered weekly-window bundle with exact source coverage accounting;
- a provider-neutral Russian or English synthesis profile with separate facts,
  inferences, hypotheses, coverage gaps, and at most five safe follow-up tasks;
- an explicit `SecurityIntelligenceReviewExtensionV1` registered through Extension SDK
  V1;
- generated closed-shape JSON Schemas and a content-bound contract manifest;
- deterministic synthetic tests on Linux and Windows.

The default registry names CISA, GitHub Security, MITRE ATLAS, NIST, OpenAI Security, and
OWASP GenAI origins. These entries are bounded source identities, not claims of current
availability, exhaustive coverage, or endorsement. The registry performs no DNS or
network access.

## Evidence and authority boundary

Deterministic processing does not upgrade external claims into deterministic evidence.
Every result from this extension uses `evidence_class=external_unreviewed`. Collected
primary-source metadata may produce a low-severity `review_candidate`; secondary-source
or model-proposed content remains `inconclusive`. A missing or quiet source never becomes
`pass`.

The core contract stores only identifiers, timestamps, classifications, and SHA-256
commitments. Raw titles, article bodies, prompts, model responses, credentials, cookies,
headers, machine paths, and unrestricted URLs have no field in the wire models.

`operational_authority` is always `none`. Findings cannot open issues, change the corpus,
rewrite standards mappings, modify policy, dismiss alerts, block or allow an action, or
trigger deployment.

## Provider and model neutrality

The synthesis profile fixes the output sections and evidence taxonomy, not a vendor. A
future operator may use a local model, an external model, several models, or deterministic
templates outside the core. Their statements remain proposals until separately reviewed;
multiple correlated models or syndicated articles do not count as independent evidence.

## Explicitly not implemented

- live RSS, Atom, browser, GitHub, NVD, OSV, social, or vendor API fetching;
- credentials, authenticated feeds, paid calls, or private sources;
- raw-content storage, summarization, or public rendering;
- automatic tasks, notifications, issues, pull requests, policy changes, or enforcement;
- real-time monitoring, independent verification, CVE validation, or exhaustive coverage.

Those capabilities require separate source-acquisition, privacy, copyright, freshness,
rate-limit, secret, and owner-authority gates. The V1 offline contracts are designed so a
future collector can be added without changing the evidence or Extension SDK boundary.
