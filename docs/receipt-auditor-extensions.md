# Router and Cheap Filter receipt auditors

Status: source-level review candidate stacked on the unreleased Security Intelligence
extension. It is not present in the published `v1.2.0` package.

Harness owns two deterministic Extension SDK auditors for canonical accounting receipts
produced by exact public companion revisions:

- `llm-router` invocation receipt V1;
- `llm-cheap-filter` triage batch receipt V1.

The companion projects own their receipt codecs. Harness owns a separate semantic audit
implementation and consumes only caller-supplied canonical receipt bytes plus canonical
portfolio observations. Production Harness code does not import or invoke either package,
discover installed extensions, open the network, start subprocesses, or execute injected
model callables.

## What the audit establishes

For every supplied receipt, the auditor independently checks:

- closed canonical UTF-8 JSON and duplicate/unknown field rejection;
- receipt content identity and exact producer contract pin;
- complete ordered attempt or input/result accounting;
- terminal state, token, summary, fixed-point price, and FX consistency where present;
- receipt replay across event bindings;
- exact event repository commit, activity, artifact, byte digest, receipt id, and producer
  or timestamp binding when the source contract exposes those fields;
- fixed `operational_authority=none` and filter
  `may_lower_security_decision=false` semantics.

The audit does not verify raw prompts, hidden decisions, model output, source authenticity,
provider identity, invoice truth, safety, effectiveness, or whether a producer honestly
reported the observed values. Digest bindings are content-minimizing, not anonymizing or
automatically public-safe.

## Outcome semantics

The adapters deliberately never emit `pass`:

| Condition | Extension outcome |
|---|---|
| canonical accounting and exact event binding | `inconclusive` — accounting is bound, no security verdict |
| missing receipt evidence or incomplete telemetry | `inconclusive` |
| malformed receipt, accounting drift, replay, or event-binding drift | `finding` |

Source, activity, repository, byte-envelope, and artifact-locator linkage is checked
before malformed receipt classification. Receipt-id, producer, and timestamp linkage is
then checked only when semantic decoding made those producer fields available; malformed
bytes cannot claim a validated semantic identity.

No result authorizes a provider call, lowers a guard decision, authenticates a producer,
or changes an allow/deny decision. Extension manifests keep evidence provenance at
`producer_declared` or `external_unreviewed` and operational authority at `none`.

## Exact source boundary

[`schemas/receipt-auditors.v1.manifest.json`](../schemas/receipt-auditors.v1.manifest.json)
binds each reviewed source commit and tree, canonical component manifest, receipt schema,
source semantic implementation, optional producer contract manifest, Harness implementation,
tests, workflow, and documentation.

Text artifacts use LF-normalized SHA-256. Component manifests use canonical JSON plus one
terminal LF. Linux and Windows CI check the actual pinned producer repositories and build
synthetic receipts with their source-owned codecs before crossing the Harness byte boundary.

The JSON Schemas are closed shape contracts for Harness pins and bindings. The Python
auditor remains authoritative for canonical bytes, state machines, arithmetic, replay, and
event linkage.

## Privacy and retention

Receipt bytes remain caller-owned in-memory inputs. Harness bindings and findings emit only
digests, fixed reason codes, source pins, evidence class, and authority-free dispositions.
The auditors do not write raw receipt bytes. Operators must still keep receipts derived from
private prompts, models, incidents, or customer data under their own access and retention
policy.

## Verification

```bash
python tools/receipt_auditor_contracts.py check
python -m pytest -q tests/test_receipt_auditors.py
```

The exact cross-repository test additionally requires CI-owned clean checkouts at the
manifest-pinned revisions. Passing these synthetic checks demonstrates contract
compatibility only, not independent security effectiveness or production readiness.
