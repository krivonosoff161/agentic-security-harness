# Runtime Guard product foundation

> Status: executable specification under review; not a production gateway.
>
> Reviewed: 2026-07-26.

## Product thesis

Prompt filters inspect text. A Runtime Guard must decide whether a proposed agent action
is authorized before an effect occurs, while retaining enough evidence to audit the
decision without retaining the conversation.

The proposed product is a vendor-neutral authorization and evidence boundary:

```text
untrusted agent proposal
  -> metadata-only ActionEnvelope
  -> deterministic policy decision point
  -> allow | redact | block | ask_user | sandbox_only | log_only
  -> isolated executor in a separate trust domain
  -> hash-bound execution outcome receipt (future component)
```

The current repository implements only the metadata contracts and a pure deterministic
evaluator in `runtime_guard_foundation.py`. It does not ship a proxy, server, executor,
credential broker, durable ledger, IAM integration, deployment, or production policy
engine.

## Why this is different

Current standards and vendor products cover useful parts of the problem: prompt and
response inspection, tool-call risk signals, agent identity, OAuth transport,
sandboxing, and audit. The open gap is one portable chain that binds:

1. human sponsor and current task authority;
2. exact action, destination, purpose, data policy, time, and budget;
3. a least-privilege capability plus separately verified handoff lineage;
4. action-specific consent for protected effects;
5. current provider terms, privacy, license, and publication policy;
6. an atomic cost/request reservation;
7. a privacy-safe evidence receipt.

This is a product hypothesis, not a market-exclusivity claim.

## Foundation objects

| Object | Purpose | Important non-claim |
|---|---|---|
| `RuntimeDataEnvelope` | Reuses the shipped `DataEnvelope` fields and binds classification to content, policy, time, receipt, and classifier trust root. | A label or known root name is not authentication; the canonical digest of every assertion must also exist in trusted `GuardContext`. |
| `ActionEnvelope` | Canonical metadata and hashes for one proposed effect. | It contains no raw prompt, model response, tool output, secret, or employee conversation. |
| `CapabilityGrant` | Binds one exact action digest plus subject, scope, target, purpose, time, delegation depth, policy, nonce, and trust-root reference. | `verification="verified"` is accepted only from code-owned `GuardContext`; atomic consumption still belongs to a future authority service. |
| `ConsentReceipt` | Binds approval to the full canonical action digest and active policy. | Conversation text cannot become consent. |
| `HandoffEvidenceBinding` | Hash-binds payload, receiver, expiry, policy, and the existing handoff evidence. | A canonical digest of the complete binding must exist in trusted context; this evaluator still does not derive parent-child non-expansion. |
| `ProviderPolicy` | Binds an exact invocation route, destination, model, terms/AUP/privacy/model license, review window, retention/training/output/publication status, region, and caps. | It is a time-bounded review record, not legal advice. |
| `BudgetReservation` | Requires an action/provider/request/conservative maximum RUB cost, fresh pricing/FX evidence, rounding rule, and safety margin before an external call can be allowed. | Atomic compare-and-swap and post-call settlement belong to the future budget service. |
| `EvidenceReceipt` | Is a decision-only receipt binding action, policy, full decision context, previous hash, and safe hashes. | It is not an execution outcome, signature, trusted time, or production tamper evidence. |

The shipped synthetic `CapabilityToken` can be converted only into an **unverified**
draft `CapabilityGrant`. The conversion deliberately cannot promote a toy token into
authority.

## Canonical decisions

Track B uses these six dispositions:

- `allow`: deterministic metadata checks are satisfied;
- `redact`: produce a new sanitized projection with a new hash, then evaluate again;
- `block`: a hard invariant failed;
- `ask_user`: fresh action-bound consent or a separate owner gate is required;
- `sandbox_only`: a directive to a future executor, not permission or proof of
  isolation; that executor must verify sandbox identity, filesystem/egress policy, and
  return an execution receipt;
- `log_only`: observe without creating operational authority.

Every cloud model query is an egress effect and requires fresh action-bound consent in
addition to capability, route/model/provider policy, data, and budget checks.

Older `ALLOW/WARN/REDACT/QUARANTINE/BLOCK` gateway sketches in `architecture.md` and
`api-reference.md` are legacy design material. `WARN` maps to `ask_user` or `log_only`
depending on effect; `QUARANTINE` maps to `sandbox_only` or `block`. The six Track B
dispositions are canonical for new work.

## Provider and model fleet roles

Models are advisory sensors. They never issue capabilities, consent, budget
reservations, policy verdicts, or owner authority.

| Route | Allowed foundation role | Current gate |
|---|---|---|
| Local Prometheus | Bounded adversarial phrasing and classifier proposals over synthetic fixtures. | Local-only, hardware cap, no 24/7 polling. |
| Local MiMo | Mathematical counterexample and invariant review. | Backend/runtime identity must be verified before evidence use. |
| Alibaba Model Studio | Optional second opinions over self-created synthetic, public-domain, or otherwise rights-cleared material. | Current original-publisher model license, Alibaba terms, competitive-product restriction, region, protected credential injection, and budget reservation required. |
| Yandex AI Studio | Optional Russian-language review over rights-cleared synthetic tasks. | The exact invocation route must prove its logging control. `dataLoggingEnabled=false` is documented for `FoundationModelsCall` only; an account-level opt-out is not effective until 24 hours after the documented action. |
| GigaChat | None in this cycle. | Hold until the commercial-use and result-publication terms are confirmed for the active tariff. |

No cloud call was needed to implement or verify this foundation. Cycle usage remains
zero cloud requests and zero rubles.

The detailed route allocation and evidence-quality rules are in
[runtime-guard-model-fleet-contract.md](runtime-guard-model-fleet-contract.md). The
executable entry point and requirement-to-test matrix are in
[runtime-guard-api-acceptance-pack.md](runtime-guard-api-acceptance-pack.md).

## Privacy and evidence boundary

Allowed evidence:

- safe route and classification labels;
- request/action/content hashes;
- provider/model identifiers and reviewed policy digests;
- request and cost counters;
- deterministic verdict and reason codes;
- short independently written findings and public source links.

Forbidden evidence:

- raw prompt, response, tool output, employee conversation, private code, customer data;
- `.env`, keys, tokens, account identifiers, private endpoints;
- reversible secret fingerprints or secret-derived diagnostics;
- provider output presented as independent proof.

SHA-256 is not automatically anonymous. Never hash secrets for evidence or publication.
Use opaque random identifiers, or a keyed digest in a separate trust domain, for
low-entropy or identifying values.

## Enforcement invariant for a future product

This module is a policy decision point only. A production design must enforce complete
mediation:

`effect_occurs(action) => executor_consumed(valid_allow_receipt(action))`

The executor must reject stale, replayed, wrong-policy, wrong-target, or merely
`sandbox_only` decision receipts and emit a distinct `ExecutionOutcomeReceipt`.

## Product-repository owner gate

The current PR must stop at contracts, a pure evaluator, tests, and documentation.
Creating any executor, proxy, service API, storage engine, credential broker, IAM
integration, interception hook, deployment, or production enforcement path requires a
separate owner decision on a separate product repository and trust domain.

## Verification

Focused:

```powershell
python -m pytest tests/test_runtime_guard_foundation.py -q
python -m ruff check src/agentic_security_harness/runtime_guard_foundation.py tests/test_runtime_guard_foundation.py
python -m mypy src/agentic_security_harness/runtime_guard_foundation.py tests/test_runtime_guard_foundation.py
```

Full repository checks remain required before publication.
