# Runtime Guard API and acceptance pack

> Reviewed: 2026-07-26.
>
> Status: executable Python contract only; no service, network API, or executor.

## Foundation API

The only executable entry point in this foundation is:

```python
evaluate_action(action: ActionEnvelope, context: GuardContext) -> GuardDecision
```

The function is pure with respect to network, filesystem, Git, processes, credentials,
and durable state. It accepts metadata and digests, validates strict Pydantic schemas,
and returns a deterministic decision plus a decision-only evidence receipt.

Inputs:

- `ActionEnvelope`: exact actor/action/effect/target/purpose/scope/data/route/budget and
  lineage metadata;
- `GuardContext`: exact active policy, trusted-root sets, authority/consent/provider/
  budget records, authenticated canonical digests of complete classification/handoff/
  tool bindings, settled usage, active reservations, replay state, and evaluation time.

Output:

- `GuardDecision.disposition`: `allow`, `redact`, `block`, `ask_user`,
  `sandbox_only`, or `log_only`;
- stable reason codes;
- explicit owner-gate flag;
- `EvidenceReceipt` with action/context/policy hashes and previous-hash binding.

`allow` is a policy-decision result, not an executed effect. A future executor needs a
separate authenticated one-time decision receipt and must implement complete mediation.

## Compatibility rule

Unknown fields are rejected. New authority-bearing fields require a schema-version
change, adversarial tests, policy migration, and owner review. The existing synthetic
`CapabilityToken` converts only to an unverified draft and cannot become authority.

## Acceptance matrix

| Requirement | Executable evidence | Acceptance |
|---|---|---|
| No authority from text/model/tool output | Unverified capability and unknown-field tests | Must block. |
| Least-privilege scope/target | Empty scope, scope expansion, canonical URI, and target mismatch tests | Must reject or block. |
| Current action consent | Unverified and stale-digest consent tests | Must `ask_user`; conversation history is insufficient. |
| Model query is egress | Missing-consent model-query test | Must `ask_user`; a provider policy does not imply user consent. |
| Owner gates preserved | Merge action test | Must `ask_user` even with capability and consent. |
| Data policy enforced | can-store, recipient, forwarding, TTL, purpose, secret/private tests | Must fail closed. |
| Sanitization is two-phase | Restricted then verified-sanitized projection tests | Original gets `redact`; only new verified hash may be reconsidered. |
| Tool effect cannot hide | Trusted tool/effect binding test | Effective write policy and consent apply. |
| Handoff is action-bound | Payload, receiver, freshness, trust-root and replay tests | Missing/invalid required handoff blocks. |
| Provider legal record current | Exact route/destination/model plus stale/held/logging/retention/training/output/publication/license/input-rights tests | Any mismatch or uncertainty blocks. |
| Budget is race-aware at decision boundary | Fresh quote/FX conservative reservation and all-active-reservations tests | Aggregate request/cost cap cannot be exceeded. |
| Replay/order ambiguity rejected | Seen digest/ID and duplicate record tests | Must block or reject schema. |
| Evidence binds decision inputs | Context-digest mutation test | Authority or usage change changes context digest. |
| Verified strings do not self-authenticate | Missing/reused trusted-binding digest tests | A known root, `verified` flag, or reused receipt ID alone blocks. |
| Tool wrappers cannot hide effects | Effect-downgrade and tool-egress tests | Exact effective effect, route, consent, data and budget policy apply. |
| Privacy boundary | Serialized evidence test and repository secret scan | No raw identity, prompt, response, tool output, or secret. |

## Repository acceptance commands

```powershell
python -m pytest -q tests/test_runtime_guard_foundation.py
python -m pytest -q
python -m ruff check .
python -m mypy src tests tools
python -m bandit -r src -ll -ii
ash validate examples/
git diff --check
```

Release-style acceptance also requires two independently created wheel/sdist artifact
sets to be byte-identical after the repository's documented normalization. Passing
these checks proves only the bounded foundation at the reviewed commit. It does not
prove production enforcement, complete mediation, provider compliance at call time, or
resistance to real attacks.

## Explicit non-acceptance

This pack must fail product acceptance if any implementation adds or claims:

- a proxy/listener, executor, credential broker, provider adapter, durable ledger,
  IAM integration, deployment, live target, or hidden cross-project mutation;
- raw prompts, responses, employee conversations, secrets, private evidence, or
  reversible secret fingerprints;
- model-issued authority or consensus-as-proof;
- a provider call without exact route, rights, license, logging, price/FX, and budget
  evidence;
- a merge, release, tag, or deployment without its separate owner gate.
