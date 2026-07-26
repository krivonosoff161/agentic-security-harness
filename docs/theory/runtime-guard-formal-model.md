# Runtime Guard formal model

> Status: deterministic executable-specification mathematics, not production proof.

Let a proposed action be:

`a = (actor, sponsor, effect, target, purpose, scopes, data, time, route, budget, lineage)`

Let `P` be the exact active policy digest, `C` a verified capability grant, `U` a fresh
consent receipt, `H` a verified handoff result, `V` a current provider-use record, and
`B` an atomic budget reservation.

## Authorization predicate

The metadata eligibility predicate is:

`eligible(a) = fresh(a) ∧ policy(a)=P ∧ capability(a,C) ∧ data_ok(a) ∧ handoff_ok(a,H) ∧ route_ok(a,V) ∧ budget_ok(a,B)`

Eligibility is not authorization. Authorization additionally requires current consent
for protected effects and the separate owner gate where policy requires it:

`authorized(a) = eligible(a) ∧ (¬protected(a) ∨ valid_consent(a,U)) ∧ owner_gate_ok(a)`

Narrative text, model output, tool output, retrieved context, and memory have no term
that can make `capability`, `valid_consent`, or `owner_gate_ok` true.

## Delegation predicate

The present foundation accepts only a trusted, action-bound handoff verification result.
It does **not** yet derive parent-child non-expansion. A future lineage verifier must
prove all of:

- `parent.can_delegate = true`;
- `child.depth = parent.depth + 1 ≤ parent.max_delegation_depth`;
- `scopes(child) ⊆ scopes(parent)`;
- `targets(child) ⊆ targets(parent)`;
- `effects(child) ⊆ effects(parent)`;
- `data_policy(child) ⊆ data_policy(parent)`;
- `providers(child) ⊆ providers(parent)`;
- `regions(child) ⊆ regions(parent)`;
- `budget(child) ≤ budget(parent)`;
- `purpose(child) = purpose(parent)`;
- `expiry(child) ≤ expiry(parent)`;
- trusted parent digest, receiver, policy, and lineage root all verify.

Until that verifier exists, a handoff binding is evidence input, not proof that
capability cannot expand.

## External-provider predicate

For any egress:

`external(a) ⇒ provider_id(a) ≠ null ∧ destination_digest(a) ≠ null`

`external(a) ⇒ data_class(a) ∈ {public, synthetic, sanitized}`

The `public` class is still insufficient without documented rights to submit and use
the material. A sanitized class is accepted only with a trusted classification receipt.

`provider_ok(a,V) = current_terms(V) ∧ allowed_automation(V) ∧ eligible_research(V) ∧ acceptable_retention(V) ∧ reviewed_model_license(V) ∧ input_rights(V) ∧ output_rights(V)`

Restricted data uses a two-phase transformation:

`restricted(original) -> REDACT`

`verified_sanitized_projection(new_hash) -> re-evaluate`

The first decision never executes the original external call.

## Budget predicate

Let `G` be settled global usage, `A` all active verified reservations, and
`Q_provider` settled provider usage. Let proposed requests be `r`, conservative maximum
cost be `c_max`, global caps be `R=200` and `K=150000` kopecks:

`G.requests + Σ(A.requests) ≤ R`

`G.cost + Σ(A.cost_max) ≤ K`

`Q_provider.requests + Σ(A_provider.requests) ≤ V.request_cap`

`Q_provider.cost + Σ(A_provider.cost_max) ≤ V.cost_cap`

The reservation binds action digest, provider, request count, maximum cost, current
pricing/FX digest, rounding, and safety margin. The pure evaluator checks the receipt;
atomic compare-and-swap and post-call settlement are future budget-service duties.

Provider policy lookup is additionally bound to the exact invocation-route,
destination, and model digests. A policy for one Yandex/Alibaba route or model cannot
authorize another route or model that shares the same provider name.

## Complete mediation

A production executor must enforce:

`effect_occurs(a) ⇒ executor_consumed(valid_allow_receipt(a))`

The current repository does not implement or verify this property. `sandbox_only` is a
directive, not permission: the future executor must verify sandbox identity, isolation,
filesystem and egress policy, then issue a separate `ExecutionOutcomeReceipt`.

## Fail-closed conditions

The decision is `block` when identity/route/schema is malformed, time is stale or in the
future, an action or ID was consumed, policy differs, verifier is unavailable, a trust
root is unknown, handoff/tool evidence is unverified, storage/forwarding policy fails,
provider terms or rights are stale/held, or any budget bound fails.

Owner-only actions (`merge`, `release`, `deployment`, `IAM`, secret access, destructive
operations) resolve to `ask_user` even when other metadata is valid. This evaluator does
not convert prior context into that authority.

## Evidence limitations

The decision-only receipt stores:

`hash(action_id), digest(action), content_hash, policy_hash, context_hash, previous_hash, decision, reason_codes`

It stores no raw prompt, response, tool output, secret, or employee identity. SHA-256
alone is not privacy protection for secrets or low-entropy identifiers. Production must
use opaque random identifiers or keyed digests from a separate trust domain as
appropriate.

The foundation marks origin authentication unverified and trusted time not recorded.
Therefore a self-hash and previous-hash link demonstrate deterministic binding only;
production authenticity needs a separate signer, append-only store, trusted time, key
rotation, revocation, and independent verification.

## Test interpretation

Synthetic tests falsify specific contract bugs: empty-scope authority, target/scope
expansion, consent reuse, recipient omission, self-declared sanitization, storage-policy
bypass, stale terms, aggregate budget overflow, replay, duplicate IDs/nonces, unknown
trust roots, unverified handoff/tool identity, malformed digests/URIs, and
authority-by-text. Passing them does not prove production protection, complete
mediation, low false-positive rate, or bypass-free deployment.
