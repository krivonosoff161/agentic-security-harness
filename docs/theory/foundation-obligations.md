# Foundation contracts and evidence limits

This is the public contract summary for the [17-question matrix](../foundation-matrix.md).
Full working derivations and drafts remain outside public Git. The statements below
name assumptions, implemented checks and counterexamples so they can be reviewed without
treating a private calculation, finite test or model observation as universal safety.
The regression inputs are public synthetic records, not evidence of model intention.

## L1. Restriction order

On normalized envelope fields, restriction means recipient/purpose subsets, no added
storage/forward/mutability permission, no removed confirmation, no lower sensitivity,
no longer finite TTL (`None` is unbounded), and unchanged classification-source identity.
Unknown sensitivity labels compare only to themselves. The absent envelope is not
treated as a public envelope. The product relation is a partial order on these normalized
policy fields, not on unrelated metadata or list representation.

Code: `envelope_policy.envelope_violations`. The independent finite oracle in
`tests/test_foundation_contracts.py` checks 4,096 ordered pairs over 64 states and order
laws. Other axes have targeted tests. Chain non-expansion requires an authentic starting
policy and a check at every boundary; a wrong initial label or bypass is outside this result.

## L2. Time narrowing

With original write time t0, elapsed time t-t0 and finite write/store/read TTL values F,
the implemented read condition is `t-t0 <= min(F)`; no finite deadline exists when F is
empty. Equality is accepted. All bounds use the original write epoch.

`validate_memory_read_envelope` and governed-memory tests reject the previously accepted
case write=60, store=read=1, elapsed=30. Missing elapsed time checks metadata only.
No claim is made about clock authenticity, erasure of bytes or provider retention.

## L3. Scope and ancestry

For supplied parent/child **envelope metadata**, the checked condition is
`S_child subseteq S_parent`. A known-empty parent scope admits only an empty child
scope. `None` means no parent-scope comparison, not an authenticated empty grant.

The handoff payload is hash-bound opaque data. A payload field named `scope` is not
interpreted as a capability grant or compared to the envelope by this toy verifier.
A metadata PASS does not authorize payload execution. The separate consumer/Gateway
must bind an actual action to trusted policy; full payload/authority composition remains
an explicit research question.

Tests cover the complete two-action parent/child scope matrix and distinguish unknown
from known-empty parent state. Core's stateless handoff does not authenticate ancestry
or maintain a spent-receipt set. Handoff metadata checks a supplied adjacent sequence;
Transfer's self-parent check does not establish multi-node cycle rejection.
Expiry, authenticated provenance, complete ancestry and replay prevention are separate.

## L4. Advice versus an action

Model, Filter, Router and Playbook outputs are data, not policy or an action grant.
The intended composition requires a trusted policy and a decision on the exact action
at every effect path. Complete mediation is an assumption, not a consequence of a
successful local example or a component's advisory PASS.

Public code witnesses are the quarantine/advisory connectors, Runtime Gateway, receipt
auditors and policy-pack extension. Existing checks cover parsing, allowlists, bindings,
replay context and fake/no-op composition. They do not establish isolation for another host.

## L5. Commitments and audit history

A fixed encoding and trusted expected digest can bind bytes under the hash assumptions;
neither a digest nor a self-consistent hash chain authenticates the initial claim.
An independently trusted final commitment/length and an event-coverage contract are
needed to reason about history deletion, truncation or replacement.

The trace-truncation characterization records the structural/causal limit. Package-specific
canonicalization, exact pack-byte pins and producer authentication are distinct.
Python sorted JSON is not automatically RFC 8785/JCS. No new signature or custody
authentication is claimed.

## L6. Budgets and fixed-point accounting

Nonnegative charges and an atomic reserve-before-use rule support a nonnegative remaining
budget; uncounted retries or alternate executors violate the required model assumptions.
A finite retry limit is not a distributed accounting service.

Router receipt checks bind declared bounded-integer charges, attempt order and integer
half-even arithmetic. They do not attest provider usage, invoice totals or global budget
reservation. The public matrix keeps Router and Core loop contracts separate.

## L7. Advisory decision combination

A trusted decision may be combined with advice only through a policy-owner-defined rule
that cannot weaken that decision. Filter `drop/cheap/chief` is routing, not an
`allow/deny` authorization order; Playbooks `observe/challenge/escalate/abstain` is advice.

Receipts declare operational authority none; Core audits them and Gateway decides.
This boundary does not establish classifier accuracy or the correctness of every future
adapter's combination rule.

## L8. Recovery and liveness

Safety and progress are different obligations. Perpetual refusal may prevent effects
without producing a useful permitted result. A finite approved recovery graph needs both
a terminating transition rule and a reachable useful terminal state without new authority.

Catalog question 16 has no shipped scenario establishing both obligations. A decreasing
rank is a proposed method for termination, not a claim that recovery is implemented.

## Metrics are not authorization

Required-label retention uses `|P intersect C| / |P|` when P is nonempty; empty P is N/A,
not an invented success rate. Scope expansion is the set `S_child - S_parent`.
Structural risk scores are reporting heuristics unless independently calibrated and
cannot override hard blockers.

## Primary references

- Saltzer and Schroeder (1975), [The Protection of Information in Computer Systems](https://www.mit.edu/~Saltzer/publications/protection/index.html):
  fail-safe defaults and complete mediation are design principles, not proof of this code.
- [RFC 8785 (2020)](https://www.rfc-editor.org/rfc/rfc8785.html):
  canonical representation matters for commitments; this reference does not certify
  this project's encodings as JCS or authenticate a producer.

References are untrusted research input. No downloaded research code, private derivation
archive or raw model transcript is included in this public summary.
