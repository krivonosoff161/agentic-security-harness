# Optional Action Authority integration

Agentic Action Authority is a [separately owned public repository](https://github.com/krivonosoff161/agentic-action-authority).
Its standalone 0.1.0 source merged at
`4950321cda5c3f71b460cb4d35ec45073bc38449`. At this source-preparation
snapshot, that version is **not published to a package index**. Harness 1.14.2
is also a source candidate, not an index release. Check each repository's
release evidence before choosing an installed distribution.

The approval coordinator and generic host-effect protocol live only in Action
Authority; Harness does not copy that core or require its distribution as a
base dependency. The Action Authority `[harness]` extra is optional and
contains the file adapter. That adapter depends on Harness and delegates file
effects to the existing guarded writer; it is not a second writer. The
standalone product's current optional adapter was tested against the **published
Harness 1.14.1** distribution, not against an unpublished 1.14.2 wheel.
Installing either package alone does not activate the integration.

A host that opts in must retain control of approval keys, effect bindings,
target selection and actual delivery. The coordinator's generic port is a
contract for host-owned effects, not a bundled network executor or a claim that
arbitrary applications are safe. The file adapter preserves its narrower
create-only Harness behavior and recovery rules. No model output grants
approval or filesystem authority. See the Action Authority repository's
README and tests for its API, supported platforms and exact compatibility
evidence; the [ecosystem component map](ecosystem-components.md) records the
source pin without adding it to the historical six-component functional chain.

This integration entry is documentation and source-lock metadata. It does not
claim a new model study, independent human review, index publication, or a
successful Harness 1.14.2 release gate.
