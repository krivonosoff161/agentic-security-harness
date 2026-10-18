# Optional Action Authority integration

Agentic Action Authority is a [separately owned public repository](https://github.com/krivonosoff161/agentic-action-authority).
Its standalone 0.1.1 source merged at
`281d4cb9c4620697f33005c6e0d628e41ff20fa0` and its
[0.1.1 release](https://github.com/krivonosoff161/agentic-action-authority/releases/tag/v0.1.1)
is published on TestPyPI and [PyPI](https://pypi.org/project/agentic-action-authority/0.1.1/).
The 0.1.0 TestPyPI attempt remains a failed verification record, not a PyPI
release. Harness 1.14.2 is
[published](releases/v1.14.2.md), with a failed initial Windows production
lookup and a separate passing seven-job read-only verification. Check each
repository's release evidence before choosing an installed distribution.
The immutable Harness 1.14.2 tag locked Action Authority source
`4950321cda5c3f71b460cb4d35ec45073bc38449`; this page and the current
ecosystem lock reflect a later main-branch pin, not a change to that tag or wheel.

Action Authority tag build
[39108172887](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39108172887)
passed all five jobs, and tag Gitleaks
[39108172888](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39108172888)
passed. TestPyPI
[39108339899](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39108339899)
and PyPI
[39108500218](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39108500218)
each passed all seven publication and verification jobs. Both official indexes
carry the same non-yanked wheel SHA-256
`ca9df74f7c935f210cf0d787bde97723d9980f600388e034f29f8dbc93fc3caf`.
The four index-installed lanes each passed core 28 or adapter 72 tests on
Windows and Linux with zero skips, errors or failures. These 0.1.1 results
supersede compatibility inference from the prior 0.1.0 source checks; they do
not relabel its failed TestPyPI verification or the failed initial Harness
production workflow.

The approval coordinator and generic host-effect protocol live only in Action
Authority; Harness does not copy that core or require its distribution as a
base dependency. The Action Authority `[harness]` extra is optional and
contains the file adapter. That adapter depends on Harness and delegates file
effects to the existing guarded writer; it is not a second writer. The
standalone product's optional adapter passed installed core 28 and adapter 72
checks on each of Windows and Linux against **published Harness 1.14.2** at
0.1.1 in the index runs above. Earlier 0.1.0 source checks (PR #5 CI
`39063796029`, post-merge `39106883232`) remain historical evidence.
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
claim a new model study, independent human review, automatic activation from
Action Authority publication, or that the failed Harness production workflow passed.
