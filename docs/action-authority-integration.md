# Optional Action Authority integration

Agentic Action Authority is a [separately owned public repository](https://github.com/krivonosoff161/agentic-action-authority).
Its standalone 0.2.0 source is tagged at
`d5462692c2e4788364788ebc3fc11458c5abaf1c` and is published on
TestPyPI and [PyPI](https://pypi.org/project/agentic-action-authority/0.2.0/).
Harness 1.14.2 is
[published](releases/v1.14.2.md), with a failed initial Windows production
lookup and a separate passing seven-job read-only verification. Check each
repository's release evidence before choosing an installed distribution.
The immutable Harness 1.14.2 tag locked Action Authority source
`4950321cda5c3f71b460cb4d35ec45073bc38449`; this page and the current
ecosystem lock reflect a later main-branch pin, not a change to that tag or wheel.

Action Authority's exact tag build
[39116791967](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39116791967)
supplied the wheel with SHA-256
`e4e87e764bca9232bae74b66cef78d45d8c0eb03809442e0bc9bb2bd3955e328`.
TestPyPI
[39203686111](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39203686111)
and PyPI
[39203940701](https://github.com/krivonosoff161/agentic-action-authority/actions/runs/39203940701)
each passed all seven publication and verification jobs against that same
wheel; the PyPI publication receipt binds publish mode, the 0.2.0 tag,
`d5462692c2e4788364788ebc3fc11458c5abaf1c`, build `39116791967`
and the wheel digest. Four index-installed lanes each passed core 29 or adapter
93 tests on Windows and Linux with zero skips, errors or failures. Matching
index bytes and descriptions were read back. These checks establish package
identity and the declared synthetic contract, not independent human review.

The prior [0.1.1 release](https://github.com/krivonosoff161/agentic-action-authority/releases/tag/v0.1.1)
is historical: its source pin was `281d4cb9c4620697f33005c6e0d628e41ff20fa0`,
and TestPyPI `39108339899` and PyPI `39108500218` each passed seven jobs with
core 28 / adapter 72 checks. The 0.1.0 TestPyPI verifier failure remains a
failed verification record, not a PyPI release. None of these earlier results
is relabeled as 0.2.0 evidence or as a passed Harness production workflow.

The approval coordinator and generic host-effect protocol live only in Action
Authority; Harness does not copy that core or require its distribution as a
base dependency. The Action Authority `[harness]` extra is optional and
installs the Harness dependency needed by its file adapter. That adapter delegates file
effects to the existing guarded writer; it is not a second writer. The
standalone product's optional adapter passed installed core 29 and adapter 93
checks on each of Windows and Linux against **published Harness 1.14.2** at
0.2.0 in the index runs above. The new public `DocumentHost` facade composes
one create-only document journey: a trusted host declares its repository and
revision, independently verifies the operator-key fingerprint, prepares the
request, applies a separate signed decision, then gives the agent only a
content-only callback. The declarations are not remote Git attestation, and
setup does not create or approve an operator key. See the
[versioned integration guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.2.0/docs/integration.md)
and [one-document path](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.2.0/docs/one-document.md).
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
