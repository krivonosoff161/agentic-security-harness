# Ecosystem integration and public package set

This page records the exact source integration gate and the public package set for the
optional ecosystem components. Harness `v1.4.0` publishes the exact extras after the
companion distributions were released. Installation still grants no automatic approval,
binding, activation, execution, provider access, or deployment authority.

## Exact source set

| Surface | Source head | Source tree | Role in this gate |
|---|---|---|---|
| Harness release baseline | `31c1f290f724298e5674a581c0699e6718b89285` | `fabb779cb29523ae0d42d346e1249371dc608f71` | released `v1.4.0` package source and optional-extras base |
| Transfer extension | `f4f464a085734b3a9296d337ad87897954905e2a` | `b75caee39d50b48b54f07070e4c8193518d43333` | published base 0.2.1 and extension 1.0.1 plus reconciled docs |
| Handoff extension | `46aba8284dd1a006bf9739edaa1c9d3212b7e735` | `5103a8be98628a2a575fda753a0a4a473168cc62` | published base 0.3.0 and extension 1.0.0 plus reconciled docs |
| Policy Pack | `190769a15a44f5a5af790b33fc37724e6417c27f` | `e3a5601a779c8b2e2f92516da30cf2750d320b5b` | published data-only package 0.1.0 plus reconciled docs |
| Router receipts | `69642b42d9999285a0c4642fcaa0405b67e619ad` | `bb1507c6389c6f4e91edd447b91c4c90b915f9a7` | published unique `agentic-llm-router` 0.2.0 package and receipt contract |
| Cheap Filter receipts | `17f13fd3986a2869686e59ca62123340fd56178b` | `5fc988323cada929a5c74846c4e28ddd468d26be` | published zero-runtime-dependency 0.2.0 package and receipt contract |
| Public profile projection | `36ce2be1ac27867cd95fbdb9d1a1027e8a0ed2f2` | `56d2069a47280bb80df7426a2c2d2ea29667a5df` | pre-final-repin documentation projection |

The release baseline is Harness `main` commit
`31c1f290f724298e5674a581c0699e6718b89285` and the lock binds each companion repository's
merged `main` commit shown above. The central lock names `refs/heads/main` and the
workflow checks out those exact immutable commits. The final profile repin is deliberately
sequenced after this Harness documentation merge to avoid a false circular current-head claim.

Both source-owned extension manifests retain exact Harness API compatibility evidence at
`c1dd69856212458ae952e43aeb2b0cc9290e8205`. The central matrix checks that same base,
builds all eight wheels, installs the closed wheelhouse without dependency resolution,
and verifies the two entry-point declarations without loading extension code. Separate
PyPI resolver smokes prove the published `v1.4.0` package coordinates.

## Executable gate

The `ecosystem-integration` workflow runs on Ubuntu and Windows with Python 3.11. Each
matrix row:

1. checks out every public component at the exact head above;
2. validates all generated Harness schemas, manifests, docs, and the central component
   lock;
3. builds the Harness wheel plus all seven companion/runtime/extension wheels, then installs
   the closed wheelhouse with `--no-index --no-deps`;
4. performs metadata-only distribution inspection and reinspection-based approval before
   any extension module is imported;
5. imports only the explicitly selected factory, applies lifecycle binding, and executes
   one canonical synthetic advisory observation for each extension;
6. composes the Corpus Pack, evaluates the data-only Policy Pack, and exercises the
   Controlled Local adapter against an in-process literal-loopback fixture; and
7. verifies exact optional-dependency coordinates and installed wheel metadata without
   importing extension entry points; and
8. runs the repository test, Ruff, mypy, Bandit, and package build/wheel smoke gates.

The repository's separate pinned Gitleaks workflow remains the PR-level full-history
secret scan. It runs on the same pull request without making the exact-source matrix
interpret nested companion worktrees as Harness-owned history.

The generated `schemas/companion-extensions.v1.manifest.json` binds this workflow, its
E2E test, this page, and the compatibility matrix by exact SHA-256. The always-on
generator check therefore fails if any of those evidence surfaces are deleted or changed
without regenerating and reviewing the contract manifest.

The matrix does not use provider credentials, paid APIs, external model calls, extension
auto-discovery, arbitrary tools, or an upstream MCP server. The Controlled Local contour
uses only an operator-test fixture bound to literal loopback. Distribution approval is
not signature verification, sandboxing, producer authentication, or permission to trust
third-party code.

## Compatibility labels

`extension_candidate` describes an operator-selected nested extension. The
compatibility matrix therefore records two Python ranges: `python` preserves the base
repository package range, while `extension_python` records the tested nested extension
range (`>=3.11,<3.14`). The packages are available from PyPI, but the extension does not
ship inside the Harness wheel and installation does not approve or bind it.

## Schema governance

The ecosystem `*.v1` files shipped with the public Harness line. This reconciliation does
not widen their closed enums or runtime semantics. Generated schema and component-lock
digests identify the exact reviewed revision; incompatible future schema changes require
the documented versioned lifecycle rather than silent widening.

This separate policy does not alter the runtime evidence-artifact rules in
[artifact-schemas.md](artifact-schemas.md): widening a runtime artifact enum still
requires a minor version bump and a reader registry update. Before any first stable
publication of these ecosystem contracts, their public version must likewise adopt the
documented `MAJOR.MINOR` lifecycle.
