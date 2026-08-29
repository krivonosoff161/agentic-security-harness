# Ecosystem integration candidate

This page records the review-only source integration gate for the optional public
ecosystem components. The published `v1.3.0` core contains the SDK and built-in auditors,
but not these optional package dependencies. This source candidate adds exact extras and
still grants no automatic activation, execution, or deployment authority.

## Exact source set

| Surface | Source head | Source tree | Role in this gate |
|---|---|---|---|
| Harness merged baseline | `c1dd69856212458ae952e43aeb2b0cc9290e8205` | `596c189e8b15ceaf7bf28337546655e23d47d3ef` | released `v1.3.0` docs-sync main anchor and optional-extras base |
| Transfer extension | `24b94cec7a18668ce4b236005a88e7be2bc205a1` | `dded5dd4dde34660259b80dbd48f2df1abe52cf2` | merged base 0.2.0 and extension 1.0.0 wheel sources |
| Handoff extension | `c02c8729d272aabed569e8e9a5f4dbd16e23a8f4` | `1443b6fed31805800d553cca31eade6d8a40dfe9` | merged base 0.3.0 and extension 1.0.0 wheel sources |
| Policy Pack | `dc75965f7ba4a766bb0e142773cf81985dc8340a` | `c5e34452e978193877fef660e417e4f376904a34` | merged data-only package 0.1.0 source |
| Router receipts | `87bc037b5c31cb110f7f253fb6bdcde0fa0c0f22` | `641f3fa10f10188eff250fa77264f25e0f51071c` | merged unique `agentic-llm-router` 0.2.0 package source and receipt contract |
| Cheap Filter receipts | `8d4dcf282a5408e04151ec550f69bc7c5065621f` | `ed587047da7364ac3bce4cb269553abee9a5e4d9` | merged zero-runtime-dependency 0.2.0 package source and receipt contract |
| Public profile projection | `ccb34ef951f434db8220b75bdf1129c3d0f97fda` | `b2c08e6aebd042d8fdfa3cf16dd42fd2b59355a0` | merged documentation projection only |

The final candidate descends from Harness `main` commit
`c1dd69856212458ae952e43aeb2b0cc9290e8205` and binds each companion repository's
merged `main` commit shown above. The central lock names `refs/heads/main` and the
workflow checks out those exact immutable commits. A later release gate must reverify
that the same source set remains intended; it must not silently float to newer heads.

Both source-owned extension manifests now name exact released Harness source
`c1dd69856212458ae952e43aeb2b0cc9290e8205`. The central matrix checks that same base,
builds all eight wheels, installs the closed wheelhouse without dependency resolution,
and verifies the two entry-point declarations without loading extension code.

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

`extension_candidate` describes a review-only nested extension source tree. The
compatibility matrix therefore records two Python ranges: `python` preserves the base
repository package range, while `extension_python` records the tested nested extension
range (`>=3.11,<3.14`). Neither label means that the extension ships inside the Harness
wheel or is available from PyPI.

## Schema governance

The ecosystem `*.v1` files in this stacked source candidate are review-only and have not
had a first stable public release. Adding the closed `extension_candidate` enum and
optional `extension_python` field is therefore a pre-publication contract correction,
not a backwards-compatible evolution of a shipped schema. Generated schema and
component-lock digests identify the exact reviewed revision; an older reader that does
not know the enum fails closed. No compatibility promise is made to earlier PR snapshots.

This separate policy does not alter the runtime evidence-artifact rules in
[artifact-schemas.md](artifact-schemas.md): widening a runtime artifact enum still
requires a minor version bump and a reader registry update. Before any first stable
publication of these ecosystem contracts, their public version must likewise adopt the
documented `MAJOR.MINOR` lifecycle.
