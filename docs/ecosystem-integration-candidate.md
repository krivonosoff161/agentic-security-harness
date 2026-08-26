# Ecosystem integration candidate

This page records the review-only source integration gate for the optional public
ecosystem components. It is not part of the published `v1.2.0` package, does not install
companions automatically, and grants no execution or deployment authority.

## Exact source set

| Surface | Source head | Source tree | Role in this gate |
|---|---|---|---|
| Harness merged baseline | `e49a9d81334177dffa1786d132344ba8e51902e1` | `673afdbdf4ab3af7ff975b66610f771ff74aace9` | stable `main` anchor containing the squash-merged ecosystem candidate and profile convergence |
| Transfer extension | `240f3081b6614439e03d61479114e330fe7c3d52` | `8e2e3319776a48fb96e04a2cd34ed83bb5d3d191` | nested no-dependency Harness extension plus `agentic-transfer-verifier` runtime wheel |
| Handoff extension | `f4e51e0603497f63c62453fc4030319fdfc5ac04` | `78311595f72469748469a1dfd4dc4a286244159f` | nested no-dependency Harness extension plus `ai-agent-handoff` runtime wheel |
| Policy Pack | `5a6519df5a54c103cd4b5ca14b479867c549d7d3` | `ab88886f92dc1efdbdc10a1761c91d3fceca8622` | exact data-only policy pack source |
| Router receipts | `790a101ba82fa34203219d7963978a20b55cf504` | `05fa373b1b16b276e44a9d39942127af729e7d23` | exact receipt producer contract |
| Cheap Filter receipts | `8dd1ffb8a453f62c9dd4b4a518754a23bd1651b6` | `d42f7f47a85a80cfe435a890c6ddd695085943b4` | exact receipt producer contract |
| Public profile projection | `ccb34ef951f434db8220b75bdf1129c3d0f97fda` | `b2c08e6aebd042d8fdfa3cf16dd42fd2b59355a0` | merged documentation projection only |

The final candidate descends from Harness `main` commit
`e49a9d81334177dffa1786d132344ba8e51902e1` and binds each companion repository's
merged `main` commit shown above. The central lock uses `refs/heads/main` for every
public source; it does not rely on former task branches.

The Transfer source-owned manifest names Harness `6354635c...` as its historical tested
baseline. The Handoff source-owned manifest independently names Harness `285d05ad...` as
its historical tested baseline. Those commits belonged to pre-squash task histories and
are not represented as ancestors of stable `main`. The central gate instead verifies the
exact merged Harness commit and tree above as an ancestor of the current checkout, then
proves forward compatibility by building and running both exact source extensions against
that current checkout on Ubuntu and Windows.

This asymmetry is deliberate. Companion repositories retain their exact historical test
identity while the central Harness lock binds their later merged source heads. Requiring
every repository to name the final Harness head would create an impossible mutual-head
fixed point. Requiring pre-squash commits to remain ancestors after a squash merge would
also make the gate depend on former task-branch history rather than the stable merged tree.

## Executable gate

The `ecosystem-integration` workflow runs on Ubuntu and Windows with Python 3.11. Each
matrix row:

1. checks out every public component at the exact head above;
2. validates all generated Harness schemas, manifests, docs, and the central component
   lock;
3. builds the Transfer and Handoff runtime and nested extension wheels from clean `git
   archive` snapshots, then installs all four with `--no-index --no-deps`;
4. performs metadata-only distribution inspection and reinspection-based approval before
   any extension module is imported;
5. imports only the explicitly selected factory, applies lifecycle binding, and executes
   one canonical synthetic advisory observation for each extension;
6. composes the Corpus Pack, evaluates the data-only Policy Pack, and exercises the
   Controlled Local adapter against an in-process literal-loopback fixture; and
7. runs the repository test, Ruff, mypy, Bandit, and package build/wheel smoke gates.

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
