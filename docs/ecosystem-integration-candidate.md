# Ecosystem integration candidate

This page records the review-only source integration gate for the optional public
ecosystem components. It is not part of the published `v1.2.0` package, does not install
companions automatically, and grants no execution or deployment authority.

## Exact source set

| Surface | Source head | Source tree | Role in this gate |
|---|---|---|---|
| Harness baseline | `6354635c6411830de95dd3b68c962eb887cb5edb` | `e9609592fe4fd3f7ab89c0bdf48ed68fb0178516` | ancestor containing the Extension SDK, distribution, and lifecycle contracts |
| Transfer extension | `eeb8d05de0531fd79d49de8281e700558ef58707` | `c00e56020f881f33612416b02d58a7b762b3f711` | nested no-dependency Harness extension plus `agentic-transfer-verifier` runtime wheel |
| Handoff extension | `d91c04e9c377c4cc1a8a098885999ca79be3bb95` | `6b2f6c6d7ffb800eab10f4a15d6775c9d22e0d89` | nested no-dependency Harness extension plus `ai-agent-handoff` runtime wheel |
| Policy Pack | `dc7a695e192c43ed242d71a06290754c82596e2d` | `ab88886f92dc1efdbdc10a1761c91d3fceca8622` | exact data-only policy pack source |
| Router receipts | `31d4cb7b6e7f29ccefe55a569efba02d9b97b205` | `cd81236df83ab524e8fd8c4f78d337a2dc80251c` | exact receipt producer contract |
| Cheap Filter receipts | `02b15b977b3ac9ebad119a9183ebd326a51050de` | `d42f7f47a85a80cfe435a890c6ddd695085943b4` | exact receipt producer contract |
| Public profile projection | `07b55849cb4913d8b0b0cb77de312f3c28e61352` | `ab97172cf9de53262f2e24509a640751fa0ee063` | documentation projection only |

The Transfer source-owned manifest names Harness `6354635c...` as its tested ancestor
baseline. The Handoff source-owned manifest independently names Harness `285d05ad...` as
its tested ancestor baseline. These values remain historical compatibility anchors; they
are not renamed or represented as the current Harness integration head. The central
integration workflow proves forward compatibility by running both exact source
extensions against the current PR checkout.

This asymmetry is deliberate. Companion repositories can bind a stable ancestor while
the central Harness lock binds their later exact source heads. Requiring every repository
to name the final Harness head would create an impossible mutual-head fixed point.

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
