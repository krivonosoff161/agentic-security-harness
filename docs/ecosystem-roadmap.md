# Agentic Security ecosystem roadmap

> Generated from `ecosystem/roadmap.yaml`; edit the machine contract, not this file.
> Roadmap entries grant no operational authority.

Version: `2026.08.23-doc-convergence`  
Authority: `none`

## Ordered phases

| Phase | Status | Depends on | Deliverables |
|---|---|---|---|
| `documentation-convergence` | **active** | none | component manifests; document crosswalk; generated public projections; drift and link checks |
| `extension-contract` | **active** | `documentation-convergence` | extension manifest; check catalog; offline conformance kit; digest-bound companion adapters |
| `installable-extensions` | **active** | `extension-contract` | package entry points; compatibility matrix; cross-platform suite verification |
| `threat-watch` | **active** | `extension-contract` | digest-bound public source registry; offline snapshot review contract; model-neutral synthesis profile; external-unreviewed advisory output |
| `ecosystem-release-gates` | **planned** | `installable-extensions`, `threat-watch` | cross-repository lock; independent reviewer evidence; release compatibility report |

## Explicit non-claims

- all components are installable extensions today
- private research is public
- roadmap status grants operational authority
- synthetic validation proves production effectiveness
