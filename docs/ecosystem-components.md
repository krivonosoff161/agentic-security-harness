# Ecosystem components

> Generated from `ecosystem/compatibility.json` and the ordered component list.

| Component | Integration | Harness API | Source package Python | Extension Python | Supported | Tested |
|---|---|---|---|---|---|---|
| `agentic-security-harness` | `suite_verified` | `>=1,<2` | `>=3.11,<3.14` | `not applicable` | linux, windows | linux, windows |
| `agentic-transfer-verifier` | `extension_candidate` | `1 (candidate; future package boundary >=1.3,<2)` | `>=3.10` | `>=3.11,<3.14` | linux, windows | linux, windows |
| `ai-agent-handoff` | `extension_candidate` | `1` | `>=3.11` | `>=3.11,<3.14` | linux, windows | linux, windows |
| `llm-safety-playbooks` | `standalone` | `not-applicable` | `>=3.9` | `not applicable` | linux, windows | linux, windows |
| `llm-router` | `contract_only` | `not-yet-declared` | `>=3.9` | `not applicable` | linux, windows | linux, windows |
| `llm-cheap-filter` | `standalone` | `not-yet-declared` | `>=3.9` | `not applicable` | linux, windows | linux, windows |
| `agentic-runtime-guard` | `contract_only` | `private-sanitized-boundary` | `>=3.11` | `not applicable` | windows | windows |
| `krivonosoff161` | `standalone` | `not-applicable` | `not-applicable` | `not applicable` | web | web |

`contract_only` and `standalone` are honest current states. They do not mean
the component is already installable through the Harness Extension API.
`extension_candidate` identifies an exact review-only source extension tested
by Harness; it is not a released dependency and grants no execution authority.
For that state, source-package Python preserves the base package declaration
and extension Python records the separately tested nested runtime range.
