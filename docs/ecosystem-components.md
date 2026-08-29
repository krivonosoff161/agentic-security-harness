# Ecosystem components

> Generated from `ecosystem/compatibility.json` and the ordered component list.

| Component | Integration | Harness API | Source package Python | Extension Python | Supported | Tested |
|---|---|---|---|---|---|---|
| `agentic-security-harness` | `suite_verified` | `>=1,<2` | `>=3.11,<3.14` | `not applicable` | linux, windows | linux, windows |
| `agentic-transfer-verifier` | `extension_candidate` | `1` | `>=3.10` | `>=3.11,<3.14` | linux, windows | linux, windows |
| `ai-agent-handoff` | `extension_candidate` | `1` | `>=3.11` | `>=3.11,<3.14` | linux, windows | linux, windows |
| `llm-safety-playbooks` | `standalone` | `not-applicable` | `>=3.9` | `not applicable` | linux, windows | linux, windows |
| `llm-router` | `contract_only` | `not-yet-declared` | `>=3.9` | `not applicable` | linux, windows | linux, windows |
| `llm-cheap-filter` | `standalone` | `not-yet-declared` | `>=3.9` | `not applicable` | linux, windows | linux, windows |
| `agentic-runtime-guard` | `contract_only` | `private-sanitized-boundary` | `>=3.11` | `not applicable` | windows | windows |
| `krivonosoff161` | `standalone` | `not-applicable` | `not-applicable` | `not applicable` | web | web |

`contract_only` and `standalone` are honest integration states; a passive
Harness package extra does not promote them into runtime extensions.
`extension_candidate` identifies an operator-selected extension tested by
Harness. Publication does not grant approval, binding, or execution authority.
For that state, source-package Python preserves the base package declaration
and extension Python records the separately tested nested runtime range.
