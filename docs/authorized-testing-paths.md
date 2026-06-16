# Authorized testing paths

> Last reviewed: 2026-06-16.
>
> Scope: how Agentic Security Harness can be used for legitimate defensive evaluation.
> This page is not legal advice. It defines project policy and evidence expectations.

## Principle

The harness is for **authorized defensive evaluation** of agentic AI boundary failures.
It can run against local synthetic targets, systems you own, systems you are explicitly
authorized to test, or provider endpoints only when their program scope permits it.

Local execution through Ollama, LM Studio, vLLM, or another self-hosted runtime removes
dependency on a cloud API provider. It does **not** remove legal duties, model-license
terms, acceptable-use policies, or authorization boundaries.

## Supported paths

| Path | What it means | Current support | Required evidence |
|---|---|---|---|
| Demo synthetic lab | Built-in mock/demo/toy targets with synthetic data only. | Shipped. | Run config, traces, scorecard, validation result. |
| Local runtime lab | A local OpenAI-compatible runtime such as Ollama, LM Studio, or vLLM. | Supported through experimental `run-external`; prompt-only, no tool execution. | `run_config.runtime`: runtime label, model id, `network_mode=local-only`, model license note, recovery guidance. |
| Owned system assessment | A target adapter around a system controlled by the user or organization. | Future adapter track; current docs only. | Written scope, adapter metadata, target owner, isolation, logs. |
| Customer-authorized assessment | Testing a third-party system with explicit permission. | Future adapter track; current docs only. | Rules of engagement, scope, dates, contacts, allowed tests. |
| Provider bug bounty / safe harbor | Testing a provider product only inside its published scope. | Manual process outside the harness; artifacts may be generated if allowed. | Program URL, scope, allowed test class, no out-of-scope data. |
| Standards-aligned benchmark | Mapping harness findings to public frameworks. | Partial. | Mapping source, category, status, and a clear "not certification" note. |

## Official anchors

Use these as public methodology anchors, not as endorsements:

- NIST AI Risk Management Framework: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI 600-1 GenAI Profile: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- NIST SP 800-115 Technical Guide to Information Security Testing and Assessment:
  <https://csrc.nist.gov/pubs/sp/800/115/final>
- OWASP Top 10 for LLM Applications:
  <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- OWASP Top 10 for Agentic Applications:
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- MITRE ATLAS: <https://atlas.mitre.org/>
- CISA AI guidance: <https://www.cisa.gov/ai>
- NCSC / CISA secure AI system development guidance:
  <https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development>

Provider programs and policies change. Before testing provider-owned systems, check the
current program scope and terms directly.

## Evidence fields future adapters should record

Future non-demo adapters should make the authorization model visible in artifacts:

```json
{
  "authorization_mode": "demo_synthetic | local_runtime | owned_system | customer_authorized | provider_program",
  "target_owner": "self | organization | customer | provider | synthetic",
  "scope_reference": "path-or-url",
  "rules_of_engagement": "path-or-url",
  "provider_terms_url": "https://example.invalid/policy",
  "safe_harbor_url": "https://example.invalid/safe-harbor",
  "model_license": "license-or-policy-name",
  "network_mode": "off | local-only | authorized-external",
  "data_class": "synthetic | sanitized | customer-approved"
}
```

The current shipped local targets do not need these fields because they are offline,
synthetic, and deterministic. The experimental external path already records run
configuration, redacted base URL, credential env-var name, raw-response metadata, and
cross-check status. New local-runtime runs also record `run_config.runtime` with
`authorization_mode=local_runtime`, `prompt_only=true`, `tool_execution=false`, model
license/policy note, and recovery guidance.

## Not allowed in this project

- Testing third-party systems without written authorization.
- Real credential theft, real exfiltration, malware behavior, persistence, evasion, or
  service disruption.
- Publishing real secrets, private prompts, private customer data, or provider tokens.
- Claiming NIST, OWASP, MITRE, CISA, NCSC, or provider certification.
- Treating local model execution as permission to ignore model licenses or laws.

## How to phrase public results

Preferred wording:

> This run used synthetic benchmark scenarios and maps findings to public security
> frameworks for analyst orientation. It is not a certification or endorsement.

For local runtimes:

> This run evaluated an authorized local OpenAI-compatible runtime through the
> experimental prompt-only external path. The artifact records `network_mode=local-only`,
> model id, model-license note, and recovery guidance. No tools were executed.

For future owned-system adapters:

> This run evaluated a target under a documented authorization scope. The report records
> the adapter, target owner, network mode, and artifact validation status.

Avoid:

- "unrestricted red-team";
- "provider policy bypass";
- "certified secure";
- "proves this model is safe";
- "officially approved by NIST / OWASP / MITRE".

## Recovery expectations

If an authorized check cannot run, the user should see:

- what failed;
- whether the result is final or inconclusive;
- how to retry;
- what artifact was saved;
- what alternate path is available.

This matches the benchmark's broader recovery-path principle and should become a future
pattern family.
