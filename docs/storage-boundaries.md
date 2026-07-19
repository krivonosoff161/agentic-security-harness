# Storage boundaries

Portfolio-level documentation and storage authority is defined in the
[Documentation Contract](https://github.com/krivonosoff161/krivonosoff161/blob/main/docs/documentation-contract.md).
This page narrows that contract for Agentic Security Harness.

Agentic Security Harness is a public, release-facing repository. Keep the
repository limited to source code, public documentation, deterministic examples,
sanitized screenshots, deterministic synthetic traces, redacted artifacts, and
small reproducible fixtures.

Do not commit private or raw security research artifacts:

- raw model prompts or responses
- private attack-vector notes
- private traces from owned systems
- canary runs against local/private projects
- API keys, provider configs, tokens, `.env` files, or credentials
- generated report directories outside curated examples

Use local storage for raw work:

```text
<user-home>\research-artifacts\security-harness\
```

Public artifacts should be summaries, not raw dumps. If a result is useful for
the public repository, write a sanitized document or deterministic demo fixture
that can be reproduced without private systems or secrets.
