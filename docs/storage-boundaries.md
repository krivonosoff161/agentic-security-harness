# Storage boundaries

Agentic Security Harness is a public, release-facing repository. Keep the
repository limited to source code, public documentation, deterministic examples,
sanitized screenshots, and small reproducible fixtures.

Do not commit private or raw security research artifacts:

- raw model prompts or responses
- private attack-vector notes
- private traces from owned systems
- canary runs against local/private projects
- API keys, provider configs, tokens, `.env` files, or credentials
- generated report directories outside curated examples

Use local storage for raw work:

```text
C:\Users\krivo\research-artifacts\security-harness\
```

Public artifacts should be summaries, not raw dumps. If a result is useful for
the public repository, write a sanitized document or deterministic demo fixture
that can be reproduced without private systems or secrets.
