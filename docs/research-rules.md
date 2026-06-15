# Safe research rules

> **Agentic Security Harness.** These rules apply to all contributions, patterns, fixtures, and research
> in this repository. They complement [Responsible use](../SECURITY.md#responsible-use) and
> the [mission](mission.md).

1. **Authorized targets only.** Run the harness against mock / demo / your own / explicitly
   authorized systems. Never against third-party systems without written permission.
2. **Synthetic secrets only.** Use synthetic markers; never real credentials, tokens, or keys.
3. **No real credential collection.** Patterns must not gather real secrets from any system.
4. **No real exfiltration.** Data-exfiltration tests are simulations with synthetic markers;
   no data leaves a mock boundary.
5. **No live-abuse payloads.** No payload designed to harm or abuse a real system - use
   sanitized placeholders only.
6. **Deterministic tests.** Same inputs -> same trace. No network, no randomness, no clocks
   in unit tests.
7. **Cite prior art.** When a concept or technique comes from another project or paper, cite
   it; do not copy code blindly (respect licenses).
8. **Self-review before commits.** Check for secrets, overclaiming, unsafe wording, and scope
   creep before proposing a commit.
9. **Green before reporting.** Run `pytest`, `ruff check`, and `mypy` and confirm they pass
   before reporting work as done.
10. **Document residual risk honestly.** State what a test or mitigation does **not** cover.
