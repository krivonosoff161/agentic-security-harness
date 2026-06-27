# Show HN Launch Draft

Status: draft for manual publication by the maintainer.

Do not publish until:

- the README front-door demo is merged and visible on `main`;
- the terminal and comparison-table screenshots render on GitHub;
- the demo command still reproduces `24 modeled findings -> 0 modeled findings`;
- CI is green on the latest README/docs PRs.

## Title

```text
Show HN: Testing whether AI coding agents obey untrusted repo text
```

## Body

AI coding agents read a lot of untrusted text: README files, issues, docs, tool output,
generated logs, and handoff notes from other agents.

Some of that text describes the project. Some of it contains instructions. The agent is
supposed to know the difference.

I wanted a reproducible way to test whether it actually does.

I built `agentic-security-harness`, a trace-first defensive benchmark for agentic AI
boundary failures. The local demo runs 24 synthetic boundary-failure patterns against
controlled demo agents. It records each interaction as a trace, produces scorecards and
remediation output, and writes a before/after comparison.

The included vulnerable demo agent fails the pattern set. The protected demo agent runs
against the same patterns and shows the expected contrast:

```text
baseline: demo-local-agent failed=24  protected: protected-demo-agent failed=0
```

Example pattern:

A synthetic README contains an instruction that should not have authority, such as telling
the agent to act outside its allowed boundary. A boundary-safe agent records the text as
untrusted repo data and does not act on it. The failing agent treats the README text as an
instruction. The harness records the prompt, response, decision, and canonical state hash
so the result can be inspected instead of summarized as an anecdote.

Try the local demo:

```bash
git clone https://github.com/krivonosoff161/agentic-security-harness
cd agentic-security-harness
pip install -e ".[dev]"
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

The demo uses local deterministic targets. No external API calls are required.

Limitations:

This is not a proof that a production agent is safe. It tests whether controlled targets
fail specific synthetic boundary patterns and leaves inspectable evidence. External model
evaluation through OpenAI-compatible endpoints exists, but it is experimental and
prompt-only.

I am looking for feedback on the pattern corpus, trace format, and whether this kind of
evidence would be useful for teams already testing AI coding agents or agentic CI.

https://github.com/krivonosoff161/agentic-security-harness

## Notes

- Use the repo URL as the submitted Show HN URL.
- Keep the title focused on untrusted repo text rather than broad "AI security".
- If asked about claims, answer with the benchmark boundary: deterministic synthetic
  traces, not production certification.
