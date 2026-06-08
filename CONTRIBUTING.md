# Contributing

> Product name TBD. Thanks for considering a contribution.

This is an early-stage project. The most valuable contributions right now are new
**attack cases**, scanner improvements, and honest measurement of detector quality.

## Getting started

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && mypy app && pytest
```

See [docs/development.md](docs/development.md) for the full layout and extension points.

## Ways to contribute

- **Add an attack** to `tests/attacks/` — a new injection variant, encoding trick, or
  leak case. New detection work should start with a failing test here.
- **Add or improve a scanner** — implement the `Scanner` protocol; keep it deterministic
  and fast. A scanner returns findings; it does not decide (the policy engine does).
- **Add a provider adapter** — implement `ProviderAdapter`; isolate provider quirks.
- **Docs** — clarity, accuracy, and removing any overclaiming.

## Ground rules

- **No overclaiming.** This project does risk reduction, not 100% protection. PRs that
  imply guaranteed protection will be revised. Report detector quality honestly,
  including false negatives.
- **The simple path stays simple** — the default must run with zero extra services
  (SQLite, no Redis, no classifier). Heavy dependencies (e.g. Presidio) go behind extras.
- **No secrets in code or config** — provider keys come from env only.
- **No self-learning shortcuts** — rules do not mutate at runtime; feedback labels are
  collected for future, human-reviewed adaptive rules only.

## Pull requests

- One logical change per PR; conventional commit style (`feat:`, `fix:`, `docs:`, `test:`).
- Include tests; keep `ruff`, `mypy`, and `pytest` green.
- Update `CHANGELOG.md` under `[Unreleased]`.
- For anything security-sensitive, see [SECURITY.md](SECURITY.md) — do not disclose
  vulnerabilities in a public PR.

## License of contributions

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
