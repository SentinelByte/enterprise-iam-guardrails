# Contributing

Thanks for taking a look. This is a small project, so the bar is simple:
keep it green, keep it typed, keep findings actionable.

## Setup

```bash
uv venv
uv pip install -e ".[dev]"
pre-commit install
```

## Before opening a PR

```bash
ruff check .
mypy src/
bandit -c pyproject.toml -r src/
pytest
```

CI runs these same four commands on Python 3.11 and 3.12, so if they pass
for you, they'll pass there too.

## Adding a check

Every check returns `list[Finding]` (`src/iam_guardrails/findings.py`) and
shouldn't raise on well-formed input. Add a fixture under `tests/fixtures/`
for both the "this should fire" and "this should be clean" case, and write
the `remediation` text as if it'll be read by someone who's never seen the
check before — because it will be.
