# Contributing

Thanks for considering a contribution to `bgp-hijack-monitor`.

## Development setup

```bash
git clone https://github.com/YOUR-USERNAME/bgp-hijack-monitor.git
cd bgp-hijack-monitor
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src/ tests/     # lint -- must be clean
mypy src/                  # type-check
pytest -v                  # all tests must pass
```

## Guidelines

- New detection rules go in `detector.py` and must be pure functions with no
  network/database access, so they stay unit-testable without mocking.
- New alert backends implement `alerts/base.py::AlertBackend` and must never
  raise out of `send()` — log and swallow.
- Please add tests for any new behavior; PRs that only add features without
  tests will be asked for tests before merge.
- Keep line length to 100 columns (enforced by `ruff`).

## Reporting security issues

If you find a security-relevant bug (e.g. something that could suppress
legitimate hijack alerts, or a credential-handling issue), please open a
private security advisory on GitHub rather than a public issue.
