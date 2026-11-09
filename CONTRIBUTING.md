# Contributing

## Development setup

1. Install Python 3.12 or newer (and Node.js 22 for the dashboard).
2. Create a virtual environment and install everything:

   ```bash
   python -m venv .venv && source .venv/bin/activate   # PowerShell: .\.venv\Scripts\Activate.ps1
   make install        # or: python -m pip install -e ".[api,security,dev]" -e apps/api
   ```

3. Before the first commit run `make fix` once so formatting and import order match the
   Ruff configuration.

## Quality checks

```bash
make check      # ruff, ruff format --check, mypy, pytest
make cov        # tests with coverage
```

## Development principles

- Keep security engines modular; engines talk through the interfaces in `aegischain.domain`.
- Fail safe: an error or missing evidence is `INDETERMINATE` (or `FAIL`), never `PASS`.
- Add tests for new behaviour, including the failure path.
- Validate every external input; never read paths supplied by an API client.
- Do not invent data (versions, licenses, hashes, suppliers) that the source does not state.
- Document architectural decisions as ADRs in `docs/design-decisions/`.
- Never commit secrets or private signing keys.
