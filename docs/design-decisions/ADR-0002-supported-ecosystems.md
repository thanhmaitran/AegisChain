# ADR-0002: Supported ecosystems and honest scope

**Status:** accepted

## Decision
P0: Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`) and Node.js (`package.json`,
`package-lock.json` v2/v3). `uv.lock` was inexpensive and is also implemented. Recognised but **not
analysed**: `pnpm-lock.yaml`, `yarn.lock`, `Pipfile.lock`, Go, Cargo, Maven, Gradle. They are listed
in `IngestionResult.unsupported_files` and raise a warning, so an unsupported lockfile never looks
like "no dependencies".

`package-lock.json` v1 is rejected with a parse error (INDETERMINATE) rather than half-parsed.

## Consequences
The README lists exactly these formats. Adding an ecosystem is: parser + registry entry + OSV
ecosystem mapping + fixtures with ground truth.
