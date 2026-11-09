# Coding Standards

* Python 3.12, full type hints, `mypy --strict` on `packages/` and `apps/api/src`.
* `ruff` rules `E,F,I,B,UP`, line length 100 (formatter-enforced).
* Frozen dataclasses for domain data; no mutable module state.
* Engines receive collaborators (clock, transport, provider) as arguments - no hidden globals or
  `datetime.now()` inside decision logic.
* Errors: raise a domain exception (`aegischain.exceptions`) at boundaries; never `except: pass`.
  A broad `except Exception` is only allowed in `AnalysisPipeline`, where it converts a crash into
  INDETERMINATE evidence and logs it.
* Do not invent data. If a source does not state a value, represent it as `None`/`UNKNOWN`.
* Subprocesses use argument lists, never `shell=True`.
* Logging: structured fields via `extra={"fields": {...}}`; never log secrets or file contents.
* Commit messages: Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
