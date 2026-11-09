# Known Limitations and Residual Risks

These are real gaps, listed so nobody over-trusts the tool.

## Verification status of this release
* Core engines, CLI, policy, SBOM, integrity, archive handling and the API **service layer** are
  covered by 203 automated tests that were executed and passed during development.
* The **FastAPI HTTP layer, SQLAlchemy/PostgreSQL repository, Alembic migration, React dashboard,
  Dockerfiles and GitHub workflows were written but not executed** in the authoring sandbox
  (no network, so FastAPI/SQLAlchemy/npm packages could not be installed). HTTP and PostgreSQL tests
  exist and run in CI (`apps/api/tests/test_http_api.py`, `tests/integration/test_database.py`);
  treat the first CI run as the first verification of those parts.
* `ruff` and `mypy --strict` were not available in the sandbox. Run `make fix` and `make check`
  before the first commit and expect some findings.
* The **Sigstore CLI integration** has not been run against a real attestation.

## Functional limits
* Only the ecosystems in ADR-0002 are analysed; pnpm/yarn/Pipfile/Go/Cargo/Maven are reported as
  unsupported, not analysed.
* `requirements.txt` without `==` pins yields unknown versions and therefore unscanned components.
* npm: declared ranges in `package.json` are not evaluated against locked versions (only presence).
  Peer dependencies are noted, not modelled. Lockfile v1 is rejected.
* Poetry/uv lock hashes are omitted when a package has several files (no single digest to claim).
* Licenses come only from lockfile metadata (npm lockfiles often include them; Poetry locks do not)
  or from operator-supplied evidence (`--license-evidence`). Most Python components will be
  `UNKNOWN` unless evidence is provided. Nothing is inferred.
* Vulnerability results depend on OSV. No reachability or exploitability analysis. CVSS v4 is not
  scored (severity falls back to the advisory label, then UNKNOWN).
* SBOMs are structurally validated only; official schema validation runs in CI, not in the product.
* Direct/transitive classification from `poetry.lock` alone is inferred from graph roots and flagged.

## Operational limits
* Single shared API key; no per-user authentication, authorisation or rate limiting.
* Analysis is synchronous inside the request; very large uploads need proxy timeouts and CPU limits.
* Starlette buffers multipart uploads before the service-level size check; enforce
  `client_max_body_size` at the proxy (provided in `docker/nginx.conf`).
* The default SQLite store is single-node.
* The local OSV cache is not integrity-protected against a local attacker.
