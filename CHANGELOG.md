# Changelog

All notable changes are documented here. The format follows Keep a Changelog.

## [0.1.0] - Unreleased

### Added
- Repository ingestion with symlink, credential-file, depth, count and size protections.
- Dependency intelligence for requirements.txt, pyproject.toml (PEP 621/735, Poetry), poetry.lock,
  uv.lock, package.json and package-lock.json (v2/v3), with direct/transitive classification,
  depth, cycle, duplicate-version and manifest/lockfile consistency analysis.
- CycloneDX 1.5 and SPDX 2.3 SBOM generation with structural validation and cross-format checks.
- OSV vulnerability engine: batch queries, retry, pagination, caching, local range verification,
  CVSS v3 scoring.
- SPDX license-expression engine with allow/deny policies.
- SHA-256 streaming integrity engine; SLSA provenance and Sigstore signature verification.
- Deterministic policy engine (PASS / FAIL / WARN / INDETERMINATE) with expiring waivers.
- CLI, FastAPI backend, SQLite and PostgreSQL persistence with append-only audit log.
- React dashboard, Docker Compose deployment, GitHub Actions CI/security/release workflows.
