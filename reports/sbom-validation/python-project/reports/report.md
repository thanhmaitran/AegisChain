# AegisChain Security Audit Report

**Final decision: INDETERMINATE**

- Repository: `python-project` (`sha256:42f10d67ba0251b5031ac11416a2eab269c6d46a2d68c6ab373e8c38147e1329`)
- Policy: `default` v1 (evaluated as of 2026-01-01)
- Tool: AegisChain 0.1.0, generated 2026-01-01T00:00:00+00:00
- Evidence digest: `sha256:005e745a7768b9457c3cc75a58d38a11c00d76dcf52153bb4bfbe30c9c7375ef`

## Engine results

| Engine | Status | Evaluated |
|---|---|---|
| Dependency Analysis | PASS | yes |
| SBOM Validation | PASS | yes |
| Vulnerability Analysis | INDETERMINATE | yes |
| License Compliance | WARN | yes |
| Artifact Integrity | PASS | no (not required) |
| Provenance Verification | PASS | no (not required) |

## Reasons

- [Vulnerability Analysis] Vulnerability lookup skipped: Vulnerability lookup skipped (offline mode). This is NOT evidence that the dependencies are vulnerability-free.
- [License Compliance] 13 component(s) have a missing, invalid or custom license

## Vulnerabilities

Source: OSV (https://api.osv.dev); lookup status: **SKIPPED**

No matches were reported. This is not proof that the dependencies are free of vulnerabilities.

## Dependencies

13 components (4 direct, 9 transitive); parsed files: poetry.lock, pyproject.toml

## Metrics (seconds)

- dependency: 0.002254
- ingestion: 0.001512
- license: 2e-05
- policy: 5.9e-05
- sbom: 0.00093
- vulnerability: 8.6e-05
