# AegisChain Security Audit Report

**Final decision: INDETERMINATE**

- Repository: `python-project` (`sha256:42f10d67ba0251b5031ac11416a2eab269c6d46a2d68c6ab373e8c38147e1329`)
- Policy: `default` v1 (evaluated as of 2026-11-09)
- Tool: AegisChain 0.1.0, generated 2026-11-09T01:12:47+00:00
- Evidence digest: `sha256:87b98a4329eef7a56df80b0abf18194b64b627b99a15d9c435b843bbd46ae0d6`

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
- [License Compliance] 12 component(s) have a missing, invalid or custom license

## Vulnerabilities

Source: OSV (https://api.osv.dev); lookup status: **SKIPPED**

No matches were reported. This is not proof that the dependencies are free of vulnerabilities.

## Dependencies

13 components (4 direct, 9 transitive); parsed files: poetry.lock, pyproject.toml

## Metrics (seconds)

- dependency: 0.009873
- ingestion: 0.012064
- license: 5.4e-05
- policy: 0.000104
- sbom: 0.001509
- vulnerability: 0.000164
