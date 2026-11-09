# AegisChain Security Audit Report

**Final decision: INDETERMINATE**

- Repository: `python-project` (`sha256:42f10d67ba0251b5031ac11416a2eab269c6d46a2d68c6ab373e8c38147e1329`)
- Policy: `default` v1 (evaluated as of 2026-11-09)
- Tool: AegisChain 0.1.0, generated 2026-11-09T01:04:55+00:00
- Evidence digest: `sha256:fe229dfdd6690661f50f339fe653fbc075a76a2821327d7a466d9c16dc51f115`

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

- dependency: 0.013141
- ingestion: 0.008768
- license: 2.5e-05
- policy: 6.6e-05
- sbom: 0.001408
- vulnerability: 6e-05
