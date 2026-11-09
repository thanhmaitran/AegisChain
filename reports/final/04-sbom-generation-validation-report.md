# 04 - SBOM Generation and Validation Report

* **CycloneDX 1.5 and SPDX 2.3** generated from one internal model; SPDX 3.0 deferred (ADR-0003).
* **Coverage:** every component appears in both documents; identifiers are Package URLs; versions,
  license declarations (as SPDX expressions) and hashes are included only when the source states
  them. Unknown values are omitted (CycloneDX) or `NOASSERTION` (SPDX).
* **Relationships:** root -> direct dependencies and component -> dependency edges in both formats;
  `cross_check` proves both documents describe the same components and edges.
* **Validation:** structural validators (required fields, unique ids, referential integrity) plus
  cross-format equality; `schema_validated` is reported as `false` because official JSON-schema
  validation is delegated to CI (`pyspdxtools`). Results: 4/4 generated SBOM sets valid,
  input-order independent and fully covering (`reports/sbom-validation/`). Example outputs for the
  two example projects are committed under the same directory.
* **Determinism:** timestamps are injected; serial number and SPDX namespace derive from content.
* **Limits:** hand-written CycloneDX adapter (replace with the official library when available),
  no supplier data (no trustworthy source in lockfiles), no file-level SPDX data.
