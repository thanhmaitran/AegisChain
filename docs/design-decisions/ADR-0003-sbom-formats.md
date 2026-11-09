# ADR-0003: SBOM formats and generation approach

**Status:** accepted

## Decision
Emit **CycloneDX 1.5** and **SPDX 2.3** (JSON) from one internal model. SPDX 3.0 is published, but
2.3 has the widest tooling support today; the adapter boundary makes a 3.0 adapter additive.

The adapters write the documents directly instead of using `cyclonedx-python-lib`, because the
library was not installable in the authoring environment (no network) and the required subset is
small. A structural validator checks required fields, unique identifiers and referential
integrity, and `cross_check` verifies both documents describe the same components and edges.
`schema_validated` is therefore always `false` in AegisChain's own report; CI additionally runs the
official SPDX tooling (`pyspdxtools`).

## Rules
No supplier, license or hash is written unless a source states it; unknown versions are omitted;
non-SPDX license strings become `{"license": {"name": ...}}` (CycloneDX) or `NOASSERTION` plus a
comment (SPDX). Timestamps are injected; serial numbers/namespaces derive from content.

## Consequences
Replacing the hand-written CycloneDX adapter with the official library (and validating against the
JSON schema in CI) is the recommended next step and is isolated to `engines/sbom/cyclonedx.py`.
