# Trust Model

## What each piece of evidence establishes

| Evidence | Establishes | Does **not** establish |
|---|---|---|
| SHA-256 matches a reference digest | The bytes equal whatever the reference describes | Who produced the file; that the reference is trustworthy |
| Provenance subject digest matches | The provenance document is *about* this artifact | That the document is authentic |
| Builder / source match policy | The claimed builder and repo are on the operator's allow-list | That the claim is true unless the document is signed |
| Sigstore verification (identity) | A holder of the expected OIDC identity signed it, logged in Rekor | That the signer's workflow is free of vulnerabilities |
| OSV has no match | No known advisory matched at query time | That the dependency is safe |
| License declared as MIT | The package metadata says MIT | A legal conclusion |

## Roots of trust

1. The **operator's policy** (trusted builders, sources, signer identity, OIDC issuer).
2. **Sigstore's public-good instance** (via the `sigstore` client's TUF-distributed roots).
3. **OSV** as a vulnerability data source (queried over HTTPS).
4. The **reference digests** the operator supplies. Obtain them out-of-band (e.g. from a signed
   release page), not from the same place as the artifact.

## Decision rule

PASS is only produced when every *required* check ran and succeeded. A check that could not run is
INDETERMINATE; a check that ran and found a problem is FAIL.
