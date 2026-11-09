# ADR-0005: Provenance and signature verification

**Status:** accepted

## Decision
Keep four questions separate, each a named `Check`:

1. `subject_digest_match` - the provenance subject digest equals the artifact's SHA-256;
2. `builder_identity` and `source_repository` - they match an explicit trust policy;
3. `sigstore_signature` - signature, certificate chain, transparency log and signer identity
   verified by the official `sigstore` client (`verify identity`).

AegisChain does **not** implement signature cryptography. Without the client, an identity or an
issuer, the signature check is `INDETERMINATE`. Only an explicit "verification failed" from the tool
is `FAIL`; infrastructure errors stay `INDETERMINATE`.

Supported containers: in-toto Statement v0.1/v1, DSSE envelope, Sigstore bundle, JSON-lines
(GitHub attestation downloads). SLSA provenance v0.2 and v1 field layouts are read.

## Limitations
The Sigstore CLI integration could not be exercised offline during development; it is covered by a
test double and by the "unavailable" paths. Verify it against a real attestation before relying on
it (`docs/security/limitations.md`).
