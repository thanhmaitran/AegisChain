# 06 - Artifact Provenance and Integrity Report

* **SHA-256:** streaming (1 MiB chunks), constant-time comparison, symlinks and non-regular files
  refused, change-during-read detected. Evaluation: 500/500 unmodified files accepted, 500/500
  single-bit flips detected, plus empty/missing/invalid/no-reference edge cases (1,004/1,004).
* **Separation of concerns:** hash match, provenance subject match, builder/source policy match and
  signature verification are independent named checks (ADR-0005).
* **Provenance:** in-toto Statement v0.1/v1, DSSE, Sigstore bundle, JSON-lines; SLSA v0.2 and v1
  field layouts. 11/11 crafted evidence sets classified as expected (valid, wrong digest,
  untrusted builder/source, no trust policy, non-SLSA predicate, garbage, empty subjects, none).
* **Signature:** delegated to the official `sigstore` client; absence of client, identity or issuer
  -> INDETERMINATE.
* **Trust assumptions:** `docs/security/trust-model.md`.
* **Limitations:** Sigstore integration not exercised against a real attestation in development;
  the evaluation used a test double for the signature backend. A matching hash proves nothing
  about authorship.
