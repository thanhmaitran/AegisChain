# 02 - Threat Model Report

Full model: `docs/security/threat-model.md` (STRIDE, 15 threats, controls, residual risks).

* **Assets:** integrity of the decision, the analysis host, API key and stored reports, policies,
  the OSV cache.
* **Trust boundaries:** untrusted repository/artifact input; network data (OSV, Sigstore);
  API clients; database; operator-trusted policy files.
* **Attack surfaces:** repository traversal, archive extraction, manifest parsers, OSV responses,
  provenance documents, policy YAML, API uploads, the browser.
* **Key controls with tests:** no symlink following, credential files never read, zip-slip/link/bomb
  protection, digest re-verification between ingestion and parsing, bounded reads, safe YAML,
  linear-time graph analysis (2,000-node cycle test), fail-safe INDETERMINATE semantics.
* **Residual risks:** single shared API key and no rate limiting; CPU time not capped per request;
  secrets embedded *inside* manifests could surface in findings; local cache is not
  integrity-protected; Sigstore integration unverified against a real attestation.
