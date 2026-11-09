# 08 - Final Engineering Report

## Objectives
Build an engineering-grade software supply chain security platform: dependency intelligence, SBOMs,
vulnerability and license analysis, artifact integrity/provenance verification and a deterministic
policy decision, delivered through a CLI, API and dashboard, with evidence for every claim.

## Architecture and implementation
Eight engines behind Protocols, one orchestrating pipeline, thin delivery layers (see report 01).
About 5,300 lines of Python in the core and API, about 2,200 lines of Python tests (203 passing
tests, 3 skipped for missing optional dependencies) and a 720-line TypeScript dashboard.

## Engineering challenges
* **Fail-safe semantics.** Four-state decisions with `worst([]) == INDETERMINATE`; every external
  failure maps to INDETERMINATE; policy parsing is strict (empty policy refused).
* **Not inventing data.** Versions, hashes, licenses and transitive edges appear only with evidence.
* **Hostile input.** No links, no execution, bounded reads/extraction, digest pinning between
  ingestion and parsing, linear-time graph algorithms.
* **Working without network.** The core depends on three small libraries; the OSV client takes an
  injected transport so every failure mode is testable offline.

## Experimental results
See `docs/evaluation/` and `reports/final/evaluation-summary.md`: all engine evaluations match
ground truth; near-linear scaling to 10,000 components.

## Security evaluation
Threat model with 15 threats and tested controls (report 02). Three real defects were found by the
test suite during development and fixed with regression tests.

## Limitations
Consolidated in `docs/security/limitations.md`. Most important: the HTTP layer, PostgreSQL
repository, dashboard, Docker/CI definitions and Sigstore integration were written but not executed
in the development sandbox; no real-world repository study; single shared API key.

## Future development
Official CycloneDX library + JSON-schema validation in the product; SPDX 3.0 adapter; pnpm/yarn/Go/
Cargo parsers; reachability-aware prioritisation; per-user auth and rate limiting; async analysis
queue; study on labelled real repositories; verified Sigstore/`slsa-verifier` end-to-end tests.
