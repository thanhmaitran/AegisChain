# ADR-0007: Standard-library dataclasses in the core, Pydantic at the API boundary

**Status:** accepted (deviation from the original stack proposal)

## Context
The roadmap proposed Pydantic models throughout. The core's models are internal, immutable
evidence records that are serialised canonically and compared for equality.

## Decision
Use frozen `dataclasses` in the core (zero runtime dependencies beyond `networkx`, `packaging`,
`PyYAML`) with explicit validation at the trust boundaries (parsers, policy loader, archive
extraction, OSV client). Use Pydantic only for HTTP request/response validation in `apps/api`.

## Consequences
+ The whole core test suite runs without network or heavy dependencies; fewer supply-chain
  dependencies in a supply-chain security tool.
+ Frozen dataclasses give cheap immutability and hashing semantics.
- Validation is hand-written where Pydantic would generate it; `from_jsonable` provides the
  inverse of serialisation.
