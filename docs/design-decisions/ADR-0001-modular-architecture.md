# ADR-0001: Modular monolith with interface-separated engines

**Status:** accepted

## Context
Eight engines with clear responsibilities must be testable independently and reusable from a CLI,
an API and CI.

## Decision
One deployable process; each engine is a package that depends only on the domain layer and receives
collaborators (clock, HTTP transport, provider) by injection. FastAPI and the database sit outside
the core.

## Consequences
+ Simple deployment/debugging; fast tests (the full suite runs in under a second).
+ Engines can be extracted into services later because their contracts are already explicit.
- A defect in one engine shares a process with the others; the pipeline therefore converts engine
  crashes into `INDETERMINATE` evidence.
