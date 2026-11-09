# ADR-0006: Deterministic policy evaluation with four states

**Status:** accepted

## Decision
`evaluate_policy(evidence, policy)` is a pure function (clock only through `evidence.as_of`).
Rules map evidence to `RuleResult`s per engine; the engine status is the worst rule status; the
final status is the worst engine status with precedence `FAIL > INDETERMINATE > WARN > PASS`.

* Missing/unverifiable evidence is `INDETERMINATE` if the policy requires it, else `WARN`.
* Engines that are not required and have no evidence are shown as `PASS` with `evaluated: false`
  so the dashboard can say "not required" rather than imply a check ran.
* Policies are strict YAML: unknown keys, invalid enums, `on_unscanned: PASS` and waivers without an
  expiry are errors. An empty policy file is refused rather than defaulted.
* Waivers expire (`expires` is mandatory) and may match an OSV id or any alias.

## Consequences
Stored evidence can be re-evaluated under another policy without network access (`POST
/api/v1/policies/evaluate`), and property tests assert order independence and monotonicity.
