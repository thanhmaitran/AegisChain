"""Deterministic decision engine: aggregate rule results into a final decision."""

from __future__ import annotations

from collections.abc import Sequence

from aegischain.domain.models import EngineDecision, PolicyEvaluation, RuleResult
from aegischain.domain.status import Status, worst
from aegischain.engines.policy.models.policy import SecurityEvidence, SecurityPolicy
from aegischain.engines.policy.rules import rules as R

ENGINE_ORDER = (R.DEPENDENCY, R.SBOM, R.VULN, R.LICENSE, R.INTEGRITY, R.PROVENANCE)


def _decision(engine: str, rules: Sequence[RuleResult], evaluated: bool = True) -> EngineDecision:
    return EngineDecision(engine, worst(r.status for r in rules), evaluated, tuple(rules))


def evaluate_policy(evidence: SecurityEvidence, policy: SecurityPolicy) -> PolicyEvaluation:
    """Pure function: identical evidence + policy + ``as_of`` always give the same result."""
    integrity_rules, integrity_eval = R.integrity_rules(evidence.integrity, policy)
    prov_rules, prov_eval = R.provenance_rules(evidence.provenance, policy)
    engines = (
        _decision(
            R.DEPENDENCY, R.dependency_rules(evidence.dependency, evidence.ingestion, policy)
        ),
        _decision(R.SBOM, R.sbom_rules(evidence.sbom_validation)),
        _decision(R.VULN, R.vulnerability_rules(evidence.vulnerability, policy, evidence.as_of)),
        _decision(R.LICENSE, R.license_rules(evidence.licenses, policy)),
        _decision(R.INTEGRITY, integrity_rules, integrity_eval),
        _decision(R.PROVENANCE, prov_rules, prov_eval),
    )
    final = worst(e.status for e in engines)
    reasons = tuple(
        f"[{e.engine}] {r.message}" for e in engines for r in e.rules if r.status is not Status.PASS
    )
    return PolicyEvaluation(policy.name, policy.version, evidence.as_of, engines, final, reasons)
