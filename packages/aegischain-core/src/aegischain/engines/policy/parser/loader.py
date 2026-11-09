"""Strict YAML policy loader. Unknown keys and invalid values are rejected."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml

from aegischain.domain.status import Severity, Status
from aegischain.engines.policy.models.policy import (
    DependencyPolicy,
    IntegrityPolicy,
    LicensePolicyConfig,
    ProvenancePolicy,
    SecurityPolicy,
    VulnerabilityPolicy,
    Waiver,
)
from aegischain.exceptions import PolicyError

MAX_POLICY_BYTES = 1024 * 1024


def _only(section: str, data: Any, allowed: set[str]) -> dict[str, Any]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PolicyError(f"'{section}' must be a mapping")
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"unknown key(s) in '{section}': {', '.join(sorted(map(str, unknown)))}")
    return data


def _bool(section: str, key: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"'{section}.{key}' must be true or false")
    return value


def _strings(section: str, key: str, value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"'{section}.{key}' must be a list of strings")
    return tuple(value)


def _severities(section: str, key: str, value: Any) -> tuple[Severity, ...]:
    out = []
    for item in _strings(section, key, value):
        try:
            out.append(Severity(item.upper()))
        except ValueError as exc:
            raise PolicyError(f"'{section}.{key}': unknown severity {item!r}") from exc
    return tuple(out)


def _status(section: str, key: str, value: Any, allowed: set[Status]) -> Status:
    try:
        status = Status(str(value).upper())
    except ValueError as exc:
        raise PolicyError(f"'{section}.{key}': invalid status {value!r}") from exc
    if status not in allowed:
        raise PolicyError(f"'{section}.{key}' must be one of {sorted(s.value for s in allowed)}")
    return status


def parse_policy(document: Any) -> SecurityPolicy:
    if not isinstance(document, dict):
        raise PolicyError("policy document must be a mapping with a top-level 'policy' key")
    root = _only("<root>", document, {"policy"})
    if not isinstance(root.get("policy"), dict):
        raise PolicyError(
            "'policy' must be a non-empty mapping (an empty policy is refused, not defaulted)"
        )
    body = _only(
        "policy",
        root.get("policy"),
        {
            "name",
            "version",
            "dependencies",
            "vulnerabilities",
            "licenses",
            "provenance",
            "integrity",
        },
    )
    name, version = body.get("name", "unnamed-policy"), str(body.get("version", "1"))
    if not isinstance(name, str) or not name:
        raise PolicyError("'policy.name' must be a non-empty string")

    dep = _only("dependencies", body.get("dependencies"), {"require_lockfile"})
    vul = _only(
        "vulnerabilities",
        body.get("vulnerabilities"),
        {
            "block_on",
            "warn_on",
            "fail_on_unfixed",
            "unfixed_min_severity",
            "on_unscanned",
            "waivers",
        },
    )
    lic = _only("licenses", body.get("licenses"), {"allowed", "denied", "unknown_license"})
    prov = _only(
        "provenance",
        body.get("provenance"),
        {
            "require_provenance",
            "require_verified_signature",
            "trusted_builders",
            "trusted_sources",
            "signer_identity",
            "oidc_issuer",
        },
    )
    integ = _only("integrity", body.get("integrity"), {"require_sha256"})

    waivers: list[Waiver] = []
    for w in vul.get("waivers", []) or []:
        w = _only("vulnerabilities.waivers[]", w, {"id", "justification", "expires"})
        if not w.get("id") or not w.get("justification"):
            raise PolicyError("every waiver needs 'id' and 'justification'")
        expires = w.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError as exc:
                raise PolicyError(f"waiver {w['id']}: 'expires' must be YYYY-MM-DD") from exc
        if not isinstance(expires, date):
            raise PolicyError(f"waiver {w['id']}: 'expires' is required (waivers must expire)")
        waivers.append(Waiver(str(w["id"]), str(w["justification"]), expires))

    defaults = VulnerabilityPolicy()
    return SecurityPolicy(
        name=name,
        version=version,
        dependencies=DependencyPolicy(
            _bool("dependencies", "require_lockfile", dep.get("require_lockfile", False))
        ),
        vulnerabilities=VulnerabilityPolicy(
            block_on=_severities("vulnerabilities", "block_on", vul["block_on"])
            if "block_on" in vul
            else defaults.block_on,
            warn_on=_severities("vulnerabilities", "warn_on", vul["warn_on"])
            if "warn_on" in vul
            else defaults.warn_on,
            fail_on_unfixed=_bool(
                "vulnerabilities", "fail_on_unfixed", vul.get("fail_on_unfixed", False)
            ),
            unfixed_min_severity=(
                _severities(
                    "vulnerabilities", "unfixed_min_severity", [vul["unfixed_min_severity"]]
                )[0]
                if "unfixed_min_severity" in vul
                else defaults.unfixed_min_severity
            ),
            on_unscanned=_status(
                "vulnerabilities",
                "on_unscanned",
                vul.get("on_unscanned", "INDETERMINATE"),
                {Status.INDETERMINATE, Status.WARN, Status.FAIL},
            ),
            waivers=tuple(waivers),
        ),
        licenses=LicensePolicyConfig(
            _strings("licenses", "allowed", lic.get("allowed")),
            _strings("licenses", "denied", lic.get("denied")),
            _status(
                "licenses",
                "unknown_license",
                lic.get("unknown_license", "WARN"),
                {Status.PASS, Status.WARN, Status.FAIL, Status.INDETERMINATE},
            ),
        ),
        provenance=ProvenancePolicy(
            _bool("provenance", "require_provenance", prov.get("require_provenance", False)),
            _bool(
                "provenance",
                "require_verified_signature",
                prov.get("require_verified_signature", False),
            ),
            _strings("provenance", "trusted_builders", prov.get("trusted_builders")),
            _strings("provenance", "trusted_sources", prov.get("trusted_sources")),
            prov.get("signer_identity"),
            prov.get("oidc_issuer"),
        ),
        integrity=IntegrityPolicy(
            _bool("integrity", "require_sha256", integ.get("require_sha256", False))
        ),
    )


def load_policy(path: Path) -> SecurityPolicy:
    try:
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyError("policy file exceeds the size limit")
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read policy: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}") from exc
    return parse_policy(document)
