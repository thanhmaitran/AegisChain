"""Structural SBOM validation and cross-format consistency checks.

This is NOT a replacement for the official JSON schemas. It verifies the
invariants AegisChain relies on (required fields, unique identifiers, referential
integrity). ``schema_validated`` is therefore always False; run an official
validator (e.g. ``cyclonedx-cli validate``, the SPDX online validator or
``pyspdxtools``) in CI for schema conformance.
"""

from __future__ import annotations

import re
from typing import Any

from aegischain.domain.models import SBOMValidationReport
from aegischain.engines.sbom import cyclonedx, spdx

_UUID_URN = re.compile(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def validate_cyclonedx(doc: dict[str, Any]) -> SBOMValidationReport:
    errors: list[str] = []
    checks = [
        "required-fields",
        "serial-number-format",
        "unique-bom-ref",
        "dependency-refs-exist",
        "purl-prefix",
        "hash-format",
    ]
    if doc.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    if doc.get("specVersion") != cyclonedx.SPEC_VERSION:
        errors.append(f"specVersion must be {cyclonedx.SPEC_VERSION}")
    if not _UUID_URN.match(str(doc.get("serialNumber", ""))):
        errors.append("serialNumber must be a urn:uuid")
    if not isinstance(doc.get("version"), int):
        errors.append("version must be an integer")
    if not _TS.match(str(doc.get("metadata", {}).get("timestamp", ""))):
        errors.append("metadata.timestamp must be UTC ISO-8601")
    refs: set[str] = set()
    root = doc.get("metadata", {}).get("component", {})
    if not root.get("bom-ref") or not root.get("name"):
        errors.append("metadata.component needs name and bom-ref")
    else:
        refs.add(root["bom-ref"])
    for comp in doc.get("components", []):
        ref = comp.get("bom-ref")
        if not comp.get("name") or not ref:
            errors.append(f"component missing name/bom-ref: {comp.get('name')!r}")
            continue
        if ref in refs:
            errors.append(f"duplicate bom-ref: {ref}")
        refs.add(ref)
        if not str(comp.get("purl", "")).startswith("pkg:"):
            errors.append(f"{ref}: purl must start with 'pkg:'")
        for h in comp.get("hashes", []):
            if not re.fullmatch(r"[0-9a-f]+", str(h.get("content", ""))):
                errors.append(f"{ref}: malformed hash content")
    for dep in doc.get("dependencies", []):
        if dep.get("ref") not in refs:
            errors.append(f"dependency ref not found: {dep.get('ref')}")
        for target in dep.get("dependsOn", []):
            if target not in refs:
                errors.append(f"dependsOn target not found: {target}")
    return SBOMValidationReport(
        "CycloneDX", cyclonedx.SPEC_VERSION, not errors, tuple(errors), tuple(checks)
    )


def validate_spdx(doc: dict[str, Any]) -> SBOMValidationReport:
    errors: list[str] = []
    checks = [
        "required-fields",
        "unique-spdxid",
        "relationship-refs-exist",
        "creation-info",
        "purl-external-ref",
        "document-describes",
    ]
    if doc.get("spdxVersion") != spdx.SPEC_VERSION:
        errors.append(f"spdxVersion must be {spdx.SPEC_VERSION}")
    if doc.get("dataLicense") != "CC0-1.0":
        errors.append("dataLicense must be CC0-1.0")
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        errors.append("SPDXID must be SPDXRef-DOCUMENT")
    if not doc.get("name"):
        errors.append("name is required")
    if not str(doc.get("documentNamespace", "")).startswith("https://"):
        errors.append("documentNamespace must be a URI")
    info = doc.get("creationInfo", {})
    if not _TS.match(str(info.get("created", ""))) or not info.get("creators"):
        errors.append("creationInfo requires created (UTC) and creators")
    ids: set[str] = {"SPDXRef-DOCUMENT"}
    for pkg in doc.get("packages", []):
        pid = pkg.get("SPDXID")
        if not pid or not re.fullmatch(r"SPDXRef-[A-Za-z0-9.\-]+", pid):
            errors.append(f"invalid SPDXID: {pid!r}")
            continue
        if pid in ids:
            errors.append(f"duplicate SPDXID: {pid}")
        ids.add(pid)
        for key in ("name", "downloadLocation"):
            if not pkg.get(key):
                errors.append(f"{pid}: {key} is required")
        if pid != spdx.ROOT_ID and not any(
            r.get("referenceType") == "purl" for r in pkg.get("externalRefs", [])
        ):
            errors.append(f"{pid}: missing purl external reference")
    described = False
    for rel in doc.get("relationships", []):
        for side in ("spdxElementId", "relatedSpdxElement"):
            if rel.get(side) not in ids:
                errors.append(f"relationship references unknown id: {rel.get(side)}")
        if rel.get("relationshipType") == "DESCRIBES":
            described = True
    if not described:
        errors.append("document must DESCRIBE a root package")
    return SBOMValidationReport("SPDX", spdx.SPEC_VERSION, not errors, tuple(errors), tuple(checks))


def cross_check(cdx: dict[str, Any], spdx_doc: dict[str, Any]) -> SBOMValidationReport:
    """Both documents must describe the same component set and dependency edges."""
    errors: list[str] = []
    cdx_purls = {c["purl"] for c in cdx.get("components", [])}
    id_to_purl: dict[str, str] = {}
    for p in spdx_doc.get("packages", []):
        for ref in p.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                id_to_purl[p["SPDXID"]] = ref["referenceLocator"]
    spdx_purls = set(id_to_purl.values())
    for missing in sorted(cdx_purls - spdx_purls):
        errors.append(f"present in CycloneDX only: {missing}")
    for missing in sorted(spdx_purls - cdx_purls):
        errors.append(f"present in SPDX only: {missing}")
    cdx_edges = {
        (d["ref"], t)
        for d in cdx.get("dependencies", [])
        if d["ref"] in cdx_purls
        for t in d.get("dependsOn", [])
    }
    spdx_edges = {
        (id_to_purl[r["spdxElementId"]], id_to_purl[r["relatedSpdxElement"]])
        for r in spdx_doc.get("relationships", [])
        if r.get("relationshipType") == "DEPENDS_ON"
        and r["spdxElementId"] in id_to_purl
        and r["relatedSpdxElement"] in id_to_purl
    }
    for edge in sorted(cdx_edges ^ spdx_edges):
        errors.append(f"dependency edge differs between formats: {edge[0]} -> {edge[1]}")
    return SBOMValidationReport(
        "CycloneDX<->SPDX",
        f"{cyclonedx.SPEC_VERSION}/{spdx.SPEC_VERSION}",
        not errors,
        tuple(errors),
        ("component-set-equal", "dependency-edges-equal"),
    )
