"""SPDX 2.3 JSON adapter (SPDX 2.3 has the widest tooling support today)."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from aegischain.engines.sbom.model import SBOMInput, license_expression, safe_id

SPEC_VERSION = "SPDX-2.3"
_ALG = {"sha1": "SHA1", "sha256": "SHA256", "sha384": "SHA384", "sha512": "SHA512"}
ROOT_ID = "SPDXRef-RootPackage"


def spdx_id(purl: str, name: str) -> str:
    return f"SPDXRef-Package-{safe_id(name)}-{hashlib.sha1(purl.encode()).hexdigest()[:8]}"  # noqa: S324


def generate_spdx(sbom: SBOMInput) -> dict[str, Any]:
    ids = {c.purl: spdx_id(c.purl, c.name) for c in sbom.components}
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": ROOT_ID,
            "name": sbom.root_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
    ]
    for c in sbom.components:
        pkg: dict[str, Any] = {
            "SPDXID": ids[c.purl],
            "name": c.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }
            ],
        }
        if c.version is not None:
            pkg["versionInfo"] = c.version
        expr = license_expression(c.declared_license)
        pkg["licenseDeclared"] = expr if expr is not None else "NOASSERTION"
        if expr is None and c.declared_license:
            pkg["licenseComments"] = (
                f"Declared value could not be parsed as SPDX: {c.declared_license!r}"
            )
        checks = [
            {"algorithm": _ALG[a], "checksumValue": h}
            for a, h in sorted(c.hashes.items())
            if a in _ALG
        ]
        if checks:
            pkg["checksums"] = checks
        packages.append(pkg)

    rels: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ROOT_ID,
        }
    ]
    rels += [
        {"spdxElementId": ROOT_ID, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ids[p]}
        for p in sorted(sbom.direct_purls)
    ]
    for c in sbom.components:
        rels += [
            {
                "spdxElementId": ids[c.purl],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ids[d],
            }
            for d in sorted(c.dependencies)
            if d in ids
        ]
    token = str(uuid.uuid5(uuid.NAMESPACE_URL, "aegischain:spdx:" + sbom.content_digest))
    return {
        "spdxVersion": SPEC_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{sbom.root_name}-sbom",
        "documentNamespace": f"https://aegischain.invalid/spdx/{safe_id(sbom.root_name)}-{token}",
        "creationInfo": {
            "created": sbom.created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [f"Tool: {sbom.tool_name}-{sbom.tool_version}"],
        },
        "packages": packages,
        "relationships": rels,
    }
