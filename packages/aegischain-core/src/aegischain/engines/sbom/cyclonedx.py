"""CycloneDX 1.5 JSON adapter."""

from __future__ import annotations

import uuid
from typing import Any

from aegischain.engines.sbom.model import SBOMInput, license_expression

SPEC_VERSION = "1.5"
_HASH_ALG = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
_SCOPE = {"runtime": "required", "optional": "optional", "dev": "excluded"}


def root_ref(root_name: str) -> str:
    return f"root:{root_name}"


def generate_cyclonedx(sbom: SBOMInput) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for c in sbom.components:
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": c.purl,
            "name": c.name,
            "purl": c.purl,
            "scope": _SCOPE[c.scope.value],
            "properties": [
                {"name": "aegischain:direct", "value": str(c.direct).lower()},
                {"name": "aegischain:ecosystem", "value": c.ecosystem.value},
                {"name": "aegischain:scope", "value": c.scope.value},
            ],
        }
        if c.version is not None:  # never invent a version
            entry["version"] = c.version
        hashes = [
            {"alg": _HASH_ALG[a], "content": h}
            for a, h in sorted(c.hashes.items())
            if a in _HASH_ALG
        ]
        if hashes:
            entry["hashes"] = hashes
        expr = license_expression(c.declared_license)
        if expr is not None:
            entry["licenses"] = [{"expression": expr}]
        elif c.declared_license:
            entry["licenses"] = [{"license": {"name": c.declared_license}}]
        components.append(entry)

    root = root_ref(sbom.root_name)
    dependencies = [{"ref": root, "dependsOn": sorted(sbom.direct_purls)}]
    dependencies += [{"ref": c.purl, "dependsOn": sorted(c.dependencies)} for c in sbom.components]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, "aegischain:cdx:" + sbom.content_digest)),
        "version": 1,
        "metadata": {
            "timestamp": sbom.created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {"type": "application", "name": sbom.tool_name, "version": sbom.tool_version}
                ]
            },
            "component": {"type": "application", "bom-ref": root, "name": sbom.root_name},
        },
        "components": components,
        "dependencies": dependencies,
    }
