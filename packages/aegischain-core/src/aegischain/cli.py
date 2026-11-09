"""Command line interface: ``aegischain analyze | verify-artifact | validate-policy``.

Exit codes: 0 PASS/WARN, 1 FAIL (or WARN with --strict), 2 INDETERMINATE, 3 usage/input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegischain import __version__
from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.application.report import render_markdown, write_outputs
from aegischain.domain.interfaces import VulnerabilityProvider
from aegischain.domain.status import Status
from aegischain.engines.integrity.hasher import verify_artifact
from aegischain.engines.policy import SecurityPolicy, load_policy
from aegischain.engines.provenance.verifiers.signature_verifier import SigstoreCliVerifier
from aegischain.engines.vulnerability.provider import OsvProvider, SkippedVulnerabilityProvider
from aegischain.exceptions import AegisChainError
from aegischain.infrastructure.cache import VulnerabilityCache
from aegischain.infrastructure.osv_client import OsvClient
from aegischain.utils.logging import configure_logging
from aegischain.utils.serialization import pretty_json

_EXIT = {Status.PASS: 0, Status.WARN: 0, Status.FAIL: 1, Status.INDETERMINATE: 2}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegischain", description="Software supply chain security analysis"
    )
    p.add_argument("--version", action="version", version=f"aegischain {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="emit structured logs to stderr")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyse a repository directory")
    a.add_argument("path", type=Path)
    a.add_argument(
        "--policy", type=Path, help="YAML policy file (default: built-in default policy)"
    )
    a.add_argument("--out", type=Path, help="write SBOMs and reports into this directory")
    a.add_argument(
        "--offline", action="store_true", help="skip OSV lookups (result will be INDETERMINATE)"
    )
    a.add_argument("--osv-cache", type=Path, help="directory for the OSV record cache")
    a.add_argument("--no-dev", action="store_true", help="exclude development dependencies")
    a.add_argument("--artifact", type=Path, help="build artifact to verify")
    a.add_argument("--expected-sha256", help="trusted reference digest for --artifact")
    a.add_argument(
        "--provenance",
        type=Path,
        help="SLSA provenance (statement, DSSE envelope or Sigstore bundle)",
    )
    a.add_argument("--signature-bundle", type=Path, help="Sigstore bundle for --artifact")
    a.add_argument(
        "--license-evidence", type=Path, help='JSON object {"<purl>": "<SPDX expression>"}'
    )
    a.add_argument("--format", choices=("markdown", "json"), default="markdown")
    a.add_argument("--strict", action="store_true", help="exit 1 on WARN as well")

    v = sub.add_parser(
        "verify-artifact", help="hash an artifact and compare it with a reference digest"
    )
    v.add_argument("artifact", type=Path)
    v.add_argument("--expected-sha256")

    c = sub.add_parser("validate-policy", help="validate a policy file")
    c.add_argument("policy", type=Path)
    return p


def _load_license_evidence(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    if path.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("license evidence file is too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise ValueError("license evidence must be a JSON object of string pairs")
    return data


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.verbose:
        configure_logging()
    try:
        if args.command == "validate-policy":
            policy = load_policy(args.policy)
            print(f"Policy '{policy.name}' v{policy.version} is valid.")
            return 0
        if args.command == "verify-artifact":
            result = verify_artifact(args.artifact, args.expected_sha256)
            print(pretty_json(result), end="")
            return _EXIT[result.status]

        policy = load_policy(args.policy) if args.policy else SecurityPolicy()
        provider: VulnerabilityProvider
        if args.offline:
            provider = SkippedVulnerabilityProvider()
        else:
            provider = OsvProvider(OsvClient(), VulnerabilityCache(args.osv_cache))
        pipeline = AnalysisPipeline(provider, SigstoreCliVerifier())
        output = pipeline.run(
            AnalysisRequest(
                root_path=args.path,
                policy=policy,
                include_dev_dependencies=not args.no_dev,
                artifact_path=args.artifact,
                expected_sha256=args.expected_sha256,
                provenance_path=args.provenance,
                signature_bundle_path=args.signature_bundle,
                license_evidence=_load_license_evidence(args.license_evidence),
            )
        )
    except (AegisChainError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.out:
        write_outputs(output, args.out)
    report = output.report
    print(pretty_json(report) if args.format == "json" else render_markdown(report), end="")
    if args.strict and report.decision is Status.WARN:
        return 1
    return _EXIT[report.decision]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
