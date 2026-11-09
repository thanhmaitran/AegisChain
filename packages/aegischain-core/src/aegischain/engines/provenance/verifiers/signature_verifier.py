"""Signature verification backends.

AegisChain never implements signature cryptography itself. The default backend
delegates to the official ``sigstore`` client (keyless verification: signature,
certificate chain, transparency log and signer identity are all checked by it).
"""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 - invoked with an argument list, never a shell
from pathlib import Path

from aegischain.domain.models import Check
from aegischain.domain.status import Status

CHECK_NAME = "sigstore_signature"
_TIMEOUT_SECONDS = 120


class SigstoreCliVerifier:
    def __init__(self, executable: str = "sigstore") -> None:
        self._exe = executable

    def verify(
        self, artifact: Path, bundle: Path, identity: str | None, issuer: str | None
    ) -> Check:
        if not identity or not issuer:
            return Check(
                CHECK_NAME,
                Status.INDETERMINATE,
                "No expected signer identity/OIDC issuer configured; a signature cannot be trusted without them",
            )
        exe = shutil.which(self._exe)
        if exe is None:
            return Check(
                CHECK_NAME,
                Status.INDETERMINATE,
                "The 'sigstore' client is not installed (pip install 'aegischain[security]')",
            )
        cmd = [
            exe,
            "verify",
            "identity",
            "--bundle",
            str(bundle),
            "--cert-identity",
            identity,
            "--cert-oidc-issuer",
            issuer,
            str(artifact),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False
            )  # noqa: S603
        except subprocess.TimeoutExpired:
            return Check(CHECK_NAME, Status.INDETERMINATE, "Sigstore verification timed out")
        except OSError as exc:
            return Check(
                CHECK_NAME,
                Status.INDETERMINATE,
                f"Sigstore client could not be run: {exc.strerror}",
            )
        if proc.returncode == 0:
            return Check(
                CHECK_NAME,
                Status.PASS,
                "Sigstore verified signature, certificate chain, transparency log entry and signer identity",
            )
        message = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
        # Only an explicit verification failure is a FAIL; infrastructure errors stay INDETERMINATE.
        if "fail" in message[0].lower() and "verif" in message[0].lower():
            return Check(
                CHECK_NAME, Status.FAIL, f"Sigstore verification failed: {message[0][:200]}"
            )
        return Check(
            CHECK_NAME,
            Status.INDETERMINATE,
            f"Sigstore client error (exit {proc.returncode}): {message[0][:200]}",
        )


class UnavailableSignatureVerifier:
    """Used when no backend is configured: signatures are reported as unverified."""

    def verify(
        self, artifact: Path, bundle: Path, identity: str | None, issuer: str | None
    ) -> Check:
        return Check(
            CHECK_NAME, Status.INDETERMINATE, "No signature verification backend configured"
        )


class StaticSignatureVerifier:
    """Test double returning a preset result."""

    def __init__(self, status: Status, detail: str = "static result") -> None:
        self._check = Check(CHECK_NAME, status, detail)

    def verify(
        self, artifact: Path, bundle: Path, identity: str | None, issuer: str | None
    ) -> Check:
        return self._check
