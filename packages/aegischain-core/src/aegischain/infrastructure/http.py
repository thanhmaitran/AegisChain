"""Minimal HTTP transport abstraction (stdlib only, injectable for tests)."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Protocol

MAX_RESPONSE_BYTES = 20 * 1024 * 1024


class Transport(Protocol):
    def request(
        self, method: str, url: str, body: bytes | None, timeout: float
    ) -> tuple[int, bytes]: ...


class UrllibTransport:
    """HTTPS-only transport. Redirects to non-HTTPS targets are refused."""

    def request(
        self, method: str, url: str, body: bytes | None, timeout: float
    ) -> tuple[int, bytes]:
        if not url.startswith("https://"):
            raise ValueError("only https:// URLs are permitted")
        req = urllib.request.Request(  # noqa: S310 - scheme validated above
            url,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", "User-Agent": "aegischain/0.1"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.status, resp.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(MAX_RESPONSE_BYTES)
