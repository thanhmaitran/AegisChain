"""OSV.dev API client: batch queries, pagination, retries and timeouts.

API reference: https://google.github.io/osv.dev/api/
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import quote

from aegischain.exceptions import ProviderError
from aegischain.infrastructure.http import Transport, UrllibTransport

OSV_BATCH_LIMIT = 1000
_MAX_PAGES = 20


class OsvClient:
    def __init__(
        self,
        transport: Transport | None = None,
        base_url: str = "https://api.osv.dev",
        timeout: float = 20.0,
        max_retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        batch_size: int = OSV_BATCH_LIMIT,
    ) -> None:
        if not 0 < batch_size <= OSV_BATCH_LIMIT:
            raise ValueError("batch_size must be between 1 and 1000")
        self._transport = transport or UrllibTransport()
        self._base = base_url.rstrip("/")
        self._timeout, self._retries, self._backoff = timeout, max_retries, backoff
        self._sleep, self._batch_size = sleep, batch_size

    # -- low level ------------------------------------------------------------
    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = json.dumps(body).encode() if body is not None else None
        last = "no attempt made"
        for attempt in range(self._retries + 1):
            if attempt:
                self._sleep(self._backoff * 2 ** (attempt - 1))
            try:
                status, data = self._transport.request(
                    method, self._base + path, payload, self._timeout
                )
            except (OSError, TimeoutError, ValueError) as exc:
                last = f"transport error: {exc}"
                continue
            if status == 200:
                try:
                    parsed = json.loads(data)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ProviderError(f"OSV returned malformed JSON for {path}") from exc
                if not isinstance(parsed, dict):
                    raise ProviderError(f"OSV returned a non-object response for {path}")
                return parsed
            if status == 429 or status >= 500:
                last = f"HTTP {status}"
                continue
            raise ProviderError(f"OSV request {path} failed with HTTP {status}")
        raise ProviderError(
            f"OSV request {path} failed after {self._retries + 1} attempts ({last})"
        )

    # -- public API -----------------------------------------------------------
    def query_batch(self, packages: Sequence[tuple[str, str, str]]) -> list[list[dict[str, Any]]]:
        """``packages`` are (name, ecosystem, version). Returns [{"id","modified"}, ...] per package."""
        results: list[list[dict[str, Any]]] = []
        for start in range(0, len(packages), self._batch_size):
            chunk = packages[start : start + self._batch_size]
            queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for n, e, v in chunk]
            response = self._request("POST", "/v1/querybatch", {"queries": queries})
            items = response.get("results")
            if not isinstance(items, list) or len(items) != len(chunk):
                raise ProviderError("OSV batch response does not match the request")
            for query, item in zip(queries, items, strict=True):
                results.append(self._collect(query, item))
        return results

    def _collect(self, query: dict[str, Any], item: Any) -> list[dict[str, Any]]:
        if not isinstance(item, dict):
            raise ProviderError("OSV batch result is not an object")
        vulns: list[dict[str, Any]] = []
        pages = 0
        while True:
            for v in item.get("vulns", []) or []:
                if not isinstance(v, dict) or not isinstance(v.get("id"), str):
                    raise ProviderError("OSV result contains a malformed vulnerability stub")
                vulns.append(v)
            token = item.get("next_page_token")
            if not token:
                return vulns
            pages += 1
            if pages > _MAX_PAGES:
                raise ProviderError("OSV pagination exceeded the page limit")
            follow = self._request(
                "POST", "/v1/querybatch", {"queries": [{**query, "page_token": token}]}
            )
            results = follow.get("results")
            if (
                not isinstance(results, list)
                or len(results) != 1
                or not isinstance(results[0], dict)
            ):
                raise ProviderError("OSV pagination response is malformed")
            item = results[0]

    def get_vulnerability(self, osv_id: str) -> dict[str, Any]:
        record = self._request("GET", f"/v1/vulns/{quote(osv_id, safe='')}")
        if record.get("id") != osv_id:
            raise ProviderError(
                f"OSV returned a record for a different id than requested: {osv_id}"
            )
        return record
