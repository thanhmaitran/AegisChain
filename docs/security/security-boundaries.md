# Security Boundaries

| Boundary | Enforced by | Where |
|---|---|---|
| Repository content -> engines | bounded reads, digest pinning, no links, no execution | `engines/ingestion/scanner.py` |
| Archive upload -> filesystem | `extract_archive` (names, links, sizes, count) | `infrastructure/archive.py` |
| Client -> server paths | no path parameters exist; policies by allow-listed name | `aegischain_api/services.py` |
| HTTP -> service | Pydantic schemas (`extra="forbid"`), UUID patterns, API key | `aegischain_api/schemas.py`, `dependencies.py` |
| Network -> OSV data | HTTPS-only transport, response size cap, schema checks | `infrastructure/http.py`, `osv_client.py` |
| Policy file -> policy | safe YAML, strict schema, 1 MiB cap | `engines/policy/parser/loader.py` |
| Process -> subprocess | `sigstore` invoked with an argument list, no shell, timeout | `signature_verifier.py` |
| Container | non-root, read-only FS, `cap_drop: ALL`, `no-new-privileges` | `docker-compose.yml` |
| CI | default `contents: read`; `id-token: write` only in the attest job | `.github/workflows/*.yml` |

**What AegisChain never does:** execute or import repository code, run package-manager commands,
download or install dependencies, open artifacts as anything other than a byte stream, or accept
filesystem paths from API clients.
