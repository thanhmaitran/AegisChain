# API Reference

Base path `/api/v1`. All routes require the header `X-API-Key: <key>` (see
`AEGISCHAIN_API_KEY`). Interactive documentation is served at `/docs` and the schema at
`/openapi.json`; regenerate `docs/api/openapi.json` with `make openapi`.

`GET /health` is unauthenticated and returns `{"status": "ok"}`.

| Method | Endpoint | Purpose | Body / query |
|---|---|---|---|
| POST | `/projects` | Create a project | JSON `{"name": "my-app"}` (letters, digits, space, `._-`) |
| GET | `/projects` | List projects | - |
| GET | `/projects/{id}/runs` | List analysis runs of a project | - |
| POST | `/analysis` | Upload a repository archive and analyse it | multipart: `project_id`, `archive` (zip/tar/tar.gz/bz2/xz), optional `policy` (name), `include_dev` |
| GET | `/analysis/{run_id}` | Run summary and policy evaluation | - |
| GET | `/dependencies/{run_id}` | Component inventory, findings, graph payload | - |
| GET | `/sbom/{run_id}` | Stored SBOM | `?format=cyclonedx\|spdx` |
| GET | `/vulnerabilities/{run_id}` | Vulnerability report (matches, severity source, lookup status) | - |
| GET | `/provenance/{run_id}` | Integrity and provenance evidence of the run | - |
| POST | `/artifacts/verify` | Verify an uploaded artifact | multipart: `artifact`, optional `expected_sha256`, `policy`, `provenance`, `signature_bundle` |
| GET | `/policies` | Names of server-side policies | - |
| POST | `/policies/evaluate` | Re-evaluate a run's stored evidence under another policy | JSON `{"run_id": "<uuid>", "policy": "<name>"}` |
| GET | `/reports/{run_id}` | Audit report | `?format=json\|markdown` |

## Status codes

| Code | Meaning |
|---|---|
| 201 | Created (project, analysis) |
| 400 | Unsafe or unsupported archive |
| 401 | Missing/invalid API key |
| 404 | Unknown id |
| 409 | Duplicate project name / missing parent |
| 413 | Request body too large |
| 422 | Validation error (bad id format, unknown policy, oversized upload, schema violations) |

## Security notes

* Clients never provide filesystem paths. Uploads are spooled to a private temporary directory and
  removed afterwards; upload file names are ignored.
* Policies are selected by **name** from a server-side directory.
* Every response carries `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Cache-Control: no-store` and a restrictive `Content-Security-Policy`.
* An analysis decision of `INDETERMINATE` is returned with HTTP 201: the request succeeded; the
  *evidence* was insufficient.

## Example

```bash
curl -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
     -d '{"name":"demo"}' http://localhost:8000/api/v1/projects
curl -H "X-API-Key: $KEY" -F project_id=<uuid> -F policy=production-release \
     -F archive=@repo.zip http://localhost:8000/api/v1/analysis
```
