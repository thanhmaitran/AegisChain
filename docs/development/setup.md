# Development Setup

Requirements: Python 3.12+, Node.js 22+ (dashboard), Docker (optional).

```bash
python -m venv .venv
source .venv/bin/activate            # PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[api,security,dev]" -e apps/api
python -m pip check
make fix          # one-time: apply ruff formatting / import ordering
make check        # lint + type check + tests
```

Check your interpreter first (Windows): `py --list` then `py -3.12 -m venv .venv`. Avoid a default
Python that is newer than the dependencies support.

## Run the CLI

```bash
aegischain analyze examples/python-project --offline --out artifacts
aegischain analyze examples/node-project --osv-cache .osv-cache --policy configs/policies/default.yaml
```

Exit codes: `0` PASS/WARN, `1` FAIL (or WARN with `--strict`), `2` INDETERMINATE, `3` usage error.

## Run the API and dashboard

```bash
export AEGISCHAIN_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
uvicorn aegischain_api.main:create_app --factory --reload      # http://localhost:8000/docs
cd apps/web && npm ci && npm run dev                           # http://localhost:5173
```

## Docker Compose

```bash
cp .env.example .env     # set POSTGRES_PASSWORD and AEGISCHAIN_API_KEY
docker compose up --build   # dashboard on http://localhost:8080
```

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `AEGISCHAIN_API_KEY` | required (>=16 chars) | API key for all `/api/v1` routes |
| `AEGISCHAIN_DATABASE_URL` | `sqlite:///./aegischain.db` | `postgresql+psycopg://...` in production |
| `AEGISCHAIN_POLICY_DIR` | `configs/policies` | Named policies available to clients |
| `AEGISCHAIN_OSV_CACHE_DIR` | none | Persistent OSV record cache |
| `AEGISCHAIN_MAX_UPLOAD_BYTES` | 52428800 | Upload size limit |
| `AEGISCHAIN_CORS_ORIGINS` | empty | Comma-separated origins (empty = none) |
| `AEGISCHAIN_OFFLINE` | false | Skip OSV (all analyses become INDETERMINATE) |
