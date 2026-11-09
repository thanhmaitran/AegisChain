"""Export the OpenAPI schema to docs/api/openapi.json (requires the `api` extra)."""

import json
from pathlib import Path

from aegischain_api.main import create_app
from aegischain_api.settings import Settings

settings = Settings(api_key="x" * 32, database_url="sqlite:///:memory:")
schema = create_app(settings).openapi()
out = Path("docs/api/openapi.json")
out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote {out}")
