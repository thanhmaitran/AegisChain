# Examples

* `python-project/` - `pyproject.toml` + `poetry.lock` (13 components, 4 direct).
* `node-project/` - `package.json` + `package-lock.json` v3 with nested duplicate versions.
* `sample-policies/` - `production-release.yaml` (strict, fail-closed) and `permissive.yaml`.

These are **synthetic fixtures**: hashes/integrity values are derived from package names and are not
real registry digests. They contain no claims about real vulnerabilities.

```bash
aegischain analyze examples/python-project --offline --out artifacts
aegischain analyze examples/node-project --policy examples/sample-policies/production-release.yaml --offline
```
