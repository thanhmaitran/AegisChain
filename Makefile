.PHONY: install test lint fix typecheck cov bench evaluate openapi web docker-up docker-down check

PY ?= python

install:
	$(PY) -m pip install -e ".[api,security,dev]" -e apps/api
	$(PY) -m pip check

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

fix:
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

typecheck:
	$(PY) -m mypy packages/aegischain-core/src apps/api/src

cov:
	$(PY) -m pytest --cov --cov-report=term-missing

bench:
	$(PY) benchmarks/run_benchmarks.py

evaluate:
	$(PY) benchmarks/run_evaluation.py

openapi:
	$(PY) scripts/export_openapi.py

web:
	cd apps/web && npm ci && npm run build

docker-up:
	docker compose up --build

docker-down:
	docker compose down

check: lint typecheck test
