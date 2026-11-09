FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY apps/api ./apps/api
RUN pip install ".[api,security]" ./apps/api
COPY configs ./configs
COPY database ./database
# Run as an unprivileged user; analysis workspaces live in /tmp (tmpfs in compose).
RUN useradd --system --uid 10001 --no-create-home aegis && mkdir -p /data && chown aegis /data
USER aegis
ENV AEGISCHAIN_POLICY_DIR=/app/configs/policies AEGISCHAIN_OSV_CACHE_DIR=/data/osv-cache
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["uvicorn", "aegischain_api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
