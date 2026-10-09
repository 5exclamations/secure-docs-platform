#!/usr/bin/env bash
# Generates a local .env with random secrets (and the Prometheus token file). Refuses to overwrite.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e .env ]]; then echo ".env already exists, not overwriting" >&2; exit 0; fi
rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(33))'; }
METRICS_TOKEN="$(rand)"
umask 077
cat > .env <<ENV
POSTGRES_PASSWORD=$(rand)
APP_DB_PASSWORD=$(rand)
REDIS_PASSWORD=$(rand)
MINIO_ROOT_USER=minio$(python3 -c 'import secrets; print(secrets.token_hex(4))')
MINIO_ROOT_PASSWORD=$(rand)
JWT_SECRET=$(rand)$(rand)
METRICS_TOKEN=${METRICS_TOKEN}
GRAFANA_ADMIN_PASSWORD=$(rand)
ENV
mkdir -p .secrets
chmod 755 .secrets      # traversable by the non-root Prometheus container (local dev only)
printf '%s' "${METRICS_TOKEN}" > .secrets/metrics_token
chmod 644 .secrets/metrics_token   # read by the (non-root) Prometheus container; local dev only
echo "Wrote .env and .secrets/metrics_token"
