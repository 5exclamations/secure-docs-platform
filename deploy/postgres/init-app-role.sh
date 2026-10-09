#!/bin/bash
# Runs once on first start of the postgres container. Creates the runtime role the API uses.
# The role cannot own tables, is not a superuser and has no BYPASSRLS, so row level security
# policies always apply to it. Migrations run as the (owner) POSTGRES_USER instead.
set -euo pipefail
psql -v ON_ERROR_STOP=1 -v app_pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE docs_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT CONNECT ON DATABASE docs TO docs_app;
SQL
