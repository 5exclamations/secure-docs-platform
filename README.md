# Secure Document Platform

A multi-tenant document management API built to be reviewed: tenant isolation enforced at four layers, short-lived signed downloads, expiring sharing, an append-only audit trail, and the infrastructure, pipelines and runbooks around it.

**Stack:** Python 3.12, FastAPI, SQLAlchemy 2 (async), PostgreSQL 16, Redis 7, S3-compatible storage (MinIO locally, S3 on AWS), Docker Compose, Terraform (AWS), GitHub Actions, Prometheus, Grafana, OpenTelemetry, pytest.

![Swagger UI of the running API](docs/img/swagger-ui.png)

## Try it

```bash
make secrets                 # random local secrets into .env (git-ignored)
docker compose up --build -d # API, Postgres, Redis, MinIO, Prometheus, Grafana, Jaeger
python scripts/demo.py --base-url http://localhost:8000
```

No cloud account is needed. Open `http://localhost:8000/docs` for the interactive API. Details and ports are in [docs/deployment.md](docs/deployment.md). The first build compiles MinIO from source because the project no longer publishes container images.

A real run of the demo walkthrough (captured against the API with a MinIO server behind it; full text in [docs/demo-output.txt](docs/demo-output.txt)):

![Demo run](docs/img/demo-run.png)

Direct API usage:

```bash
curl -s localhost:8000/api/v1/auth/register -H 'content-type: application/json' -d '{
  "organization_name":"Acme","organization_slug":"acme",
  "email":"admin@acme.example","password":"correct-horse-battery-9"}'
TOKEN=$(curl -s localhost:8000/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@acme.example","password":"correct-horse-battery-9"}' | jq -r .access_token)
curl -s localhost:8000/api/v1/documents -H "Authorization: Bearer $TOKEN" \
  -F file=@contract.pdf -F title="Merger contract" -F tags=legal,confidential
curl -s localhost:8000/api/v1/documents/<id>/download -H "Authorization: Bearer $TOKEN"   # signed URL, 60 s
```

## What it does

| Area | Behaviour |
|---|---|
| Tenancy | Organizations own their users, documents, grants, share links and audit log. Registering creates an organization and its first admin; admins invite users. |
| Auth | Argon2id passwords with a policy, JWT access (15 min) and refresh (7 d) tokens, OAuth2 password and refresh grants at `/auth/token`, rotation with replay detection, logout, optional RS256 with JWKS and discovery documents. |
| Authorization | Roles (admin, editor, viewer) intersected with per-document relationships (owner or grant). Grants can expire. |
| Documents | Upload, versioned history, metadata and tags, full-text search over title and description, pagination, soft delete, admin hard delete that removes the objects. |
| Downloads | Short-lived presigned URLs straight from object storage; the API never proxies file bytes. SHA-256 returned with each download. |
| Sharing | Per-user grants with expiry, and public share links with mandatory expiry, optional download cap and revocation. |
| Audit | Authentication, access, sharing, administrative changes and authorization denials; append-only at the database level. |
| Operations | JSON logs with request and trace ids, Prometheus metrics, OpenTelemetry traces, liveness and readiness probes, alert rules, Grafana dashboard. |

## Security design in brief

* **Four-layer tenant isolation**: organization-scoped queries, composite foreign keys, PostgreSQL row level security bound per transaction, and a token claim cross-check. Foreign ids answer 404, indistinguishable from missing ones.
* **Least privilege everywhere**: the API connects as a role that is neither owner, superuser nor `BYPASSRLS`; the audit table is append-only even for its owner; the EC2 role reaches one bucket, one key, three secrets and one repository; no SSH, IMDSv2 only.
* **Sessions**: refresh tokens are single-use. A replayed token kills its whole session family and raises an alert.
* **Uploads**: streamed size cap, type allowlist with magic-byte verification, sanitized names, random object keys, attachment-only downloads.
* **Abuse controls**: Redis rate limits (5 logins/min/IP, 100 requests/min/user, public link endpoint limited), per-account lockout, trusted-proxy aware client address, fail-closed behaviour when Redis is down.
* **Supply chain and scanning in CI**: Ruff, mypy strict, Bandit, Semgrep, pip-audit, Trivy (filesystem, IaC, image), gitleaks, CodeQL, Checkov, Dependabot.

Read more: [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [controls matrix](docs/security-controls.md), [infrastructure and costs](docs/infrastructure.md), [deployment](docs/deployment.md), [incident response runbook](docs/runbooks/incident-response.md).

## Verification status

Everything in this table was run while building the repository.

| Check | Result |
|---|---|
| Test suite on PostgreSQL 16 + Redis 7 + moto S3 | 108 passed, 1 skipped (the skip needs a real S3 server) |
| Same suite on a real MinIO server built from source | 109 passed, including presigned URL expiry and tampered-signature rejection |
| Coverage of `app/` | 93.8 percent (CI gate: 80) |
| Security-focused tests | tenant isolation (13 scenarios), RBAC and expiring grants, share links (expired, revoked, capped, concurrent), forged and expired tokens, refresh replay, upload attacks, header and CORS checks, RLS and append-only audit at the database level, concurrent uploads, downloads and grants |
| ruff, mypy `--strict` | clean |
| Bandit, Semgrep (python, OWASP, jwt packs), pip-audit | no findings |
| Terraform | `fmt` and `validate` pass; Checkov 258 passed, 0 failed, 17 documented skips |
| End-to-end demo through `uvicorn` | all checks passed |

**Not exercised here, and not claimed:** nothing was deployed to AWS (Terraform was validated and policy-scanned, never planned or applied); the Docker images and `docker compose up` were not built or run because the sandbox had no Docker daemon (the Compose file passes `docker compose config`); the GitHub Actions workflows are syntactically valid but have not run; Trivy, gitleaks, CodeQL and tflint run only in CI. The Grafana dashboard and Jaeger setup are provisioned from files and were not rendered, so there are no screenshots of them. Local test runs used Python 3.13; the Dockerfile and CI target 3.12.

## Repository map

```
app/                 FastAPI service (routers, authz, security, storage, middleware, observability)
migrations/          Alembic: explicit DDL, RLS policies, audit trigger, least-privilege grants
tests/               pytest suites; tests/infra.py starts throwaway Postgres, Redis and S3
scripts/             demo, local (Docker-free) stack, DB role bootstrap, bucket init, expiry check
deploy/              Prometheus, Grafana, OTel collector, Postgres init, MinIO build
infra/               Terraform modules and the dev environment
docs/                architecture, threat model, controls, infrastructure, deployment, runbook
.github/workflows/   ci, security, infra pipelines; dependabot
SPEC.md              the original specification this implementation started from
```

## Differences from SPEC.md

The specification predates the multi-tenancy requirement, so organizations were added to every table and rule. Other deliberate differences: `is_deleted` became a `deleted_at` timestamp; liveness and readiness live at `/health` and `/health/ready` (outside the versioned prefix, so load balancers and probes do not depend on API versions); SQLAlchemy is pinned below 2.1 because the OpenTelemetry instrumentation does not support it yet; the spec's "EC2 + docker compose" target is realised as EC2 running the container under systemd rather than the Compose file; integration tests use CI service containers (or locally started binaries) instead of `docker compose`.

## Known limits

Single application instance in the reference deployment, no malware scanning of uploads, metadata-only search, HS256 shared secret by default (RS256 available), and no external identity provider federation. [docs/threat-model.md](docs/threat-model.md) lists these with the trade-offs.
