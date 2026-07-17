# Secure Document Management Platform — Specification

## Purpose
Production-grade REST API for secure document storage with role-based access,
built to demonstrate backend, cloud, and DevSecOps competency.

## Stack (fixed, do not substitute)
- Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Alembic
- PostgreSQL 16, Redis 7
- Auth: JWT (access 15 min + refresh 7 days, refresh rotation, revocation via Redis)
- RBAC: roles `admin`, `editor`, `viewer` + per-document permissions
- File storage: S3-compatible (MinIO locally, AWS S3 in prod) via boto3
- Rate limiting: Redis-backed (slowapi or custom middleware)
- Logging: structlog, JSON output, request_id middleware
- Tests: pytest, pytest-asyncio, httpx; integration tests against real
  Postgres+Redis via docker compose
- Lint/format: ruff, mypy (strict on app code)
- Docker Compose for local dev; multi-stage Dockerfile, non-root user
- CI: GitHub Actions (lint → typecheck → tests → Semgrep → Trivy → build image)
- IaC: Terraform → AWS (EC2 + docker compose, RDS Postgres, ElastiCache optional)
- OpenAPI: auto-generated, enriched with descriptions and examples

## Domain model
- User(id, email, hashed_password, role, is_active, created_at)
- Document(id, title, description, owner_id, current_version, created_at, updated_at, is_deleted)
- DocumentVersion(id, document_id, version, s3_key, size_bytes, content_type, checksum_sha256, uploaded_by, created_at)
- DocumentPermission(id, document_id, user_id, level: read|write)
- AuditLog(id, user_id, action, resource_type, resource_id, ip, timestamp, details JSONB)

## RBAC rules
- admin: everything, including user management and all documents
- editor: create documents; read/write own documents and those shared with write
- viewer: read documents shared with them
- Owner can share/unshare a document (grant read or write)
- Soft delete only; admin can hard-delete

## API surface (prefix /api/v1)
- POST /auth/register, POST /auth/login, POST /auth/refresh, POST /auth/logout
- GET /users/me; admin: GET /users, PATCH /users/{id} (role, is_active)
- POST /documents (multipart upload), GET /documents (paginated, filters),
  GET /documents/{id}, GET /documents/{id}/download (presigned URL),
  PUT /documents/{id} (new version), DELETE /documents/{id}
- GET /documents/{id}/versions, GET /documents/{id}/versions/{v}/download
- POST /documents/{id}/permissions, DELETE /documents/{id}/permissions/{user_id}
- GET /audit (admin only, paginated, filters)
- GET /health (liveness: app), GET /health/ready (readiness: db + redis)

## Security requirements
- bcrypt/argon2 password hashing; password policy validated
- JWT signed HS256 with secret from env (RS256 is a documented future step)
- Refresh token rotation; revoked token jti stored in Redis until expiry
- Rate limits: 5/min on /auth/login per IP, 100/min general per user
- File upload: max 50 MB, content-type allowlist, filename sanitization
- Download via short-lived presigned S3 URLs, never proxying secrets
- All queries via ORM (no raw SQL string interpolation)
- Security headers middleware; CORS locked to configured origins
- Secrets only via env vars; .env.example committed, .env gitignored
- Audit log on: login, failed login, upload, download, delete, permission change, role change

## Quality bar
- Test coverage ≥ 80% on app/ (enforced in CI)
- mypy passes; ruff passes
- Every endpoint has at least one happy-path and one auth-failure test
- CI must be green before any deploy job runs
